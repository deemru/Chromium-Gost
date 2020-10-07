#define GOSTSSL
#define BORINGSSL_ALLOW_CXX_RUNTIME 1
#define WIN32_LEAN_AND_MEAN 1
#ifdef _WIN32
#pragma warning( push )
#pragma warning( disable:4003 )
#pragma warning( disable:4100 )
#endif
#include <../ssl/internal.h>
#ifdef _WIN32
#pragma warning( pop )
#endif

#ifdef COMPONENT_BUILD
#ifdef _WIN32
#pragma comment( lib, "crypt32.lib" )
#define DLLEXPORT __declspec(dllexport)
#else /* _WIN32 */
#define DLLEXPORT __attribute__( ( visibility( "default" ) ) )
#endif /* _WIN32 */
#else /* COMPONENT_BUILD */
#define DLLEXPORT
#endif /* COMPONENT_BUILD */

extern "C" {

// Initialize
int gostssl_init();

// Functionality
int gostssl_connect( SSL * s, int * is_gost );
int gostssl_read( SSL * s, void * buf, int len, int * is_gost );
int gostssl_peek( SSL * s, void * buf, int len, int * is_gost );
int gostssl_write( SSL * s, const void * buf, int len, int * is_gost );
int gostssl_shutdown( SSL * s, int * is_gost );
void gostssl_free( SSL * s );

// Markers
int gostssl_tls_gost_required( SSL * s, const SSL_CIPHER * cipher );

// Hooks
DLLEXPORT void gostssl_certhook( void * cert, int size );
DLLEXPORT void gostssl_verifyhook( void * s, unsigned * is_gost );
DLLEXPORT void gostssl_clientcertshook( char *** certs, int ** lens, wchar_t *** names, int * count, int * is_gost );
DLLEXPORT void gostssl_isgostcerthook( void * cert, int size, int * is_gost );
DLLEXPORT void gostssl_newsession( SSL * s, const void * cachestring, size_t len, const void * cert, int size );
DLLEXPORT int gostssl_is_msspi( SSL * s );

}

#ifdef _WIN32
#include <windows.h>
#else
#define LEGACY_FORMAT_MESSAGE_IMPL
#include "CSP_WinDef.h"
#include "CSP_WinCrypt.h"
#define UNIX
#endif // WIN32
#include "WinCryptEx.h"

#include <stdio.h>
#include <string.h>
#define _SILENCE_STDEXT_HASH_DEPRECATION_WARNINGS
#include <map>
#include <unordered_map>
#include <string>
#include <vector>
#include <mutex>

#include "msspi.h"
#ifndef _WIN32
#include "capix.hpp"
#endif

static const SSL_CIPHER * tls_0081 = NULL;
static const SSL_CIPHER * tls_C100 = NULL;
static const SSL_CIPHER * tls_C101 = NULL;
static const SSL_CIPHER * tls_C102 = NULL;
static const SSL_CIPHER * tls_FF85 = NULL;

int gostssl_init()
{
    MSSPI_HANDLE h = msspi_open( NULL, (msspi_read_cb)(uintptr_t)1, (msspi_write_cb)(uintptr_t)1 );
    if( !h )
        return 0;

    msspi_close( h );

    HCRYPTPROV hProv;

    if( !CryptAcquireContext( &hProv, NULL, NULL, PROV_GOST_2001_DH, CRYPT_VERIFYCONTEXT | CRYPT_SILENT ) )
        return 0;

    CryptReleaseContext( hProv, 0 );

    if( NULL == ( tls_0081 = boring_SSL_get_cipher_by_value( 0x0081 ) ) ||
        NULL == ( tls_C100 = boring_SSL_get_cipher_by_value( 0xC100 ) ) ||
        NULL == ( tls_C101 = boring_SSL_get_cipher_by_value( 0xC101 ) ) ||
        NULL == ( tls_C102 = boring_SSL_get_cipher_by_value( 0xC102 ) ) ||
        NULL == ( tls_FF85 = boring_SSL_get_cipher_by_value( 0xFF85 ) ) )
        return 0;

    return 1;
}

typedef enum
{
    GOSTSSL_HOST_AUTO = 0,
    GOSTSSL_HOST_YES = 1,
    GOSTSSL_HOST_NO = 2,
    GOSTSSL_HOST_PROBING = 16,
    GOSTSSL_HOST_PROBING_END = 31
}
GOSTSSL_HOST_STATUS;

struct GostSSL_Worker
{
    GostSSL_Worker()
    {
        h = NULL;
        s = NULL;
        host_status = GOSTSSL_HOST_AUTO;
    }

    ~GostSSL_Worker()
    {
        if( h )
            msspi_close( h );
    }

    MSSPI_HANDLE h;
    SSL * s;
    GOSTSSL_HOST_STATUS host_status;
    std::string host_string;
};

static int gostssl_read_cb( GostSSL_Worker * w, void * buf, int len )
{
    return boring_BIO_read( w->s, buf, len );
}

static int gostssl_write_cb( GostSSL_Worker * w, const void * buf, int len )
{
    return boring_BIO_write( w->s, buf, len );
}

static PCCERT_CONTEXT gcert = NULL;

static int gostssl_cert_cb( GostSSL_Worker * w )
{
    if( w->s->config->cert && w->s->config->cert->cert_cb )
    {
        if( gcert )
        {
            CertFreeCertificateContext( gcert );
            gcert = NULL;
        }

        // mimic ssl3_get_certificate_request
        if( !w->s->s3->hs->ca_names )
        {
            std::vector<const char *> bufs;
            std::vector<int> lens;
            size_t count;

            if( msspi_get_issuerlist( w->h, NULL, NULL, &count ) )
            {
                bufs.resize( count );
                lens.resize( count );

                if( msspi_get_issuerlist( w->h, &bufs[0], &lens[0], &count ) )
                    boring_set_ca_names_cb( w->s, &bufs[0], &lens[0], count );
            }
        }

        int ret = w->s->config->cert->cert_cb( w->s, w->s->config->cert->cert_cb_arg );

        if( !gcert )
        {
            if( ret <= 0 )
                return ret;
        }

        if( gcert )
        {
            if( msspi_set_mycert( w->h, (const char *)gcert->pbCertEncoded, gcert->cbCertEncoded ) )
                boring_ERR_clear_error();

            CertFreeCertificateContext( gcert );
            gcert = NULL;
        }
    }

    return 1;
}

void gostssl_certhook( void * cert, int size )
{
    if( !cert )
        return;

    if( gcert )
        return;

    if( size == 0 )
        gcert = CertDuplicateCertificateContext( (PCCERT_CONTEXT)cert );
    else
        gcert = CertCreateCertificateContext( X509_ASN_ENCODING, (BYTE *)cert, size );
}

void gostssl_isgostcerthook( void * cert, int size, int * is_gost )
{
    PCCERT_CONTEXT certctx = NULL;

    *is_gost = 0;

    if( size == 0 )
        certctx = CertDuplicateCertificateContext( (PCCERT_CONTEXT)cert );
    else
        certctx = CertCreateCertificateContext( X509_ASN_ENCODING, (BYTE *)cert, size );

    if( !certctx || !certctx->pCertInfo || !certctx->pCertInfo->SignatureAlgorithm.pszObjId )
        return;

    LPSTR pszObjId = certctx->pCertInfo->SignatureAlgorithm.pszObjId;

    if( 0 == strcmp( pszObjId, szOID_CP_GOST_R3411_R3410EL ) ||
        0 == strcmp( pszObjId, szOID_CP_GOST_R3411_12_256_R3410 ) ||
        0 == strcmp( pszObjId, szOID_CP_GOST_R3411_12_512_R3410 ) )
        *is_gost = 1;

    CertFreeCertificateContext( certctx );
    return;
}

typedef std::map< void *, GostSSL_Worker * > WORKERS_DB;
typedef std::unordered_map< std::string, GOSTSSL_HOST_STATUS > HOST_STATUSES_DB;
typedef std::pair< std::string, GOSTSSL_HOST_STATUS > HOST_STATUSES_DB_PAIR;

static WORKERS_DB & workers_db = *( new WORKERS_DB() );
static HOST_STATUSES_DB & host_statuses_db = *( new HOST_STATUSES_DB() );
static std::recursive_mutex & gmutex = *( new std::recursive_mutex() );

static void host_status_set( std::string & site, GOSTSSL_HOST_STATUS status )
{
    std::unique_lock<std::recursive_mutex> lck( gmutex );

    HOST_STATUSES_DB::iterator lb = host_statuses_db.find( site );

    if( lb != host_statuses_db.end() )
    {
        if( lb->second != GOSTSSL_HOST_NO && lb->second != GOSTSSL_HOST_YES )
            lb->second = status;
    }
    else
    {
        host_statuses_db.insert( lb, HOST_STATUSES_DB_PAIR( site, status ) );
    }
}

GOSTSSL_HOST_STATUS host_status_first( std::string & site )
{
    (void)site;
    return GOSTSSL_HOST_AUTO;
}

GOSTSSL_HOST_STATUS host_status_get( std::string & site )
{
    if( host_statuses_db.size() )
    {
        std::unique_lock<std::recursive_mutex> lck( gmutex );

        HOST_STATUSES_DB::iterator lb = host_statuses_db.find( site );

        if( lb != host_statuses_db.end() )
            return lb->second;
    }

    return host_status_first( site );
}

typedef enum
{
    WDB_SEARCH,
    WDB_NEW,
    WDB_FREE,
}
WORKER_DB_ACTION;

static GostSSL_Worker * workers_api( const SSL * s, WORKER_DB_ACTION action, const char * cachestring = NULL, const void * cert = NULL, int size = 0 )
{
    GostSSL_Worker * w = NULL;

    if( action == WDB_NEW )
    {
        w = new GostSSL_Worker();
        w->h = msspi_open( w, (msspi_read_cb)gostssl_read_cb, (msspi_write_cb)gostssl_write_cb );

        if( !w->h )
        {
            delete w;
            return NULL;
        }

        w->host_string = s->hostname.get() ? s->hostname.get() : "*";
        w->host_string += ":";
        w->host_string += cachestring ? cachestring : "*";
        w->host_status = host_status_get( w->host_string );

        msspi_set_cert_cb( w->h, (msspi_cert_cb)gostssl_cert_cb );
        w->s = (SSL *)s;

        if( s->hostname.get() )
            msspi_set_hostname( w->h, s->hostname.get() );
        if( cachestring )
            msspi_set_cachestring( w->h, cachestring );
        if( s->config->alpn_client_proto_list.size() )
            msspi_set_alpn( w->h, (const char *)s->config->alpn_client_proto_list.data(), (unsigned)s->config->alpn_client_proto_list.size() );
        if( cert && size )
            msspi_set_mycert( w->h, (const char *)cert, size );
    }

    std::unique_lock<std::recursive_mutex> lck( gmutex );

    WORKERS_DB::iterator lb = workers_db.lower_bound( (void *)s );

    if( lb != workers_db.end() && !( workers_db.key_comp()( (void *)s, lb->first ) ) )
    {
        GostSSL_Worker * w_found = lb->second;

        if( action == WDB_NEW )
        {
            delete w_found;
            lb->second = w;
            return w;
        }
        else if( action == WDB_FREE )
        {
            if( w_found->host_status >= GOSTSSL_HOST_PROBING &&
                w_found->host_status <= GOSTSSL_HOST_PROBING_END )
            {
                GOSTSSL_HOST_STATUS status;

                if( w_found->host_status == GOSTSSL_HOST_PROBING_END )
                    status = GOSTSSL_HOST_AUTO;
                else
                    status = (GOSTSSL_HOST_STATUS)( (int)w_found->host_status + 1 );

                host_status_set( w_found->host_string, status );
            }

            delete w_found;
            workers_db.erase( lb );
            return NULL;
        }

        return w_found;
    }

    if( action == WDB_NEW )
        workers_db.insert( lb, WORKERS_DB::value_type( (void *)s, w ) );

    return w;
}

int gostssl_tls_gost_required( SSL * s, const SSL_CIPHER * cipher )
{
    GostSSL_Worker * w = workers_api( s, WDB_SEARCH );

    if( w && 
        ( cipher == tls_0081 ||
          cipher == tls_C100 ||
          cipher == tls_C101 ||
          cipher == tls_C102 ||
          cipher == tls_FF85 ) )
    {
        boring_ERR_clear_error();
        boring_ERR_put_error( ERR_LIB_SSL, 0, SSL_R_TLS_GOST_REQUIRED, __FILE__, __LINE__ );
        host_status_set( w->host_string, GOSTSSL_HOST_PROBING );
        return 1;
    }

    return 0;
}

static int msspi_to_ssl_version( DWORD dwProtocol )
{
    switch( dwProtocol )
    {
        case 0x00000301:
        case 0x00000040 /*SP_PROT_TLS1_SERVER*/:
        case 0x00000080 /*SP_PROT_TLS1_CLIENT*/:
            return TLS1_VERSION;

        case 0x00000302:
        case 0x00000100 /*SP_PROT_TLS1_1_SERVER*/:
        case 0x00000200 /*SP_PROT_TLS1_1_CLIENT*/:
            return TLS1_1_VERSION;

        case 0x00000303:
        case 0x00000400 /*SP_PROT_TLS1_2_SERVER*/:
        case 0x00000800 /*SP_PROT_TLS1_2_CLIENT*/:
            return TLS1_2_VERSION;

        default:
            return SSL3_VERSION;
    }
}

static int msspi_to_ssl_state_ret( int state, SSL * s, int ret )
{
    if( state & MSSPI_ERROR )
        s->s3->rwstate = SSL_NOTHING;
    else if( state & MSSPI_SENT_SHUTDOWN && state & MSSPI_RECEIVED_SHUTDOWN )
        s->s3->rwstate = SSL_NOTHING;
    else if( state & MSSPI_X509_LOOKUP )
        s->s3->rwstate = SSL_ERROR_WANT_X509_LOOKUP;
    else if( state & MSSPI_WRITING )
    {
        if( state & MSSPI_LAST_PROC_WRITE )
            s->s3->rwstate = SSL_WRITING;
        else if( state & MSSPI_READING )
            s->s3->rwstate = SSL_READING;
        else
            s->s3->rwstate = SSL_WRITING;
    }
    else if( state & MSSPI_READING )
        s->s3->rwstate = SSL_READING;
    else
        s->s3->rwstate = SSL_NOTHING;

    if( state & MSSPI_ERROR )
    {
        s->s3->write_shutdown = bssl::ssl_shutdown_close_notify;
        s->s3->read_shutdown = bssl::ssl_shutdown_close_notify;
    }
    else
    {
        if( state & MSSPI_SENT_SHUTDOWN )
            s->s3->write_shutdown = bssl::ssl_shutdown_close_notify;
        if( state & MSSPI_RECEIVED_SHUTDOWN )
            s->s3->read_shutdown = bssl::ssl_shutdown_close_notify;
    }

    return ret;
}

static MSSPI_HANDLE get_msspi( const SSL * s, int * is_gost )
{
    GostSSL_Worker * w = workers_api( s, WDB_SEARCH );

    if( !w || w->host_status != GOSTSSL_HOST_YES )
    {
        *is_gost = FALSE;
        return NULL;
    }

    *is_gost = TRUE;
    return w->h;
}

int gostssl_read( SSL * s, void * buf, int len, int * is_gost )
{
    MSSPI_HANDLE h = get_msspi( s, is_gost );
    if( !h )
        return 0;

    int ret = msspi_read( h, buf, len );
    return msspi_to_ssl_state_ret( msspi_state( h ), s, ret );
}

int gostssl_peek( SSL * s, void * buf, int len, int * is_gost )
{
    MSSPI_HANDLE h = get_msspi( s, is_gost );
    if( !h )
        return 0;

    int ret = msspi_peek( h, buf, len );
    return msspi_to_ssl_state_ret( msspi_state( h ), s, ret );
}

int gostssl_write( SSL * s, const void * buf, int len, int * is_gost )
{
    MSSPI_HANDLE h = get_msspi( s, is_gost );
    if( !h )
        return 0;

    int ret = msspi_write( h, buf, len );
    return msspi_to_ssl_state_ret( msspi_state( h ), s, ret );
}

int gostssl_shutdown( SSL * s, int * is_gost )
{
    MSSPI_HANDLE h = get_msspi( s, is_gost );
    if( !h )
        return 0;

    int ret = msspi_shutdown( h );
    int state = msspi_state( h );
    msspi_to_ssl_state_ret( state, s, ret );

    if( ret < 0 )
        return -1;
    if( state & MSSPI_ERROR )
        return 1;
    if( state & MSSPI_SENT_SHUTDOWN && state & MSSPI_RECEIVED_SHUTDOWN )
        return 1;
    return 0;
}

#define B2C(x) ( x < 0xA ? x + '0' : x + 'A' - 10 )

void gostssl_newsession( SSL * s, const void * cachestring, size_t len, const void * cert, int size )
{
    BYTE * bb = (BYTE *)cachestring;
    std::vector<BYTE> cc;
    cc.resize( len * 2 + 1 );
    for( int i = 0; i < len; i++ )
    {
        BYTE xF = ( bb[i] ) >> 4;
        BYTE Fx = ( bb[i] ) & 0xF;
        cc[i * 2 + 0] = B2C( xF );
        cc[i * 2 + 1] = B2C( Fx );
    }
    cc[len * 2] = 0;
    workers_api( s, WDB_NEW, (char *)&cc[0], cert, size );
}

int gostssl_connect( SSL * s, int * is_gost )
{
    GostSSL_Worker * w = workers_api( s, WDB_SEARCH );

    // fallback
    if( !w || w->host_status == GOSTSSL_HOST_AUTO || w->host_status == GOSTSSL_HOST_NO )
    {
        *is_gost = FALSE;
        return 1;
    }

    *is_gost = TRUE;

    int ret = msspi_connect( w->h );

    if( ret == 1 )
    {
        s->s3->rwstate = SSL_NOTHING;

        // ALPN
        const char * alpn;
        size_t alpn_len;
        {
            alpn = msspi_get_alpn( w->h );

            if( !alpn )
                alpn = "http/1.1";

            alpn_len = strlen( alpn );
        }

        // VERSION + CIPHER
        uint16_t version;
        uint16_t cipher_id;
        {
            PSecPkgContext_CipherInfo cipher_info = msspi_get_cipherinfo( w->h );

            if( !cipher_info )
                return 0;

            version = (uint16_t)msspi_to_ssl_version( cipher_info->dwProtocol );
            cipher_id = (uint16_t)cipher_info->dwCipherSuite;
        }

        // SERVER CERTIFICATES
        std::vector<const char *> servercerts_bufs;
        std::vector<int> servercerts_lens;
        size_t servercerts_count;
        {
            if( !msspi_get_peercerts( w->h, NULL, NULL, &servercerts_count ) )
                return 0;

            servercerts_bufs.resize( servercerts_count );
            servercerts_lens.resize( servercerts_count );

            if( !msspi_get_peercerts( w->h, &servercerts_bufs[0], &servercerts_lens[0], &servercerts_count ) )
                return 0;
        }

        // force GOST for broken clients and IIS (regsvr32 -u cpcng.dll)
        if( cipher_id != 0x0081 &&
            cipher_id != 0xC100 &&
            cipher_id != 0xC101 &&
            cipher_id != 0xC102 &&
            cipher_id != 0xFF85 )
        {
            PCCERT_CONTEXT certcheck = CertCreateCertificateContext( X509_ASN_ENCODING, (BYTE *)servercerts_bufs[0], (DWORD)servercerts_lens[0] );

            if( !certcheck )
                return 0;

            if( 0 == strcmp( certcheck->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_CP_GOST_R3410EL ) )
                cipher_id = 0x0081;
            else if( 0 == strcmp( certcheck->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_CP_GOST_R3410_12_256 ) ||
                0 == strcmp( certcheck->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, szOID_CP_GOST_R3410_12_512 ) )
                cipher_id = 0xC102;

            CertFreeCertificateContext( certcheck );
        }

        w->host_status = GOSTSSL_HOST_YES;
        host_status_set( w->host_string, GOSTSSL_HOST_YES );

        char ssl_ret = boring_set_connected_cb( w->s, alpn, alpn_len, version, cipher_id, &servercerts_bufs[0], &servercerts_lens[0], servercerts_count );
        if( !ssl_ret )
            return -1;

        return 1;
    }

    return msspi_to_ssl_state_ret( msspi_state( w->h ), s, ret );
}

void gostssl_free( SSL * s )
{
    workers_api( s, WDB_FREE );
}

void gostssl_verifyhook( void * s, unsigned * gost_status )
{
    *gost_status = 0;

    GostSSL_Worker * w = workers_api( (SSL *)s, WDB_SEARCH );

    if( !w || w->host_status != GOSTSSL_HOST_YES )
        return;

    unsigned verify_status = msspi_verify( w->h );

    switch( verify_status )
    {
        case MSSPI_VERIFY_OK:
            *gost_status = 1;
            break;
        case MSSPI_VERIFY_ERROR:
            *gost_status = (unsigned)CERT_E_CRITICAL;
            break;
        default:
            *gost_status = verify_status;
    }
}

static std::vector<char *> & g_certs = *( new std::vector<char *>() );
static std::vector<int> & g_certlens = *( new std::vector<int>() );
static std::vector<std::string> & g_certbufs = *( new std::vector<std::string>() );

static std::vector<wchar_t *> & g_certnames = *( new std::vector<wchar_t *>() );
static std::vector<std::wstring> & g_certnamebufs = *( new std::vector<std::wstring>() );

static BOOL CertHasOid( PCCERT_CONTEXT pcert, const char * oid )
{
    DWORD ekuLength = 0;
    BOOL result = CertGetEnhancedKeyUsage( pcert, 0, NULL, &ekuLength );
    if( result && ekuLength > 0 )
    {
        std::vector<BYTE> ekuListBuffer(ekuLength);
        PCERT_ENHKEY_USAGE ekuList = (PCERT_ENHKEY_USAGE) &ekuListBuffer[0];
        if( CertGetEnhancedKeyUsage( pcert, 0, ekuList, &ekuLength ) )
            for( DWORD i = 0; i < ekuList->cUsageIdentifier; i++ )
                if( 0 == strcmp( ekuList->rgpszUsageIdentifier[i], oid ) )
                    return TRUE;
    }
    return FALSE;
}

void gostssl_clientcertshook( char *** certs, int ** lens, wchar_t *** names, int * count, int * is_gost )
{
    *is_gost = 1;
    *count = 0;

    HCERTSTORE hStore = CertOpenStore( CERT_STORE_PROV_SYSTEM_A, 0, 0, CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, "MY" );

    if( !hStore )
        return;

    int i = 0;
    g_certs.clear();
    g_certlens.clear();
    g_certbufs.clear();
    g_certnames.clear();
    g_certnamebufs.clear();

    for( PCCERT_CONTEXT pcert = CertFindCertificateInStore( hStore, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0, CERT_FIND_ANY, 0, 0 );
         pcert;
         pcert = CertFindCertificateInStore( hStore, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0, CERT_FIND_ANY, 0, pcert ) )
    {
        BYTE bUsage;
        DWORD dw = 0;
        // basic TLS client cert filtering
        if(    CertVerifyTimeValidity( NULL, pcert->pCertInfo ) == 0
            && CertGetCertificateContextProperty( pcert, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dw ) 
            && CertHasOid( pcert, szOID_PKIX_KP_CLIENT_AUTH ) )
        {
            g_certbufs.push_back( std::string( (char *)pcert->pbCertEncoded, pcert->cbCertEncoded ) );
            g_certlens.push_back( (int)g_certbufs[i].size() );
            g_certs.push_back( &g_certbufs[i][0] );

            if( names )
            {
                std::wstring name;
                wchar_t wName[1024];
                DWORD dwName;

                dwName = (DWORD)( sizeof( wName ) / sizeof( wName[0] ) );
                dwName = CertGetNameStringW( pcert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, wName, dwName );

                name = dwName > 1 ? wName : L"...";

                dwName = (DWORD)( sizeof( wName ) / sizeof( wName[0] ) );
                dwName = CertGetNameStringW( pcert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, wName, dwName );

                name = name + L" (" + ( dwName > 1 ? wName : L"..." ) + L")";

                g_certnamebufs.push_back( name );
                g_certnames.push_back( &g_certnamebufs[i][0] );
            }
            i++;
        }
    }

    if( i )
    {
        *certs = &g_certs[0];
        *lens = &g_certlens[0];
        if( names )
            *names = &g_certnames[0];
        *count = i;
    }

    CertCloseStore( hStore, 0 );
}

int gostssl_is_msspi( SSL * s )
{
    GostSSL_Worker * w = workers_api( s, WDB_SEARCH );
    if( !w || w->host_status != GOSTSSL_HOST_YES )
        return 0;
    return 1;
}

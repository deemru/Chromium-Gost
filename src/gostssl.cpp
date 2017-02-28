#if defined( __cplusplus )
extern "C" {
#endif

#include <openssl/ssl.h>
#include <../ssl/internal.h>
#ifndef _WIN32
#define EXPLICITSSL_CALL
#endif
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

    // Initialize
    EXPORT int EXPLICITSSL_CALL gostssl_init( BORINGSSL_METHOD * bssl );

    // Functionality
    EXPORT int EXPLICITSSL_CALL gostssl_connect( SSL * s, int * is_gost );
    EXPORT int EXPLICITSSL_CALL gostssl_read( SSL * s, void * buf, int len, int * is_gost );
    EXPORT int EXPLICITSSL_CALL gostssl_write( SSL * s, const void * buf, int len, int * is_gost );
    EXPORT void EXPLICITSSL_CALL gostssl_free( SSL * s );

    // Markers
    EXPORT int EXPLICITSSL_CALL gostssl_tls_gost_required( SSL * s );

    // Callbacks
    EXPORT void EXPLICITSSL_CALL gostssl_certhook( void * cert );

    // Linux Callbacks
    EXPORT void EXPLICITSSL_CALL gostssl_rawcerthook( void * cert, int size );
    EXPORT void EXPLICITSSL_CALL gostssl_verifyhook( SSL * s, int * is_gost );
    EXPORT unsigned EXPLICITSSL_CALL gostssl_clientcertshook( char *** certs, int ** lens );

#if defined( __cplusplus )
}
#endif

#ifdef _WIN32
#include <windows.h>
#else
#include "CSP_WinDef.h"
#include "CSP_WinCrypt.h"
#include <sys/time.h>

unsigned GetTickCount()
{
    struct timeval tv;
    if( gettimeofday( &tv, NULL ) != 0 )
        return 0;

    return ( tv.tv_sec * 1000 ) + ( tv.tv_usec / 1000 );
}
#endif // WIN32

#include <stdio.h>
#include <string.h>
#define _SILENCE_STDEXT_HASH_DEPRECATION_WARNINGS
#include <map>
#include <unordered_map>
#include <string>
#include <vector>

#include "msspi\src\msspi.h"

// Тест корректности типов на этапе компиляции
static GOSTSSL_METHOD gssl = {
    gostssl_init,
    gostssl_connect,
    gostssl_read,
    gostssl_write,
    gostssl_free,
    gostssl_tls_gost_required,
};

static BORINGSSL_METHOD * bssls = NULL;

#define TLS_GOST_CIPHER_2001 0x0081
#define TLS_GOST_CIPHER_2012 0xFF85

static const SSL_CIPHER * tlsgost2001 = NULL;
static const SSL_CIPHER * tlsgost2012 = NULL;

int gostssl_init( BORINGSSL_METHOD * bssl_methods )
{
    bssls = bssl_methods;

    MSSPI_HANDLE h = msspi_open( NULL, (msspi_read_cb)(uintptr_t)1, (msspi_write_cb)(uintptr_t)1 );
    if( !h )
        return 0;
        
    msspi_close( h );

    HCRYPTPROV hProv;

    if( !CryptAcquireContext( &hProv, NULL, NULL, 75, CRYPT_VERIFYCONTEXT | CRYPT_SILENT ) )
        return 0;

    CryptReleaseContext( hProv, 0 );

    tlsgost2001 = bssls->SSL_get_cipher_by_value( TLS_GOST_CIPHER_2001 );
    tlsgost2012 = bssls->SSL_get_cipher_by_value( TLS_GOST_CIPHER_2012 );

    if( !tlsgost2001 || !tlsgost2012 )
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
};

static int gostssl_read_cb( GostSSL_Worker * w, void * buf, int len )
{
    return bssls->BIO_read( w->s->rbio, buf, len );
}

static int gostssl_write_cb( GostSSL_Worker * w, const void * buf, int len )
{
    return bssls->BIO_write( w->s->wbio, buf, len );
}

static PCCERT_CONTEXT gcert = NULL;

static int gostssl_cert_cb( GostSSL_Worker * w )
{
    if( w->s->cert && w->s->cert->cert_cb )
    {
        if( gcert )
        {
            CertFreeCertificateContext( gcert );
            gcert = NULL;
        }

        int ret = w->s->cert->cert_cb( w->s, w->s->cert->cert_cb_arg );

        if( !gcert )
        {
            if( ret <= 0 )
                return ret;
        }

        if( gcert )
        {
            if( msspi_set_mycert( w->h, (const char *)gcert->pbCertEncoded, gcert->cbCertEncoded ) )
                bssls->ERR_clear_error();

            CertFreeCertificateContext( gcert );
            gcert = NULL;
        }
    }

    return 1;
}

void gostssl_certhook( void * cert )
{
    if( !cert )
        return;

    if( gcert )
        return;

    gcert = CertDuplicateCertificateContext( (PCCERT_CONTEXT)cert );
}

typedef std::map< void *, GostSSL_Worker * > WORKERS_DB;
typedef std::unordered_map< std::string, GOSTSSL_HOST_STATUS > HOST_STATUSES_DB;
typedef std::pair< std::string, GOSTSSL_HOST_STATUS > HOST_STATUSES_DB_PAIR;

static WORKERS_DB workers_db;
static HOST_STATUSES_DB host_statuses_db;

struct GostSSL_CriticalSection
{
    GostSSL_CriticalSection()
    {
        InitializeCriticalSectionAndSpinCount( &crit_section, 0x1000 );
    }

    ~GostSSL_CriticalSection()
    {
        DeleteCriticalSection( &crit_section );
    }

    CRITICAL_SECTION crit_section;
};

struct GostSSL_Lock
{
    GostSSL_Lock( GostSSL_CriticalSection & section )
    {
        locked_section = &section.crit_section;
        EnterCriticalSection( locked_section );
    }

    ~GostSSL_Lock()
    {
        LeaveCriticalSection( locked_section );
    }

    CRITICAL_SECTION * locked_section;
};

static GostSSL_CriticalSection gssl_critsect;

void host_status_set( const char * site, GOSTSSL_HOST_STATUS status )
{
    GostSSL_Lock lock( gssl_critsect );

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

#if defined( _WIN32 ) && defined( W_SITES )

#define REGISTRY_TREE01 "Software"
#define REGISTRY_TREE02 "Crypto Pro"
#define REGISTRY_TREE03 "gostssl"
#define REGISTRY_CHROME_SITES "_sites"

static HKEY hKeyChromeRegistryDir = 0;

VOID CloseChromeRegistryDir()
{
    if( hKeyChromeRegistryDir )
    {
        RegCloseKey( hKeyChromeRegistryDir );
        hKeyChromeRegistryDir = 0;
    }
}

BOOL OpenChromeRegistryDir( CHAR * szDir, BOOL is_write )
{
    HKEY hKey = 0;
    HKEY hKeyChild = 0;
    REGSAM RW = KEY_READ | ( is_write ? KEY_WRITE : 0 );
    CHAR szChromeRegistryDir[MAX_PATH] = { 0 };
    int i;

    CloseChromeRegistryDir();

    if( -1 == sprintf_s( szChromeRegistryDir, _countof( szChromeRegistryDir ), REGISTRY_TREE01 "\\" REGISTRY_TREE02 "\\" REGISTRY_TREE03 "\\%s", szDir ) )
        return FALSE;

    for( i = 0; i < 5; i++ )
    {
        if( hKey )
        {
            RegCloseKey( hKey );
            hKey = 0;
        }

        if( hKeyChild )
        {
            RegCloseKey( hKeyChild );
            hKeyChild = 0;
        }

        if( hKeyChromeRegistryDir )
            return TRUE;

        if( RegOpenKeyExA( HKEY_CURRENT_USER, szChromeRegistryDir, 0, RW, &hKey ) )
        {
            if( !is_write )
                break;

            if( RegOpenKeyExA( HKEY_CURRENT_USER, REGISTRY_TREE01 "\\" REGISTRY_TREE02 "\\" REGISTRY_TREE03, 0, RW, &hKey ) )
            {
                if( RegOpenKeyExA( HKEY_CURRENT_USER, REGISTRY_TREE01 "\\" REGISTRY_TREE02, 0, RW, &hKey ) )
                {
                    if( RegOpenKeyExA( HKEY_CURRENT_USER, REGISTRY_TREE01, 0, RW, &hKey ) )
                        break;

                    if( RegCreateKeyA( hKey, REGISTRY_TREE02, &hKeyChild ) )
                        break;

                    continue;
                }

                if( RegCreateKeyA( hKey, REGISTRY_TREE03, &hKeyChild ) )
                    break;

                continue;
            }

            if( RegCreateKeyA( hKey, szDir, &hKeyChild ) )
                break;

            continue;
        }

        hKeyChromeRegistryDir = hKey;
        hKey = 0;
    }

    return FALSE;
}

static BOOL isChromeSitesOpened = FALSE;

BOOL GetChromeDWORDEx( LPCSTR szKey, DWORD * dwValue )
{
    if( !hKeyChromeRegistryDir )
        return 0;

    DWORD dwLen = sizeof( *dwValue );

    if( ERROR_SUCCESS != RegQueryValueExA( hKeyChromeRegistryDir, szKey, NULL, 0, (BYTE *)dwValue, &dwLen ) )
        return FALSE;

    return TRUE;
}

GOSTSSL_HOST_STATUS host_status_first( const char * site )
{
    if( !isChromeSitesOpened )
    {
        if( !OpenChromeRegistryDir( REGISTRY_CHROME_SITES, FALSE ) )
            return GOSTSSL_HOST_AUTO;

        isChromeSitesOpened = TRUE;
    }

    {
        DWORD dwStatus;

        if( !GetChromeDWORDEx( site, &dwStatus ) )
            return GOSTSSL_HOST_AUTO;

        switch( dwStatus )
        {
            case GOSTSSL_HOST_YES:
            case GOSTSSL_HOST_NO:
            case GOSTSSL_HOST_AUTO:
                host_status_set( site, (GOSTSSL_HOST_STATUS)dwStatus );
                return (GOSTSSL_HOST_STATUS)dwStatus;

            default:
                return GOSTSSL_HOST_AUTO;
        }
    }
}

#else

GOSTSSL_HOST_STATUS host_status_first( char * site )
{
    (void)site;
    return GOSTSSL_HOST_AUTO;
}

#endif

GOSTSSL_HOST_STATUS host_status_get( char * site )
{
    if( host_statuses_db.size() )
    {
        GostSSL_Lock lock( gssl_critsect );

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

GostSSL_Worker * workers_api( SSL * s, WORKER_DB_ACTION action )
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

        msspi_set_cert_cb( w->h, (msspi_cert_cb)gostssl_cert_cb );
        w->s = s;
        
        if( s->tlsext_hostname )
        {
            msspi_set_hostname( w->h, s->tlsext_hostname );
            w->host_status = host_status_get( s->tlsext_hostname );
        }
    }

    GostSSL_Lock lock( gssl_critsect );

    WORKERS_DB::iterator lb = workers_db.lower_bound( s );

    if( lb != workers_db.end() && !( workers_db.key_comp()( s, lb->first ) ) )
    {
        if( action == WDB_NEW )
        {
            delete lb->second;
            lb->second = w;
        }
        else if( action == WDB_FREE )
        {
            if( lb->second->host_status >= GOSTSSL_HOST_PROBING &&
                lb->second->host_status <= GOSTSSL_HOST_PROBING_END &&
                s->tlsext_hostname )
            {
                GOSTSSL_HOST_STATUS status;

                if( lb->second->host_status == GOSTSSL_HOST_PROBING_END )
                    status = GOSTSSL_HOST_AUTO;
                else
                    status = (GOSTSSL_HOST_STATUS)( (int)lb->second->host_status + 1 );

                host_status_set( s->tlsext_hostname, status );
            }

            delete lb->second;
            workers_db.erase( lb );
            return NULL;
        }

        w = lb->second;
    }
    else
    {
        if( action == WDB_NEW )
            workers_db.insert( lb, WORKERS_DB::value_type( s, w ) );
    }

    return w;
}

int gostssl_tls_gost_required( SSL * s )
{
    if( s->s3->tmp.new_cipher == tlsgost2001 ||
        s->s3->tmp.new_cipher == tlsgost2012 )
    {
        bssls->ERR_clear_error();
        bssls->ERR_put_error( ERR_LIB_SSL, 0, SSL_R_TLS_GOST_REQUIRED, __FILE__, __LINE__ );
        host_status_set( s->tlsext_hostname, GOSTSSL_HOST_PROBING );
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

static int msspi_to_ssl_state_ret( MSSPI_STATE state, SSL * s, int ret )
{
    switch( state )
    {
        case MSSPI_NOTHING:
            s->rwstate = SSL_NOTHING;
            break;
        case MSSPI_READING:
            s->rwstate = SSL_READING;
            break;
        case MSSPI_WRITING:
            s->rwstate = SSL_WRITING;
            break;
        case MSSPI_X509_LOOKUP:
            s->rwstate = SSL_X509_LOOKUP;
            break;
        case MSSPI_SHUTDOWN:
            s->rwstate = SSL_NOTHING;
            break;
        default:
            s->rwstate = SSL_NOTHING;
            break;
    }

    return ret;
}

int gostssl_read( SSL * s, void * buf, int len, int * is_gost )
{
    GostSSL_Worker * w = workers_api( s, WDB_SEARCH );

    // fallback
    if( !w || w->host_status != GOSTSSL_HOST_YES )
    {
        *is_gost = FALSE;
        return 1;
    }

    *is_gost = TRUE;

    int ret = msspi_read( w->h, buf, len );
    return msspi_to_ssl_state_ret( msspi_state( w->h ), s, ret );
}

int gostssl_write( SSL * s, const void * buf, int len, int * is_gost )
{
    GostSSL_Worker * w = workers_api( s, WDB_SEARCH );

    // fallback
    if( !w || w->host_status != GOSTSSL_HOST_YES )
    {
        *is_gost = FALSE;
        return 1;
    }

    *is_gost = TRUE;

    int ret = msspi_write( w->h, buf, len );
    return msspi_to_ssl_state_ret( msspi_state( w->h ), s, ret );
}

int gostssl_connect( SSL * s, int * is_gost )
{
    GostSSL_Worker * w = workers_api( s, s->state == SSL_ST_INIT ? WDB_NEW : WDB_SEARCH );

    // fallback
    if( !w || w->host_status == GOSTSSL_HOST_AUTO || w->host_status == GOSTSSL_HOST_NO )
    {
        *is_gost = FALSE;
        return 1;
    }

    *is_gost = TRUE;

    if( s->state == SSL_ST_INIT )
        s->state = SSL_ST_CONNECT;

    int ret = msspi_connect( w->h );

    if( ret == 1 )
    {
        s->rwstate = SSL_NOTHING;

        // Не заполняем повторно
        if( s->s3->established_session &&
            s->s3->established_session->cipher &&
            s->s3->aead_write_ctx &&
            s->s3->aead_write_ctx->cipher )
        {
            s->state = SSL_ST_OK;
            return 1;
        }

        // Пока поддерживаем только http/1.1
        {
            static const char SSPI_ALPN_PROTO[] = "http/1.1";
            static const size_t SSPI_ALPN_PROTO_LEN = sizeof( SSPI_ALPN_PROTO ) - 1;

            if( s->s3->alpn_selected )
                bssls->OPENSSL_free( s->s3->alpn_selected );

            s->s3->alpn_selected = (uint8_t *)bssls->OPENSSL_malloc( SSPI_ALPN_PROTO_LEN );

            if( !s->s3->alpn_selected )
                return 0;

            memcpy( s->s3->alpn_selected, SSPI_ALPN_PROTO, SSPI_ALPN_PROTO_LEN );
            s->s3->alpn_selected_len = SSPI_ALPN_PROTO_LEN;
        }

        // заполняем оригинальные структуры (мимикрия)
        if( bssls->ssl_get_new_session( s, 0 ) <= 0 )
            return 0;

        s->s3->established_session = s->s3->new_session;
        s->s3->new_session = NULL;

        // мимика ssl3_get_server_certificate
        {
            STACK_OF( X509 ) * sk;
            sk = ( STACK_OF( X509 ) * )bssls->sk_new_null();

            if( !sk )
                return 0;

            std::vector<const char *> bufs;
            std::vector<int> lens;
            size_t count;

            if( !msspi_get_peercerts( w->h, NULL, NULL, &count ) )
                return 0;            

            bufs.resize( count );
            lens.resize( count );

            bool is_OK = false;

            if( msspi_get_peercerts( w->h, &bufs[0], &lens[0], &count ) )
            {
                for( size_t i = 0; i < count; i++ )
                {
                    const unsigned char * buf = (const unsigned char *)bufs[i];
                    X509 * x = bssls->d2i_X509( NULL, &buf, lens[i] );

                    if( !x )
                        break;

                    bssls->sk_push( CHECKED_CAST( _STACK *, STACK_OF( X509 ) *, sk ), CHECKED_CAST( void *, X509 *, x ) );
                    is_OK = true;
                }
            }

            if( !is_OK )
                return 0;

            {
                X509 * leaf = (X509 *)bssls->sk_value( CHECKED_CAST( _STACK *, const STACK_OF( X509 ) *, sk ), ( 0 ) );

                bssls->sk_pop_free( CHECKED_CAST( _STACK *, STACK_OF( X509 ) *, s->s3->established_session->x509_chain ),
                    CHECKED_CAST( void( *)( void * ), void( *)( X509 * ), bssls->X509_free ) );

                s->s3->established_session->x509_chain = sk;
                bssls->X509_free( s->s3->established_session->x509_peer );
                bssls->X509_up_ref( leaf );
                s->s3->established_session->x509_peer = leaf;
            }
        }

        // cipher
        {
            PSecPkgContext_CipherInfo cipher_info = msspi_get_cipherinfo( w->h );

            if( !cipher_info )
                return 0;

            const SSL_CIPHER * cipher = bssls->SSL_get_cipher_by_value( (uint16_t)cipher_info->dwCipherSuite );

            if( !cipher )
                return 0;

            s->version = msspi_to_ssl_version( cipher_info->dwProtocol );
            s->s3->have_version = 1;
            s->s3->established_session->ssl_version = s->version;
            s->s3->established_session->cipher = cipher;

            {
                if( s->s3->aead_write_ctx )
                    bssls->OPENSSL_free( s->s3->aead_write_ctx );

                s->s3->aead_write_ctx = (SSL_AEAD_CTX *)bssls->OPENSSL_malloc( sizeof( ssl_aead_ctx_st ) );

                if( !s->s3->aead_write_ctx )
                    return 0;

                memset( s->s3->aead_write_ctx, 0, sizeof( ssl_aead_ctx_st ) );
                s->s3->aead_write_ctx->cipher = cipher;
            }
        }

        // callback SSL_CB_HANDSHAKE_DONE
        if( s->info_callback != NULL )
            s->info_callback( s, SSL_CB_HANDSHAKE_DONE, 1 );
        else if( s->ctx->info_callback != NULL )
            s->ctx->info_callback( s, SSL_CB_HANDSHAKE_DONE, 1 );

        s->state = SSL_ST_OK;
        w->host_status = GOSTSSL_HOST_YES;

        if( s->tlsext_hostname )
            host_status_set( s->tlsext_hostname, GOSTSSL_HOST_YES );

        return 1;
    }

    return msspi_to_ssl_state_ret( msspi_state( w->h ), s, ret );
}

void gostssl_free( SSL * s )
{
    workers_api( s, WDB_FREE );
}

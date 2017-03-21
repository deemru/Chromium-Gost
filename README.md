<h3 align="center">
  <img src="extra/chromium-gost-header.png"/>
</h3>

# chromium-gost 

[![version](https://img.shields.io/github/release/deemru/chromium-gost.svg)](https://github.com/deemru/chromium-gost/releases/latest)
[![appveyor](https://img.shields.io/appveyor/ci/deemru/chromium-gost.svg?label=appveyor)](https://ci.appveyor.com/project/deemru/chromium-gost)
[![visualstudio](https://img.shields.io/vso/build/deem/2f245d40-b5be-4754-a914-1876f55cf9e7/4.svg?label=visualstudio)](https://deem.visualstudio.com/builder/_build/index?definitionId=4)

[chromium-gost](https://github.com/deemru/chromium-gost) — веб-браузер с открытым исходным кодом на основе [Chromium](https://ru.wikipedia.org/wiki/Chromium) с поддержкой криптографических алгоритмов ГОСТ при установке [защищённых соединений](https://ru.wikipedia.org/wiki/TLS) через интерфейс [msspi](https://github.com/deemru/msspi)

# [Скачать](https://github.com/deemru/chromium-gost/release/latest)
[chromium-gost](https://github.com/deemru/chromium-gost) доступен для операционных систем Windows и Linux, вы можете скачать соответствующий дистрибутив в [chromium-gost/release/latest](https://github.com/deemru/chromium-gost/release/latest)

# Принцип работы

- Оригинальная реализация `Chromium` при установке защищённых соединений использует библиотеку [BoringSSL](https://boringssl.googlesource.com/boringssl), которая не поддерживает криптографические алгоритмы  ГОСТ. Для обеспечения работы ГОСТ-алгоритмов используется интерфейс `msspi`, который может поддерживать соответствующие алгоритмы, используя установленный в систему криптопровайдер.

- При запуске браузера определяется наличие технической возможности работы криптографических алгоритмов ГОСТ через интерфейс `msspi`. В случае успеха, при установке очередного защищённого соединения помимо оригинальных идентификаторов алгоритмов в пакете будут отправлены идентификаторы алгоритмов ГОСТ.

- Если сайт поддерживает работу по ГОСТ, он может отреагировать на наличие этих идентификаторов предложением работы на ГОСТ-алгоритмах. Тогда защищённое соединение в рамках `BoringSSL` установлено не будет, так как `BoringSSL` не поддерживает ГОСТ, но поступит сигнал о соответствующей ошибке.

- В случае возникновения подобного сигнала для данного сайта происходит переключение в режим работы интерфейса `msspi`. Если защищённое соединение успешно устанавливается через интерфейс `msspi`, сайт отмечается поддерживающим алгоритмы ГОСТ и все последующие с ним соединения будут использовать интерфейс `msspi`.

- Как правило, для пользователя данный алгоритм работы остаётся незаметен, так как `Chromium` по умолчанию пытается несколько раз установить защищённое соединение с различными параметрами безопасности при возникновении ошибок.

# Обсуждение

Добро пожаловать на форум: https://www.cryptopro.ru/forum2/default.aspx?g=posts&t=9991

# Сборка

[![appveyor](https://img.shields.io/appveyor/ci/deemru/chromium-gost.svg?label=appveyor)](https://ci.appveyor.com/project/deemru/chromium-gost)
[![visualstudio](https://img.shields.io/vso/build/deem/2f245d40-b5be-4754-a914-1876f55cf9e7/4.svg?label=visualstudio)](https://deem.visualstudio.com/builder/_build/index?definitionId=4)

- Требуется Windows система с установленной Visual Studio 2015
- [Создать](https://technet.microsoft.com/ru-ru/library/gg318052(v=ws.10).aspx) или смонтировать диск `U:` (не менее 128 Гб)
- Установить [depot_tools](https://chromium.googlesource.com/chromium/src/+/master/docs/windows_build_instructions.md) в `U:\depot_tools`
- Извлечь [Chromium](https://chromium.googlesource.com/chromium/src/+/master/docs/windows_build_instructions.md) в `U:\chromium\src` (запустить `fetch chromium` в `U:\chromium`)
- Извлечь [chromium-gost](https://github.com/deemru/chromium-gost)
- При наличии `CHROMIUM_PRIVATE_ARGS` объявить их в `chromium-gost\build_windows\chromium-gost-env-private.bat` 
- Подготовить сборку — [chromium-gost\build_windows\chromium-gost-prepare.bat](https://github.com/deemru/chromium-gost/blob/master/build_windows/chromium-gost-prepare.bat)
- Собрать `gostssl.dll` — [chromium-gost\build_windows\chromium-gost-build-gostssl.bat](https://github.com/deemru/chromium-gost/blob/master/build_windows/chromium-gost-build-gostssl.bat)
- Собрать всё и упаковать в `RELEASE\chromium-gost-a.b.c.d-win32.7z` — [chromium-gost\build_windows\chromium-gost-build-release.bat](https://github.com/deemru/chromium-gost/blob/master/build_windows/chromium-gost-build-release.bat)

<h3 align="center">
  <img src="extra/chromium-gost-header.png"/>
</h3>

# chromium-gost 

[![version](https://img.shields.io/github/release/deemru/chromium-gost.svg)](https://github.com/deemru/chromium-gost/releases/latest)
[![windows](https://img.shields.io/badge/windows-supported-brightgreen.svg)](https://github.com/deemru/chromium-gost/releases/latest)
[![linux](https://img.shields.io/badge/linux-supported-brightgreen.svg)](https://github.com/deemru/chromium-gost/releases/latest)
[![macos](https://img.shields.io/badge/macos-supported-brightgreen.svg)](https://github.com/deemru/chromium-gost/releases/latest)
[![Всего](https://img.shields.io/github/downloads/deemru/chromium-gost/total)](https://github.com/deemru/chromium-gost/releases/latest)

[chromium-gost](https://github.com/deemru/chromium-gost) — веб-браузер с открытым исходным кодом на основе [Chromium](https://ru.wikipedia.org/wiki/Chromium) с поддержкой криптографических алгоритмов ГОСТ при установке [защищённых соединений](https://ru.wikipedia.org/wiki/TLS) через интерфейс [msspi](https://github.com/deemru/msspi)

# [Скачать](https://github.com/deemru/chromium-gost/releases/latest)
[chromium-gost](https://github.com/deemru/chromium-gost) доступен для операционных систем Windows, Linux и MacOS. Вы можете скачать соответствующий дистрибутив в [chromium-gost/releases/latest](https://github.com/deemru/chromium-gost/releases/latest)

# Принцип работы

- Оригинальная реализация `Chromium` при установке защищённых соединений использует библиотеку [BoringSSL](https://boringssl.googlesource.com/boringssl), которая не поддерживает криптографические алгоритмы  ГОСТ. Для обеспечения работы ГОСТ-алгоритмов используется интерфейс `msspi`, который может поддерживать соответствующие алгоритмы, используя установленный в систему криптопровайдер.

- При запуске браузера определяется наличие технической возможности работы криптографических алгоритмов ГОСТ через интерфейс `msspi`. В случае успеха, при установке очередного защищённого соединения помимо оригинальных идентификаторов алгоритмов в пакете будут отправлены идентификаторы алгоритмов ГОСТ.

- Если сайт поддерживает работу по ГОСТ, он может отреагировать на наличие этих идентификаторов предложением работы на ГОСТ-алгоритмах. Тогда защищённое соединение в рамках `BoringSSL` установлено не будет, так как `BoringSSL` не поддерживает ГОСТ, но поступит сигнал о соответствующей ошибке.

- В случае возникновения подобного сигнала для данного сайта происходит переключение в режим работы интерфейса `msspi`. Если защищённое соединение успешно устанавливается через интерфейс `msspi`, сайт отмечается поддерживающим алгоритмы ГОСТ и все последующие с ним соединения будут использовать интерфейс `msspi`.

- Для пользователя данный алгоритм работы остаётся прозрачен, так как `Chromium` автоматически устанавливает повторное соединение через интерфейс `msspi`.

# Обсуждение

Добро пожаловать на форум: https://www.cryptopro.ru/forum2/default.aspx?g=posts&t=9991

# Сборка

[![appveyor](https://img.shields.io/appveyor/ci/deemru/chromium-gost.svg?label=appveyor)](https://ci.appveyor.com/project/deemru/chromium-gost)

- Освоить сборку оригинального проекта [Chromium](https://chromium.googlesource.com/chromium/src/+/master/docs/README.md) — [Get the code: check out, build, and run Chromium]( https://chromium.googlesource.com/chromium/src/+/master/docs/get_the_code.md)
- Извлечь [chromium-gost](https://github.com/deemru/chromium-gost)
- Использовать скрипты из `build_linux`, `build_mac` или `build_windows`
- Скорректировать пути — `chromium-gost-env`
- Подготовить сборку — `chromium-gost-prepare`
- Собрать дистрибутив `chromium-gost` — `chromium-gost-build-release`

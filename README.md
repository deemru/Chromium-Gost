<h3 align="center">
  <img src="extra/chromium-gost-header.png"/>
</h3>

# Chromium-Gost

[![version](https://img.shields.io/github/release/deemru/Chromium-Gost.svg)](https://github.com/deemru/Chromium-Gost/releases/latest)
[![windows](https://img.shields.io/badge/windows-supported-brightgreen.svg)](https://github.com/deemru/Chromium-Gost/releases/latest)
[![linux](https://img.shields.io/badge/linux-supported-brightgreen.svg)](https://github.com/deemru/Chromium-Gost/releases/latest)
[![macos](https://img.shields.io/badge/macos-supported-brightgreen.svg)](https://github.com/deemru/Chromium-Gost/releases/latest)
[![downloads](https://img.shields.io/github/downloads/deemru/Chromium-Gost/total)](https://github.com/deemru/Chromium-Gost/releases/latest)

[Chromium-Gost](https://github.com/deemru/Chromium-Gost) — веб-браузер с открытым исходным кодом на основе [Chromium](https://ru.wikipedia.org/wiki/Chromium) с поддержкой криптографических алгоритмов ГОСТ при установке [защищённых соединений](https://ru.wikipedia.org/wiki/TLS) через интерфейс [msspi](https://github.com/deemru/msspi)

# [Скачать](https://github.com/deemru/Chromium-Gost/releases/latest)
[Chromium-Gost](https://github.com/deemru/Chromium-Gost) доступен для операционных систем Windows, Linux и MacOS. Вы можете скачать соответствующий дистрибутив в [Chromium-Gost/releases/latest](https://github.com/deemru/Chromium-Gost/releases/latest)

# Принцип работы

- Оригинальная реализация `Chromium` при установке защищённых соединений использует библиотеку [BoringSSL](https://boringssl.googlesource.com/boringssl), которая не поддерживает криптографические алгоритмы  ГОСТ. Для обеспечения работы ГОСТ-алгоритмов используется интерфейс `msspi`, который может поддерживать соответствующие алгоритмы, используя установленный в систему криптопровайдер.

- При запуске браузера определяется наличие технической возможности работы криптографических алгоритмов ГОСТ через интерфейс `msspi`. В случае успеха, при установке очередного защищённого соединения помимо оригинальных идентификаторов алгоритмов в пакете будут отправлены идентификаторы алгоритмов ГОСТ.

- Если сайт поддерживает работу по ГОСТ, он может отреагировать на наличие этих идентификаторов предложением работы на ГОСТ-алгоритмах. Тогда защищённое соединение в рамках `BoringSSL` установлено не будет, так как `BoringSSL` не поддерживает ГОСТ, но поступит сигнал о соответствующей ошибке.

- В случае возникновения подобного сигнала для данного сайта происходит переключение в режим работы интерфейса `msspi`. Если защищённое соединение успешно устанавливается через интерфейс `msspi`, сайт отмечается поддерживающим алгоритмы ГОСТ и все последующие с ним соединения будут использовать интерфейс `msspi`.

- Данный алгоритм максимально прозрачен для пользователя и минимально влияет на опыт взаимодействия с сайтом.

# Обсуждение

Добро пожаловать на форум: https://www.cryptopro.ru/forum2/default.aspx?g=posts&t=9991

# Сборка

[![appveyor](https://img.shields.io/appveyor/ci/deemru/Chromium-Gost.svg?label=appveyor)](https://ci.appveyor.com/project/deemru/Chromium-Gost)

- Освоить сборку оригинального проекта [Chromium](https://chromium.googlesource.com/chromium/src/+/master/docs/README.md) — [Get the code: check out, build, and run Chromium]( https://chromium.googlesource.com/chromium/src/+/master/docs/get_the_code.md)
- Извлечь [Chromium-Gost](https://github.com/deemru/Chromium-Gost)
- Использовать скрипты из `build_linux`, `build_mac` или `build_windows`
- Скорректировать пути — `chromium-gost-env`
- Подготовить сборку — `chromium-gost-prepare`
- Собрать дистрибутив `chromium-gost` — `chromium-gost-build-release`

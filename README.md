# CryptoCore

CryptoCore — учебная консольная утилита для шифрования, расшифрования, хеширования и проверки подлинности текстовых и бинарных файлов. Поддерживаются AES-128, режимы ECB, CBC, CFB-128, OFB и CTR, HMAC-SHA256 и AES-CMAC, а также системная генерация ключей и IV.

Одноблочный примитив AES предоставляется PyCryptodome. Логика режимов ECB/CBC/CFB/OFB/CTR и дополнение PKCS#7 реализованы в проекте. OpenSSL используется как независимый инструмент проверки совместимости.

## Реализовано

- AES-128;
- режимы ECB, CBC, CFB-128, OFB и CTR;
- PKCS#7 для ECB и CBC;
- обработка неполного последнего блока без padding в CFB/OFB/CTR;
- генерация ключей и 16-байтных IV через `cryptocore.csprng`;
- формат файлов с IV для новых режимов;
- шифрование и расшифрование бинарных файлов через CLI;
- автоматическое имя выходного файла, если `--output` не указан;
- предупреждение о простых предсказуемых ключах;
- подготовка данных и проверка CSPRNG через NIST STS 2.1.2;
- SHA-256 по FIPS 180-4 и SHA3-256 по FIPS 202;
- потоковое хеширование файлов командой `cryptocore dgst`;
- собственные потоковые HMAC-SHA256 и AES-128-CMAC;
- генерация MAC и проверка сохранённых значений через `dgst --verify`;
- необязательная JIT-компиляция собственных раундов SHA для больших файлов;
- модульные, интеграционные и OpenSSL compatibility tests.

## Зависимости

- Python 3.10+
- PyCryptodome 3.23.0
- pytest 8+ — только для запуска тестов
- OpenSSL — необязательный внешний инструмент для compatibility tests
- Numba 0.61+ — необязательный компилятор для ускорения собственных реализаций SHA; устанавливается через extra `speed`, вместе с NumPy и llvmlite

Тесты совместимости ищут OpenSSL сначала по пути из `CRYPTOCORE_OPENSSL`, затем в `PATH`, а на Windows — в `C:\Program Files\Git\usr\bin\openssl.exe`. Если OpenSSL действительно отсутствует, эти тесты пропускаются, а остальные тесты проекта продолжают выполняться.

## Установка

Команды для Windows PowerShell:

```powershell
git clone https://github.com/nakv1/crypto_core_nk.git
cd crypto_core_nk
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Для установки без тестовых зависимостей последнюю команду можно заменить на:

```powershell
python -m pip install -e .
```

Для ускоренного хеширования и тестов:

```powershell
python -m pip install -e ".[dev,speed]"
```

Numba компилирует написанные в проекте раунды SHA-256 и Keccak-f[1600] в машинный код. Готовые хеш-функции `hashlib`, OpenSSL и PyCryptodome при вычислении SHA и HMAC не используются. При отсутствии Numba работает реализация на обычном Python. Установленный компилятор загружается только при обработке частей сообщения от 4096 байт. Первый запуск может потребовать компиляции; следующие используют дисковый кэш Numba.

Чтобы принудительно проверить обычный Python:

```powershell
$env:CRYPTOCORE_PURE_PYTHON="1"
python -m pytest -q
Remove-Item Env:CRYPTOCORE_PURE_PYTHON
```

## Режимы

| Mode | Padding | IV | Примечание |
| --- | --- | --- | --- |
| `ecb` | PKCS#7 | нет | Файл содержит только ciphertext |
| `cbc` | PKCS#7 | 16 байт | IV генерируется при шифровании |
| `cfb` | нет | 16 байт | Используется CFB-128 |
| `ofb` | нет | 16 байт | Длина данных не изменяется |
| `ctr` | нет | 16 байт | IV используется как начальный 128-битный счётчик |

## Использование

Ключ AES-128 задаётся через `--key` как строка из 32 шестнадцатеричных символов, то есть 16 байт. При шифровании этот аргумент необязателен, при расшифровании обязателен. Программу также можно запускать как Python-модуль: `python -m cryptocore`.

### Автоматическая генерация ключа и имени файла

Если при шифровании не указан `--key`, CryptoCore генерирует случайный ключ AES-128 и один раз выводит его в `stdout`. Пример ниже связан одной парой команд. Показанный ключ — только пример: при каждом запуске значение будет другим.

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --input "$env:TEMP\plaintext.bin"
[INFO] Generated random key: 8d8356a3061233e19b04b94e48e9fe36
cryptocore --algorithm aes --mode cbc --decrypt --key 8d8356a3061233e19b04b94e48e9fe36 --input "$env:TEMP\plaintext.bin.enc"
```

Без `--output` результат шифрования записывается в `<input>.enc`, а результат расшифрования — в `<input>.dec`. В примере создаются `plaintext.bin.enc` и `plaintext.bin.enc.dec`. Если автоматически выбранный путь уже существует, программа сообщает об ошибке и не перезаписывает файл. При явно указанном `--output` сохраняется обычная запись по заданному пути.

Сгенерированный ключ не записывается в зашифрованный файл. Его нужно сразу сохранить отдельно, иначе расшифровать данные не получится.

### CSPRNG и IV

Ключи и IV создаются функцией `cryptocore.csprng.generate_random_bytes`, которая использует системный `os.urandom`. Модуль `random` не подходит для генерации криптографических ключей и IV.

При шифровании в CBC, CFB, OFB и CTR 16-байтный IV создаётся автоматически через CSPRNG. ECB не использует IV.

### Предупреждение о предсказуемом ключе

Для ключа, переданного через `--key`, CryptoCore проверяет простые шаблоны: все байты одинаковые либо идут подряд по возрастанию или убыванию. При совпадении программа выводит в `stderr` предупреждение и продолжает работу:

```text
warning: key looks predictable
```

Это дополнительная проверка, а не полная оценка качества ключа.

### ECB

ECB не использует IV. Выходной файл содержит только ciphertext.

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 2b7e151628aed2a6abf7158809cf4f3c --input plaintext.bin --output ciphertext.bin
cryptocore --algorithm aes --mode ecb --decrypt --key 2b7e151628aed2a6abf7158809cf4f3c --input ciphertext.bin --output decrypted.bin
```

### Шифрование CBC/CFB/OFB/CTR

При шифровании в новых режимах пользователь не передаёт `--iv`. CryptoCore создаёт IV через `cryptocore.csprng.generate_random_bytes(16)` и записывает результат в формате:

```text
<16-byte IV><ciphertext>
```

Первые 16 байт выходного файла являются IV, остальные байты — ciphertext.

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 2b7e151628aed2a6abf7158809cf4f3c --input plaintext.bin --output ciphertext.bin
```

Для потоковых режимов используется та же команда со значением `--mode cfb`, `--mode ofb` или `--mode ctr`.

### Расшифрование файла CryptoCore

Если файл был создан CryptoCore и содержит `IV || ciphertext`, параметр `--iv` не нужен. CLI прочитает IV из первых 16 байт, а оставшиеся данные расшифрует как ciphertext.

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 2b7e151628aed2a6abf7158809cf4f3c --input ciphertext.bin --output decrypted.bin
```

Это поведение действует для CBC, CFB, OFB и CTR.

### Расшифрование с явным IV

При явном `--iv` входной файл должен содержать чистый ciphertext без IV-заголовка. CryptoCore использует весь входной файл и не удаляет из него первые 16 байт.

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 2b7e151628aed2a6abf7158809cf4f3c --iv 101112131415161718191a1b1c1d1e1f --input ciphertext.raw --output decrypted.bin
```

Таким образом:

```text
без --iv: input = IV || ciphertext
с --iv:   input = ciphertext
```

`--iv` разрешён только при расшифровании в CBC/CFB/OFB/CTR и должен содержать ровно 32 шестнадцатеричных символа. Пользовательский IV запрещён при шифровании и для ECB.

## Аргументы

| Аргумент | Описание |
| --- | --- |
| `--algorithm` | Алгоритм шифрования; поддерживается `aes` |
| `--mode` | Режим: `ecb`, `cbc`, `cfb`, `ofb` или `ctr` |
| `--encrypt` | Шифрование входного файла |
| `--decrypt` | Расшифрование входного файла |
| `--key` | Ключ AES-128: ровно 32 шестнадцатеричных символа; необязателен для encrypt, обязателен для decrypt |
| `--iv` | IV: ровно 32 шестнадцатеричных символа; только для decrypt новых режимов |
| `--input` | Путь к входному файлу |
| `--output` | Путь к выходному файлу; без аргумента добавляется `.enc` или `.dec` |

Параметры `--encrypt` и `--decrypt` взаимоисключающие: должен быть указан ровно один из них.

## Хеширование

SHA-256 по FIPS 180-4 и SHA3-256 по FIPS 202 написаны самостоятельно. Оба алгоритма возвращают 256-битный криптографический хеш.

Команда хеширования отделена от шифрования:

```text
cryptocore dgst --algorithm sha256|sha3-256 --input <путь> [--output <путь>]
```

При обычном хешировании команда `dgst` не принимает `--key`. Этот параметр разрешён только с `--hmac` или `--cmac`. Параметры шифрования `--mode`, `--encrypt`, `--decrypt` и `--iv` в `dgst` не используются.

Без `--output` результат выводится в `stdout` в формате `<хеш>  <путь>`. Между хешем и путём стоят два пробела, строка заканчивается переводом строки. Формат сделан по образцу `*sum`-утилит.

Примеры для PowerShell:

```powershell
cryptocore dgst --algorithm sha256 --input README.md
cryptocore dgst --algorithm sha3-256 --input README.md --output "$env:TEMP\cryptocore_hash.sha3"
```

При `--output` в файл записывается строка в том же формате, а перевод строки всегда имеет вид LF. Существующий выходной файл перезаписывается.

Значение `--input -` включает чтение из стандартного ввода. Следующий пример предназначен для Git Bash или Linux:

```bash
printf 'abc' | cryptocore dgst --algorithm sha256 --input -
```

В PowerShell передача текста через конвейер может изменить байты из-за кодировки или перевода строки.

Коды возврата: `0` — успех, `1` — ошибка чтения или записи, `2` — ошибка аргументов.

Длина результата обоих алгоритмов равна 256 битам. Для идеальной 256-битной хеш-функции поиск коллизии требует порядка 2^128 операций, а поиск прообраза — порядка 2^256. Хеш помогает обнаружить изменение данных, но без секретного ключа не подтверждает их подлинность: злоумышленник может изменить файл и пересчитать хеш. Для аутентификации используется MAC, например реализованный HMAC.

Обычный Python заметно медленнее системных утилит: исходные замеры дали примерно 0,12–0,19 МиБ/с. С extra `speed` тест файла размером 1025 МиБ занял 9,85 с для SHA-256 и 12,48 с для SHA3-256, после загрузки компилятора. Запуск отдельного CLI также включает время загрузки Python, NumPy и Numba. [Методика и результаты](TESTING.md#спринт-5-mac-и-ускорение-хеширования).

## Подлинность и целостность: HMAC и CMAC

MAC вычисляется с общим секретным ключом и позволяет обнаружить изменение данных при условии, что ключ известен только доверенным сторонам. Изменение файла, MAC или ключа приводит к отказу проверки с подавляющей вероятностью. MAC не шифрует содержимое и не является цифровой подписью: любая сторона, знающая общий ключ, может вычислить корректный MAC.

### HMAC-SHA256

HMAC реализован по [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.html) на собственной SHA-256:

```text
HMAC(K, message) = SHA256((K0 xor opad) || SHA256((K0 xor ipad) || message))
```

`ipad` — 64 повтора `0x36`, `opad` — 64 повтора `0x5c`. Если ключ длиннее 64 байт, сначала вычисляется его SHA-256. Затем ключ дополняется нулями до 64 байт. Результат HMAC содержит 32 байта, или 64 hex-символа.

Ключ передаётся через обязательный `--key` как hex-строка произвольной длины с чётным числом символов, без пробелов и префикса `0x`. Для реального использования рекомендуется случайный 32-байтный ключ; короткий или пустой ключ ослабляет защиту. Пустой ключ поддерживается для полноты алгоритма и тестирования. Ключ MAC автоматически не генерируется.

```powershell
# Получить случайный ключ; сохранить его отдельно.
python -c "from cryptocore.csprng import generate_random_bytes; print(generate_random_bytes(32).hex())"

# Ключ ниже — только пример.
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --output message.hmac
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --verify message.hmac
```

При `--hmac` алгоритм `sha256` можно не указывать. HMAC с `--algorithm sha3-256` не поддерживается.

### AES-CMAC

Бонусный AES-CMAC реализован по [NIST SP 800-38B](https://doi.org/10.6028/NIST.SP.800-38B). Он использует существующий одноблочный примитив AES-128. Генерация подключей, сцепление блоков и обработка последнего блока написаны в проекте. Полный последний блок складывается с `K1`; неполный или пустой дополняется `0x80` и нулями и складывается с `K2`. Результат — 16 байт, или 32 hex-символа.

```powershell
cryptocore dgst --cmac --algorithm aes --key 2b7e151628aed2a6abf7158809cf4f3c --input message.txt --output message.cmac
cryptocore dgst --cmac --key 2b7e151628aed2a6abf7158809cf4f3c --input message.txt --verify message.cmac
```

При `--cmac` алгоритм по умолчанию — `aes`; ключ должен содержать ровно 16 байт. `--hmac` и `--cmac` взаимоисключающие.

### Формат и проверка MAC

Оба MAC читают бинарный файл или `--input -` частями по 8192 байта. В `stdout` или файл `--output` записывается `<mac> <путь>` с одним пробелом и завершающим LF. Обычное хеширование сохраняет два пробела. Существующий файл `--output` перезаписывается после успешного чтения входа.

`--verify FILE` принимает один MAC в том же формате. Ожидаемый файл читается как UTF-8 с необязательным BOM; начальные и конечные пробелы, пустые строки и имя файла игнорируются. Допускается запись только hex-значения, включая верхний регистр. Проверяется именно файл из `--input`. Несколько непустых записей, некорректный hex и записи длиннее 65536 символов отклоняются.

Для сравнения используется `secrets.compare_digest`. При совпадении печатается `[OK] HMAC verification successful` (или `CMAC`), код завершения — `0`. При несовпадении в `stderr` печатается `[ERROR] HMAC verification failed`, код — `1`. Ошибки чтения или записи также возвращают `1`, ошибки аргументов — `2`. Причина несовпадения, например неверный ключ или изменённый файл, не различается.

`--verify` разрешён только для MAC и взаимоисключается с `--output`. Сам файл с ожидаемым MAC при проверке не изменяется.

## Структура проекта

```text
crypto_core_nk/
├── src/
│   └── cryptocore/
│       ├── __init__.py
│       ├── __main__.py
│       ├── aes.py
│       ├── cli.py
│       ├── csprng.py
│       ├── file_io.py
│       ├── hash/
│       │   ├── __init__.py
│       │   ├── acceleration.py
│       │   ├── accelerated_sha256.py
│       │   ├── accelerated_sha3.py
│       │   ├── sha256.py
│       │   └── sha3_256.py
│       ├── mac/
│       │   ├── __init__.py
│       │   ├── hmac.py
│       │   ├── cmac.py
│       │   └── verification.py
│       ├── padding.py
│       └── modes/
│           ├── __init__.py
│           ├── _utils.py
│           ├── ecb.py
│           ├── cbc.py
│           ├── cfb.py
│           ├── ofb.py
│           └── ctr.py
├── tests/
│   ├── test_aes.py
│   ├── test_cli.py
│   ├── test_cli_dgst.py
│   ├── test_cli_mac.py
│   ├── test_hmac.py
│   ├── test_cmac.py
│   ├── test_mac_verification.py
│   ├── test_hash_acceleration.py
│   ├── test_large_file_hmac.py
│   ├── test_cli_keys.py
│   ├── test_cli_modes.py
│   ├── test_csprng.py
│   ├── test_ecb.py
│   ├── test_file_io.py
│   ├── test_hash_avalanche.py
│   ├── test_hash_compatibility.py
│   ├── test_large_file_hash.py
│   ├── test_cbc.py
│   ├── test_cfb.py
│   ├── test_ofb.py
│   ├── test_ctr.py
│   ├── test_openssl_compatibility.py
│   ├── test_padding.py
│   ├── test_sha256.py
│   ├── test_sha3_256.py
│   └── test_sts_data.py
├── scripts/
│   ├── benchmark_hash.py
│   ├── check_large_hmac.py
│   └── generate_sts_data.py
├── TESTING.md
├── pyproject.toml
└── README.md
```

- `aes.py` — работа с одним блоком AES-128 через PyCryptodome;
- `padding.py` — дополнение PKCS#7;
- `modes/` — самостоятельно реализованная логика режимов;
- `cli.py` — интерфейс командной строки и обработка IV;
- `csprng.py` — генерация случайных байтов через системный источник;
- `file_io.py` — чтение и запись бинарных файлов;
- `hash/` — потоковые реализации SHA-256 и SHA3-256;
- `mac/` — потоковые HMAC-SHA256, AES-CMAC и чтение ожидаемого MAC;
- `scripts/benchmark_hash.py` — сравнение скорости хеширования с системными утилитами;
- `scripts/check_large_hmac.py` — проверка HMAC при ограничении памяти процесса;
- `scripts/generate_sts_data.py` — подготовка бинарных данных для NIST STS;
- `tests/` — модульные и интеграционные тесты.

## Проверка полного цикла

Пример полного цикла CBC с автоматическим чтением IV из зашифрованного файла:

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 2b7e151628aed2a6abf7158809cf4f3c --input a.bin --output a.bin.enc
cryptocore --algorithm aes --mode cbc --decrypt --key 2b7e151628aed2a6abf7158809cf4f3c --input a.bin.enc --output b.bin
python -c "from pathlib import Path; assert Path('a.bin').read_bytes() == Path('b.bin').read_bytes()"
```

Если последняя команда ничего не вывела, файлы совпадают.

## Проверка с OpenSSL

Автоматизированные тесты проверяют ECB, CBC, CFB-128, OFB и CTR в обоих направлениях: CryptoCore → OpenSSL и OpenSSL → CryptoCore.

```powershell
python -m pytest -q tests/test_openssl_compatibility.py
```

| CryptoCore mode | OpenSSL cipher |
| --- | --- |
| `ecb` | `aes-128-ecb` |
| `cbc` | `aes-128-cbc` |
| `cfb` | `aes-128-cfb` |
| `ofb` | `aes-128-ofb` |
| `ctr` | `aes-128-ctr` |

ECB не использует IV. ECB и CBC используют PKCS#7. В тестах совместимости ECB OpenSSL запускается без `-iv` и без `-nopad`.

Ниже приведены полные сценарии для CBC. Для CFB/OFB/CTR используются те же команды с соответствующими значениями из таблицы. Если `openssl` отсутствует в `PATH`, в ручных командах можно указать полный путь к executable, например `& "C:\Program Files\Git\usr\bin\openssl.exe"` в PowerShell.

### CryptoCore → OpenSSL

CryptoCore создаёт файл `IV || ciphertext`. Перед вызовом OpenSSL IV и чистый ciphertext нужно разделить:

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 2b7e151628aed2a6abf7158809cf4f3c --input plaintext.bin --output cipher.bin
python -c "from pathlib import Path; p=Path('cipher.bin').read_bytes(); Path('iv.hex').write_text(p[:16].hex()); Path('cipher.raw').write_bytes(p[16:])"
$iv = (Get-Content -Raw iv.hex).Trim()
openssl enc -aes-128-cbc -d -K 2b7e151628aed2a6abf7158809cf4f3c -iv $iv -in cipher.raw -out openssl_decrypted.bin
python -c "from pathlib import Path; assert Path('plaintext.bin').read_bytes() == Path('openssl_decrypted.bin').read_bytes()"
```

CBC использует обычный PKCS#7, поэтому `-nopad` здесь не применяется.

### OpenSSL → CryptoCore

OpenSSL создаёт чистый ciphertext, поэтому CryptoCore получает IV через `--iv`:

```powershell
openssl enc -aes-128-cbc -K 2b7e151628aed2a6abf7158809cf4f3c -iv 101112131415161718191a1b1c1d1e1f -in plaintext.bin -out openssl_cipher.bin
cryptocore --algorithm aes --mode cbc --decrypt --key 2b7e151628aed2a6abf7158809cf4f3c --iv 101112131415161718191a1b1c1d1e1f --input openssl_cipher.bin --output cryptocore_decrypted.bin
python -c "from pathlib import Path; assert Path('plaintext.bin').read_bytes() == Path('cryptocore_decrypted.bin').read_bytes()"
```

## Тесты

Полный набор тестов запускается одной командой:

```powershell
python -m pytest -q
```

Отдельный запуск OpenSSL compatibility tests:

```powershell
python -m pytest -q tests/test_openssl_compatibility.py
```

Тесты проверяют AES, PKCS#7, все пять режимов, CLI, CSPRNG, обработку ключей и IV, ошибочные сценарии, тестовые векторы NIST и совместимость с OpenSSL. Если OpenSSL действительно отсутствует, только compatibility tests могут быть пропущены.

Для пятого спринта добавлены векторы HMAC из RFC 4231, векторы AES-CMAC, проверка подмены файла, ключа и MAC, ошибки CLI и проверки обоих способов исполнения SHA. Три ресурсоёмких теста включаются отдельно:

```powershell
$env:CRYPTOCORE_RUN_LARGE_TESTS="1"
python -m pytest -q -s tests/test_large_file_hash.py tests/test_large_file_hmac.py
Remove-Item Env:CRYPTOCORE_RUN_LARGE_TESTS
```

Рекомендуется предварительно установить extra `speed`. В Windows тест HMAC использует файл 1025 МиБ и ограничение committed memory процесса 512 МиБ. В POSIX используется `RLIMIT_AS` и обычный Python, поскольку LLVM может резервировать большое виртуальное адресное пространство; такой прогон занимает существенно больше времени.

## Проверка CSPRNG через NIST STS

NIST Statistical Test Suite 2.1.2 содержит 15 статистических тестов для анализа случайных данных. Входной файл размером 10 000 000 байт создаётся вне репозитория командой PowerShell:

```powershell
python scripts/generate_sts_data.py "$env:TEMP\cryptocore_sts_data.bin"
```

Сам набор запускается в WSL из корневого каталога собранной STS:

```bash
./assess 1000000
```

Для выполненной проверки были выбраны бинарный формат, 80 последовательностей и все 15 тестов с параметрами по умолчанию. В итоговом отчёте нет строк, помеченных `*`. STS помогает найти статистические проблемы, но не доказывает криптографическую стойкость генератора.

[Подробные результаты тестирования](TESTING.md)

## Примечание по безопасности

ECB раскрывает повторяющиеся шаблоны данных и присутствует в проекте прежде всего в учебных целях. CBC, CFB, OFB и CTR обеспечивают конфиденциальность, но сами по себе не обеспечивают целостность и подлинность: изменение ciphertext или IV не всегда обнаруживается. HMAC и CMAC доступны как отдельные операции над файлами; автоматическое объединение шифрования с аутентификацией относится к следующему спринту.

Ключ, переданный через `--key`, может сохраниться в истории командной оболочки.

Сгенерированный ключ выводится в терминал. Он может остаться в прокрутке терминала, перенаправленном выводе или журналах запуска. С этим выводом нужно обращаться как с секретными данными, а ключ сразу сохранить отдельно в надёжном месте.

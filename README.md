# CryptoCore

CryptoCore — учебная консольная утилита для шифрования, расшифрования, хеширования, получения ключей и проверки подлинности текстовых и бинарных файлов. Поддерживаются AES-128, режимы ECB, CBC, CFB-128, OFB, CTR и GCM, HMAC-SHA256, AES-CMAC и библиотечная схема Encrypt-then-MAC, а также системная генерация ключей, IV и nonce.

Одноблочный примитив AES предоставляется PyCryptodome. Логика режимов ECB/CBC/CFB/OFB/CTR/GCM, GHASH и дополнение PKCS#7 реализованы в проекте. OpenSSL используется как независимый инструмент проверки совместимости.

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
- собственный AES-128-GCM с AAD, 12-байтным nonce и полным 16-байтным тегом;
- потоковая обработка файлов и бинарного AAD в GCM;
- Encrypt-then-MAC на AES-CTR и HMAC-SHA256 с разделением ключевого материала;
- проверка аутентификации до расшифрования и записи открытого текста;
- собственный PBKDF2-HMAC-SHA256 и команда получения ключей `derive`;
- иерархия ключей назначения через HMAC и контекст;
- необязательная JIT-компиляция собственных раундов SHA для больших файлов;
- модульные, интеграционные и OpenSSL compatibility tests.

## Зависимости

- Python 3.10+
- PyCryptodome 3.23.0
- pytest 8+ — только для запуска тестов
- OpenSSL — необязательный внешний инструмент для compatibility tests
- Numba 0.61+ — необязательный компилятор для ускорения собственных реализаций SHA и PBKDF2; устанавливается через extra `speed`, вместе с NumPy и llvmlite

Тесты совместимости ищут OpenSSL сначала по пути из `CRYPTOCORE_OPENSSL`, затем в `PATH`, а на Windows — в `C:\Program Files\Git\usr\bin\openssl.exe`. Если OpenSSL действительно отсутствует, эти тесты пропускаются, а остальные тесты проекта продолжают выполняться.

Для GCM используется библиотека OpenSSL `libcrypto` через EVP API: команда `openssl enc` не поддерживает GCM. Путь к библиотеке можно задать в `CRYPTOCORE_LIBCRYPTO`; без него проверяется системный поиск и стандартные пути Git for Windows. Отсутствие библиотеки пропускает только тесты EVP, неверный явный путь считается ошибкой тестирования. В рабочей реализации GCM библиотечные режимы не используются.

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

Для ускоренного хеширования, PBKDF2 и тестов:

```powershell
python -m pip install -e ".[dev,speed]"
```

Numba компилирует написанные в проекте раунды SHA-256 и Keccak-f[1600] в машинный код. Готовые хеш-функции `hashlib`, OpenSSL и PyCryptodome при вычислении SHA и HMAC не используются. При отсутствии Numba работает реализация на обычном Python. При потоковом хешировании компилятор загружается для частей сообщения от 4096 байт; в PBKDF2 отдельное ускорение цепочки HMAC включается от 1000 итераций. Первый запуск может потребовать компиляции; следующие используют дисковый кэш Numba.

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
| `gcm` | нет | nonce 12 байт | Аутентификация ciphertext и AAD, тег 16 байт |

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
| `--mode` | Режим: `ecb`, `cbc`, `cfb`, `ofb`, `ctr` или `gcm` |
| `--encrypt` | Шифрование входного файла |
| `--decrypt` | Расшифрование входного файла |
| `--key` | Ключ AES-128: ровно 32 шестнадцатеричных символа; необязателен для encrypt, обязателен для decrypt |
| `--iv` | Только decrypt: 32 hex-символа для CBC/CFB/OFB/CTR; в GCM — псевдоним `--nonce`, 24 hex-символа |
| `--nonce` | Только GCM decrypt: 12 байт как 24 hex-символа; вход без nonce-заголовка |
| `--aad` | Только GCM: AAD как hex-строка, по умолчанию пустая |
| `--aad-file` | Только GCM: читать бинарный AAD из файла по частям; несовместим с `--aad` |
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

## Аутентифицированное шифрование: AES-GCM

AEAD объединяет конфиденциальность и проверку подлинности. GCM шифрует содержимое и аутентифицирует его вместе с AAD (associated data). AAD может содержать открытые метаданные: он не шифруется и не записывается в выходной файл. Для расшифрования нужны те же байты AAD, что использовались при шифровании.

GCM реализован по [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final). Собственные GHASH и GCTR используют одноблочный AES-128. Умножение в `GF(2^128)` использует многочлен `x^128 + x^7 + x^2 + x + 1` и предвычисленную таблицу для ключа GHASH. Счётчик GCTR увеличивает только младшие 32 бита блока. Padding PKCS#7 не применяется.

При каждом шифровании CLI генерирует новый случайный 12-байтный nonce через CSPRNG. Пользовательский nonce при шифровании запрещён. Формат файла:

```text
nonce (12 байт) || ciphertext || tag (16 байт)
```

Длина файла увеличивается на 28 байт; даже пустой файл содержит nonce и тег. Пример полного цикла с AAD:

```powershell
cryptocore --algorithm aes --mode gcm --encrypt --key 2b7e151628aed2a6abf7158809cf4f3c --input message.txt --output message.gcm --aad aabbccddeeff
cryptocore --algorithm aes --mode gcm --decrypt --key 2b7e151628aed2a6abf7158809cf4f3c --input message.gcm --output restored.txt --aad aabbccddeeff
```

При успешном расшифровании печатается `[SUCCESS] Decryption completed successfully`, код возврата — `0`. Если ключ, AAD, nonce, ciphertext или тег неверны, результат проверки — отказ:

```text
[ERROR] Authentication failed: wrong key, AAD, or tampered data
```

Код возврата — `1`. Открытый текст не вычисляется и не выводится, выходной файл не создаётся, существующий выходной файл сохраняется. Это означает полный отказ операции; программа не пытается вернуть частично расшифрованные данные. Некорректные аргументы, например `--aad wrongaad123`, возвращают `2`: AAD должен быть корректной hex-строкой с чётным числом символов. Пустая строка `--aad ""` допустима.

Для расшифрования внешнего ciphertext без nonce-заголовка используется `--nonce` (или `--iv`). Вход при этом должен содержать `ciphertext || tag`:

```powershell
cryptocore --algorithm aes --mode gcm --decrypt --key 2b7e151628aed2a6abf7158809cf4f3c --nonce cafebabefacedbaddecaf888 --input external.raw --output restored.txt --aad aabbccddeeff
```

Без `--output` действуют прежние имена `.enc`/`.dec` и запрет перезаписи существующего файла. Явный `--output` заменяется готовым результатом только после успеха. Без `--key` при шифровании генерируется случайный ключ AES-128; он выводится один раз после успешной записи.

### Большой AAD и файлы

`--aad-file` читает **бинарные байты**, а не hex-текст. Этот параметр предназначен в том числе для AAD, который не помещается в память:

```powershell
cryptocore --algorithm aes --mode gcm --encrypt --key 2b7e151628aed2a6abf7158809cf4f3c --input message.bin --output message.gcm --aad-file metadata.bin
cryptocore --algorithm aes --mode gcm --decrypt --key 2b7e151628aed2a6abf7158809cf4f3c --input message.gcm --output restored.bin --aad-file metadata.bin
```

Данные и AAD читаются частями до 8192 байт. При расшифровании проверяемый ciphertext сохраняется во временном файле; только после проверки тега расшифровывается именно эта копия. Это исключает подмену входных байтов между проверкой и расшифрованием. Дополнительное место на диске требуется для копии ciphertext и готовящегося результата. Временные файлы удаляются при штатном завершении и обработанных ошибках; аварийное завершение процесса может оставить временный файл результата.

GCM ограничивает длину одного сообщения значением `2^36 - 32` байта, длину AAD — `2^61 - 1` байт. Превышение отклоняется. CLI использует nonce только длиной 12 байт; библиотечные функции поддерживают другие непустые длины через GHASH.

### Библиотечный интерфейс

```python
from cryptocore.aead import AuthenticationError
from cryptocore.modes.gcm import GCM

cipher = GCM(key)  # key — 16 случайных байт
packet = cipher.encrypt(b"message", aad=b"metadata")
plaintext = GCM(key).decrypt(packet, aad=b"metadata")
```

Повторные вызовы `encrypt()` без явного nonce каждый раз генерируют новый nonce. AAD принимается как `bytes` либо одноразовый итератор бинарных частей. Для файлов доступны `cryptocore.aead.files.encrypt_file()` и `decrypt_file()`. Низкоуровневые `cryptocore.modes.gcm.encrypt(key, nonce, data, aad)` и `decrypt(...)` принимают nonce отдельно и работают с `ciphertext || tag`. Явный nonce в библиотеке нужен для тестов и совместимости; в оболочке `GCM(key, nonce)` он также задаёт длину заголовка пакета.

**Нельзя повторять nonce с тем же GCM-ключом:** это может разрушить конфиденциальность и подлинность. Случайная генерация и тест 1000 значений не являются математической гарантией отсутствия повторов. Для работы с большим числом сообщений нужно управлять сроком использования ключа. Реализация учебная; Python и табличный GHASH не предоставляют гарантий постоянного времени выполнения.

## Encrypt-then-MAC

`cryptocore.aead.etm.EncryptThenMAC` объединяет собственные AES-CTR и HMAC-SHA256 из предыдущих спринтов. Это отдельный библиотечный интерфейс. Для него требуются **48 байт ключевого материала**: первые 16 используются для AES, оставшиеся 32 — для HMAC. Материал можно сгенерировать случайно или получить из пароля и затем разделить ключи по назначению, как показано в разделе KDF ниже.

```python
from cryptocore.aead.etm import EncryptThenMAC
from cryptocore.csprng import generate_random_bytes

key_material = generate_random_bytes(48)  # сохранить отдельно
cipher = EncryptThenMAC(key_material)
packet = cipher.encrypt(b"message", aad=b"metadata")
plaintext = cipher.decrypt(packet, aad=b"metadata")
```

Формат пакета — `IV[16] || ciphertext || HMAC[32]`. Каждый вызов шифрования генерирует новый IV. HMAC вычисляется над `D || K_e || IV || ciphertext || AAD || len(ciphertext) || len(AAD)`, где `D = b"CryptoCore-EtM-CTR-HMAC-SHA256-v1\x00"`, а длины — 64-битные числа big-endian в байтах. AES-ключ внутри входа HMAC связывает тег с обеими частями ключевого материала; сам ключ в пакет не записывается. IV и длины полей аутентифицируются, чтобы обнаруживать подмену IV и перенос байтов между ciphertext и AAD. Это явное уточнение упрощённой формулы `MAC(C || AAD)` из задания.

При неверном MAC выбрасывается общий `AuthenticationError` до расшифрования CTR. Сравнение тегов в обеих схемах использует `secrets.compare_digest`. EtM принимает сообщение целиком в памяти, а AAD может получать частями.

## Получение ключей: PBKDF2-HMAC-SHA256

PBKDF2 получает ключ из пароля и соли (`salt`). Соль не является секретом: она делает результаты для одного пароля разными и мешает переиспользовать заранее вычисленные таблицы. Итерации увеличивают стоимость каждого подбора пароля; они не добавляют энтропию слабому паролю.

```text
cryptocore derive --password PASSWORD [--salt HEX] [--iterations COUNT] [--length BYTES] [--algorithm pbkdf2] [--output FILE]
```

| Параметр | Поведение |
|---|---|
| `--password` | Пароль как строка UTF-8; пустая строка допустима для тестов |
| `--password-file` | Вместо `--password`: точные бинарные байты файла, включая BOM, NUL и переводы строк |
| `--password-env` | Вместо `--password`: имя переменной окружения с паролем, значение кодируется UTF-8 |
| `--salt` | Строгий hex без пробелов и `0x`; без параметра генерируется случайная соль 16 байт |
| `--iterations` | Положительное целое число; по умолчанию `100000` согласно заданию |
| `--length` | Длина ключа в байтах; по умолчанию `32`, минимум `1` |
| `--algorithm` | `pbkdf2`, также используется по умолчанию; PRF всегда HMAC-SHA256 |
| `--output` | Записать только сырые бинарные байты ключа, без соли и без перевода строки |

Нужен ровно один источник пароля. В `stdout` всегда выводится `KEY_HEX  SALT_HEX` с двумя пробелами и завершающим переводом строки, в том числе при `--output`. Соль нужно сохранить вместе с числом итераций и длиной ключа, чтобы воспроизвести результат. Сам файл `--output` содержит только ключ. Существующий файл заменяется готовым результатом после успешного вычисления.

```powershell
cryptocore derive --password 'MySecurePassword123!' --salt 000102030405060708090a0b0c0d0e0f --iterations 100000 --length 32

# Новый случайный salt; ключ записывается как бинарные байты.
cryptocore derive --password-file password.bin --iterations 600000 --length 32 --output app.key

# Значение переменной окружения не передаётся в аргументах процесса.
cryptocore derive --password-env CRYPTOCORE_PASSWORD --iterations 600000 --length 32
```

Для проверки алгоритма допустимы маленькие числа итераций. Воспроизводимый пример с публичными тестовыми данными:

```text
cryptocore derive --password password --salt 73616c74 --iterations 1 --length 20
120fb6cffcf8b32c43e7225256c4f837a86548c9  73616c74
```

PBKDF2 написан по [RFC 2898](https://www.rfc-editor.org/rfc/rfc2898.html) / [RFC 8018, §5.2](https://www.rfc-editor.org/rfc/rfc8018.html#section-5.2) на собственном HMAC-SHA256:

```text
U1 = HMAC(password, salt || INT32_BE(i))
Uj = HMAC(password, Uj-1)
Ti = U1 xor U2 xor ... xor Uc
key = (T1 || T2 || ...)[0:length]
```

Номера блоков начинаются с 1, каждый блок результата содержит 32 байта. Максимальная длина — `(2^32 - 1) * 32` байт по формату счётчика. Практический размер ключа также ограничен доступной памятью. Соль в библиотечном API передаётся как байты, строка пароля — как UTF-8 либо байты произвольного содержания. Ошибки аргументов CLI возвращают `2`, ошибки чтения, генерации соли или записи — `1`, успех — `0`. При ошибке записи ключ не выводится в stdout, прежний файл сохраняется.

### Производительность и обработка пароля

HMAC один раз подготавливает состояния SHA после `ipad` и `opad`; следующие вызовы PRF используют их копии. При установленном extra `speed` цепочки от 1000 итераций компилируются Numba поверх собственного ядра SHA-256 спринта 5. Начальные состояния и `U1` получены классом HMAC; скомпилированный цикл вычисляет `U2..Uc` и XOR. Готовые PBKDF2, HMAC и SHA из криптографических библиотек не подставляются. Кэш Numba хранит машинный код, а не значения пароля и состояний.

После отдельного прогрева для 32-байтного ключа получены времена: 10k итераций — 0,011 с; 100k — 0,097 с; 1M — 1,001 с. Загрузка компилятора и прогрев заняли ещё 1,252 с внутри процесса. Полный запуск CLI дополнительно включает загрузку Python. Без Numba или с `CRYPTOCORE_PURE_PYTHON=1` работает тот же алгоритм на обычном Python, существенно медленнее. [Методика и результаты](TESTING.md#спринт-7-получение-ключей).

```powershell
python scripts/benchmark_kdf.py --iterations 10000 100000 1000000 --json-output "$env:TEMP\cryptocore_kdf_benchmark.json"
```

Значение `100000` сохранено для соответствия заданию и не является универсальным современным минимумом безопасности. Для PBKDF2-HMAC-SHA256 [OWASP рекомендует 600000 итераций](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2); нагрузку следует измерять на целевой системе. Для новых операций используйте случайную соль не короче 16 байт. Пустые или короткие соль и пароль поддерживаются для полноты алгоритма и тестов.

Пароль в `--password` может остаться в истории оболочки и списке аргументов процесса. Файл и переменная окружения уменьшают этот риск, но тоже требуют защиты. CLI обнуляет собственный `bytearray` пароля сразу после вычисления, в том числе при ошибке; гарантировать удаление всех копий в Python, `argv`, окружении и состояниях HMAC невозможно. Выведенный в stdout и сохранённый в файл ключ являются секретными данными.

### Иерархия ключей назначения

`derive_key(master_key: bytes, context: str, length: int = 32) -> bytes` реализует точную схему задания:

```text
block_i = HMAC-SHA256(master_key, UTF8(context) || INT32_BE(i))
key = (block_1 || block_2 || ...)[0:length]
```

Функция детерминирована: одинаковые параметры дают одинаковый результат. Разные контексты отделяют ключи разных назначений. При одном контексте более короткий ключ является префиксом более длинного; для независимых ключей используйте разные контексты. Путь `kdf/hkdf.py` сохранён по рекомендации задания, однако это счётчиковая схема, **не HKDF Extract/Expand из RFC 5869**.

Пример получения раздельных ключей Encrypt-then-MAC из пароля:

```python
from cryptocore.aead.etm import EncryptThenMAC
from cryptocore.csprng import generate_random_bytes
from cryptocore.kdf import derive_key, pbkdf2_hmac_sha256

salt = generate_random_bytes(16)  # сохранить, не является секретом
master = pbkdf2_hmac_sha256("example password", salt, 600000, 32)
encryption_key = derive_key(master, "etm/encryption", 16)
authentication_key = derive_key(master, "etm/authentication", 32)
cipher = EncryptThenMAC(encryption_key + authentication_key)
packet = cipher.encrypt(b"message", aad=b"metadata")
plaintext = cipher.decrypt(packet, aad=b"metadata")
```

В ТЗ спринта 7 есть несогласованность: [RFC 6070](https://www.rfc-editor.org/rfc/rfc6070.html) содержит векторы PBKDF2-HMAC-SHA1. Требуемый SHA256 проверяется по двум настоящим векторам [RFC 7914, §11](https://www.rfc-editor.org/rfc/rfc7914.html#section-11), `hashlib.pbkdf2_hmac` и OpenSSL с явно выбранным `digest:SHA256` и бинарной солью через `hexsalt:`. Строка `fixedappsalt` из примеров ТЗ не является допустимым hex и отклоняется.

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
│       ├── aead/
│       │   ├── __init__.py
│       │   ├── etm.py
│       │   └── files.py
│       ├── kdf/
│       │   ├── __init__.py
│       │   ├── _validation.py
│       │   ├── pbkdf2.py
│       │   ├── accelerated_pbkdf2.py
│       │   └── hkdf.py
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
│           ├── ctr.py
│           └── gcm.py
├── tests/
│   ├── test_aes.py
│   ├── test_cli.py
│   ├── test_cli_dgst.py
│   ├── test_cli_mac.py
│   ├── test_cli_gcm.py
│   ├── test_gcm.py
│   ├── test_gcm_openssl.py
│   ├── test_etm.py
│   ├── test_large_aad.py
│   ├── test_pbkdf2.py
│   ├── test_key_hierarchy.py
│   ├── test_cli_derive.py
│   ├── test_kdf_openssl.py
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
│   ├── check_large_aad.py
│   ├── benchmark_kdf.py
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
- `modes/gcm.py` — собственные GHASH, GCTR и GCM;
- `aead/` — общий отказ аутентификации, Encrypt-then-MAC и потоковые файлы GCM;
- `kdf/` — собственный PBKDF2 и счётчиковая иерархия ключей через HMAC;
- `scripts/benchmark_hash.py` — сравнение скорости хеширования с системными утилитами;
- `scripts/check_large_hmac.py` — проверка HMAC при ограничении памяти процесса;
- `scripts/check_large_aad.py` — проверка GCM с AAD больше лимита памяти процесса;
- `scripts/benchmark_kdf.py` — замеры PBKDF2 на 10k, 100k и 1M итераций с проверкой эталона;
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

Тесты проверяют AES, PKCS#7, все шесть режимов, CLI, CSPRNG, обработку ключей и IV, ошибочные сценарии, тестовые векторы NIST и совместимость с OpenSSL. Если OpenSSL действительно отсутствует, только compatibility tests могут быть пропущены.

В седьмом спринте добавлены настоящие векторы PBKDF2-HMAC-SHA256 из RFC 7914, длины ключей 1–100 байт, разделение контекстов, 1000 уникальных солей, бинарный вывод и источники пароля, 36 сравнений с OpenSSL KDF и проверки обоих способов исполнения PBKDF2. Проверки JIT требуют extra `speed` и могут пропускаться без него; математические проверки и обычный Python сохраняются.

Для пятого спринта добавлены векторы HMAC из RFC 4231, векторы AES-CMAC, проверка подмены файла, ключа и MAC, ошибки CLI и проверки обоих способов исполнения SHA. В шестом добавлены векторы GCM NIST, сравнение с PyCryptodome и OpenSSL EVP, подмена каждого поля, проверки отказа до расшифрования, потокового AAD и атомарной записи. Четыре ресурсоёмких теста включаются отдельно:

```powershell
$env:CRYPTOCORE_RUN_LARGE_TESTS="1"
python -m pytest -q -s tests/test_large_file_hash.py tests/test_large_file_hmac.py tests/test_large_aad.py
Remove-Item Env:CRYPTOCORE_RUN_LARGE_TESTS
```

Рекомендуется предварительно установить extra `speed`. В Windows тест HMAC использует файл 1025 МиБ и ограничение committed memory процесса 512 МиБ. В POSIX используется `RLIMIT_AS` и обычный Python, поскольку LLVM может резервировать большое виртуальное адресное пространство; такой прогон занимает существенно больше времени.

Тест GCM использует AAD 65 МиБ при лимите памяти процесса 64 МиБ и не требует extra `speed`. Отдельный запуск: `python scripts/check_large_aad.py`.

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

ECB раскрывает повторяющиеся шаблоны данных и присутствует в проекте прежде всего в учебных целях. CBC, CFB, OFB и CTR обеспечивают конфиденциальность, но сами по себе не обеспечивают целостность и подлинность: изменение ciphertext или IV не всегда обнаруживается. GCM и библиотечная схема Encrypt-then-MAC объединяют шифрование с аутентификацией; HMAC и CMAC также доступны как отдельные операции над файлами.

Ключ, переданный через `--key`, может сохраниться в истории командной оболочки.

Сгенерированный ключ выводится в терминал. Он может остаться в прокрутке терминала, перенаправленном выводе или журналах запуска. С этим выводом нужно обращаться как с секретными данными, а ключ сразу сохранить отдельно в надёжном месте.

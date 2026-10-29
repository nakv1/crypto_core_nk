# CryptoCore

CryptoCore — учебная консольная утилита для шифрования и расшифрования текстовых и бинарных файлов. Поддерживаются AES-128, режимы ECB, CBC, CFB-128, OFB и CTR, а также системная генерация ключей и IV.

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
- модульные, интеграционные и OpenSSL compatibility tests.

## Зависимости

- Python 3.10+
- PyCryptodome 3.23.0
- pytest 8+ — только для запуска тестов
- OpenSSL — необязательный внешний инструмент для compatibility tests

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
│   ├── test_cli_keys.py
│   ├── test_cli_modes.py
│   ├── test_csprng.py
│   ├── test_ecb.py
│   ├── test_file_io.py
│   ├── test_cbc.py
│   ├── test_cfb.py
│   ├── test_ofb.py
│   ├── test_ctr.py
│   ├── test_openssl_compatibility.py
│   ├── test_padding.py
│   └── test_sts_data.py
├── scripts/
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

Автоматизированные тесты проверяют CBC, CFB-128, OFB и CTR в обоих направлениях: CryptoCore → OpenSSL и OpenSSL → CryptoCore.

```powershell
python -m pytest -q tests/test_openssl_compatibility.py
```

| CryptoCore mode | OpenSSL cipher |
| --- | --- |
| `cbc` | `aes-128-cbc` |
| `cfb` | `aes-128-cfb` |
| `ofb` | `aes-128-ofb` |
| `ctr` | `aes-128-ctr` |

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

ECB раскрывает повторяющиеся шаблоны данных и присутствует в проекте прежде всего в учебных целях. CBC, CFB, OFB и CTR обеспечивают конфиденциальность, но сами по себе не обеспечивают целостность и подлинность: изменение ciphertext или IV не всегда обнаруживается. Механизмы аутентификации пока не реализованы.

Ключ, переданный через `--key`, может сохраниться в истории командной оболочки.

Сгенерированный ключ выводится в терминал. Он может остаться в прокрутке терминала, перенаправленном выводе или журналах запуска. С этим выводом нужно обращаться как с секретными данными, а ключ сразу сохранить отдельно в надёжном месте.

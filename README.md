# CryptoCore

CryptoCore — учебная консольная утилита для шифрования и расшифрования текстовых и бинарных файлов. В Sprint 2 поддерживаются AES-128 и режимы ECB, CBC, CFB-128, OFB и CTR.

Одноблочный примитив AES предоставляется PyCryptodome. Логика режимов ECB/CBC/CFB/OFB/CTR и дополнение PKCS#7 реализованы в проекте. OpenSSL используется как независимый инструмент проверки совместимости.

## Реализовано в Sprint 2

- AES-128;
- режимы ECB, CBC, CFB-128, OFB и CTR;
- PKCS#7 для ECB и CBC;
- обработка неполного последнего блока без padding в CFB/OFB/CTR;
- генерация 16-байтного IV через `os.urandom(16)`;
- формат файлов с IV для новых режимов;
- шифрование и расшифрование бинарных файлов через CLI;
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

Ключ AES-128 передаётся через `--key` как строка из 32 шестнадцатеричных символов, то есть 16 байт. Программу также можно запускать как Python-модуль: `python -m cryptocore`.

### ECB

ECB не использует IV. Выходной файл содержит только ciphertext.

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.bin --output ciphertext.bin
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.bin
```

### Шифрование CBC/CFB/OFB/CTR

При шифровании в новых режимах пользователь не передаёт `--iv`. CryptoCore вызывает `os.urandom(16)` и записывает результат в формате:

```text
<16-byte IV><ciphertext>
```

Первые 16 байт выходного файла являются IV, остальные байты — ciphertext.

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.bin --output ciphertext.bin
```

Для потоковых режимов используется та же команда со значением `--mode cfb`, `--mode ofb` или `--mode ctr`.

### Расшифрование файла CryptoCore

Если файл был создан CryptoCore и содержит `IV || ciphertext`, параметр `--iv` не нужен. CLI прочитает IV из первых 16 байт, а оставшиеся данные расшифрует как ciphertext.

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.bin
```

Это поведение действует для CBC, CFB, OFB и CTR.

### Расшифрование с явным IV

При явном `--iv` входной файл должен содержать чистый ciphertext без IV-заголовка. CryptoCore использует весь входной файл и не удаляет из него первые 16 байт.

```powershell
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --iv 101112131415161718191a1b1c1d1e1f --input ciphertext.raw --output decrypted.bin
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
| `--key` | Ключ AES-128: ровно 32 шестнадцатеричных символа |
| `--iv` | IV: ровно 32 шестнадцатеричных символа; только для decrypt новых режимов |
| `--input` | Путь к входному файлу |
| `--output` | Путь к выходному файлу |

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
│   ├── test_cli_modes.py
│   ├── test_ecb.py
│   ├── test_cbc.py
│   ├── test_cfb.py
│   ├── test_ofb.py
│   ├── test_ctr.py
│   ├── test_openssl_compatibility.py
│   └── test_padding.py
├── pyproject.toml
└── README.md
```

- `aes.py` — работа с одним блоком AES-128 через PyCryptodome;
- `padding.py` — дополнение PKCS#7;
- `modes/` — самостоятельно реализованная логика режимов;
- `cli.py` — интерфейс командной строки и обработка IV;
- `file_io.py` — чтение и запись бинарных файлов;
- `tests/` — модульные и интеграционные тесты.

## Проверка полного цикла

Пример полного цикла CBC с автоматическим чтением IV из зашифрованного файла:

```powershell
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input a.bin --output a.bin.enc
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --input a.bin.enc --output b.bin
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
cryptocore --algorithm aes --mode cbc --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.bin --output cipher.bin
python -c "from pathlib import Path; p=Path('cipher.bin').read_bytes(); Path('iv.hex').write_text(p[:16].hex()); Path('cipher.raw').write_bytes(p[16:])"
$iv = (Get-Content -Raw iv.hex).Trim()
openssl enc -aes-128-cbc -d -K 000102030405060708090a0b0c0d0e0f -iv $iv -in cipher.raw -out openssl_decrypted.bin
python -c "from pathlib import Path; assert Path('plaintext.bin').read_bytes() == Path('openssl_decrypted.bin').read_bytes()"
```

CBC использует обычный PKCS#7, поэтому `-nopad` здесь не применяется.

### OpenSSL → CryptoCore

OpenSSL создаёт чистый ciphertext, поэтому CryptoCore получает IV через `--iv`:

```powershell
openssl enc -aes-128-cbc -K 000102030405060708090a0b0c0d0e0f -iv 101112131415161718191a1b1c1d1e1f -in plaintext.bin -out openssl_cipher.bin
cryptocore --algorithm aes --mode cbc --decrypt --key 000102030405060708090a0b0c0d0e0f --iv 101112131415161718191a1b1c1d1e1f --input openssl_cipher.bin --output cryptocore_decrypted.bin
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

Тесты проверяют AES, PKCS#7, все пять режимов, CLI, обработку IV, ошибочные сценарии, тестовые векторы NIST и совместимость с OpenSSL. Если OpenSSL действительно отсутствует, только compatibility tests могут быть пропущены.

## Примечание по безопасности

ECB раскрывает повторяющиеся шаблоны данных и присутствует в проекте прежде всего в учебных целях. CBC, CFB, OFB и CTR обеспечивают конфиденциальность, но сами по себе не обеспечивают целостность и подлинность: изменение ciphertext или IV не всегда обнаруживается. Механизмы аутентификации не входят в Sprint 2.

Ключ, переданный через `--key`, может сохраниться в истории командной оболочки.

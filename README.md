# CryptoCore

CryptoCore — учебная консольная утилита для работы с криптографическими алгоритмами. В Sprint 1 реализованы AES-128, режим ECB и дополнение PKCS#7. Проект поддерживает шифрование и расшифрование текстовых и бинарных файлов.

## Реализовано в Sprint 1

- AES-128;
- режим ECB;
- дополнение PKCS#7;
- шифрование и расшифрование файлов;
- консольный интерфейс;
- работа с бинарными данными;
- тесты и проверка совместимости с OpenSSL.

## Зависимости

- Python 3.10+
- PyCryptodome 3.23.0
- pytest 8+ — только для запуска тестов
- OpenSSL — необязательно, используется только для проверки совместимости

## Установка

Команды для Windows PowerShell:

```powershell
git clone https://github.com/nakv1/crypto_core_nk.git
cd crypto_core_nk
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Использование

### Шифрование

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.txt --output ciphertext.bin
```

### Расшифрование

```powershell
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.txt
```

Программу также можно запустить как Python-модуль: `python -m cryptocore`.

## Аргументы

| Аргумент | Описание |
| --- | --- |
| `--algorithm` | Алгоритм шифрования. В Sprint 1 поддерживается только `aes`. |
| `--mode` | Режим шифрования. В Sprint 1 поддерживается только `ecb`. |
| `--encrypt` | Шифрование входного файла. |
| `--decrypt` | Расшифрование входного файла. |
| `--key` | Ключ AES-128: ровно 32 шестнадцатеричных символа. |
| `--input` | Путь к входному файлу. |
| `--output` | Путь к выходному файлу. |

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
│           └── ecb.py
├── tests/
│   ├── test_aes.py
│   ├── test_cli.py
│   ├── test_ecb.py
│   └── test_padding.py
├── pyproject.toml
└── README.md
```

- `aes.py` — работа с одним блоком AES-128;
- `padding.py` — дополнение PKCS#7;
- `modes/ecb.py` — логика режима ECB;
- `cli.py` — интерфейс командной строки;
- `file_io.py` — чтение и запись файлов;
- `tests/` — тесты проекта.

## Проверка полного цикла

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input a.bin --output a.bin.enc
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input a.bin.enc --output b.bin
python -c "from pathlib import Path; assert Path('a.bin').read_bytes() == Path('b.bin').read_bytes()"
```

Если последняя команда ничего не вывела, файлы совпадают.

## Проверка с OpenSSL

CryptoCore и OpenSSL используют дополнение PKCS#7, поэтому параметр `-nopad` здесь не нужен.

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.bin --output ciphertext.bin
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -in plaintext.bin -out ciphertext.bin.ossl
python -c "from pathlib import Path; assert Path('ciphertext.bin').read_bytes() == Path('ciphertext.bin.ossl').read_bytes()"
```

## Тесты

```powershell
python -m pytest -q
```

Тесты проверяют AES, PKCS#7, ECB, CLI и обработку ошибочных сценариев.

## Примечание

ECB используется в проекте только в учебных целях и не рекомендуется для защиты реальных данных.

# CryptoCore

CryptoCore — учебная библиотека и консольная утилита на Python для шифрования и расшифрования файлов с помощью AES-128. В Sprint 1 реализованы режим ECB и дополнение PKCS#7. PyCryptodome используется только для преобразования одного блока AES.

## Требования и зависимости

- Python 3.10 или новее
- PyCryptodome 3.23.0
- pytest 8 или новее для запуска тестов

OpenSSL не требуется для работы программы и используется только для проверки совместимости.

## Установка

Создание и активация виртуального окружения в Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

Установка вместе с зависимостями для тестов:

```powershell
python -m pip install -e ".[dev]"
```

## Использование

Ключ передаётся через `--key` как строка из 32 шестнадцатеричных символов. Такая строка соответствует 16-байтному ключу AES-128.

Шифрование файла:

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.bin --output ciphertext.bin
```

Расшифрование файла:

```powershell
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input ciphertext.bin --output decrypted.bin
```

Ту же команду можно запустить как Python-модуль:

```powershell
python -m cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.bin --output ciphertext.bin
```

## Проверка полного цикла

В примере файл `a.bin` сначала шифруется, затем расшифровывается в `b.bin`:

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input a.bin --output a.bin.enc
cryptocore --algorithm aes --mode ecb --decrypt --key 000102030405060708090a0b0c0d0e0f --input a.bin.enc --output b.bin
python -c "from pathlib import Path; assert Path('a.bin').read_bytes() == Path('b.bin').read_bytes()"
```

Если файлы совпадают, последняя команда ничего не выводит.

## Проверка через OpenSSL

CryptoCore и OpenSSL по умолчанию используют стандартное дополнение PKCS#7. Для этой проверки не нужно передавать `-nopad`.

```powershell
cryptocore --algorithm aes --mode ecb --encrypt --key 000102030405060708090a0b0c0d0e0f --input plaintext.bin --output ciphertext.bin
openssl enc -aes-128-ecb -K 000102030405060708090a0b0c0d0e0f -in plaintext.bin -out ciphertext.bin.ossl
python -c "from pathlib import Path; assert Path('ciphertext.bin').read_bytes() == Path('ciphertext.bin.ossl').read_bytes()"
```

Команды работают в PowerShell, Git Bash и Linux, если `openssl` доступен в `PATH`.

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

`aes.py` выполняет преобразование одного блока AES, `padding.py` отвечает за PKCS#7, а `modes/ecb.py` обрабатывает блоки в режиме ECB. В `cli.py` находится интерфейс командной строки, в `file_io.py` — бинарное чтение и запись файлов. Каталог `tests` содержит тесты этих компонентов.

## Тесты

```powershell
python -m pytest -q
```

## Замечание о безопасности

ECB сохраняет заметные закономерности исходных данных и не подходит для защиты реальной информации. В этом проекте режим используется только в учебных целях.

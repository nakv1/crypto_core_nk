"""Потоковый формат GCM: nonce[12] || ciphertext || tag[16]."""

from pathlib import Path
from tempfile import TemporaryFile

from cryptocore import csprng
from cryptocore.aead import AuthenticationError
from cryptocore.file_io import atomic_output, iter_chunks
from cryptocore.modes.gcm import GCMAuthenticator, GCTR


def encrypt_file(key, input_path, output_path, aad=b"", *, exclusive=False):
    """Читает файл и AAD частями, каждый раз генерирует 12-байтный nonce."""
    # Закрываем источник до публикации результата, в том числе при input=output.
    with atomic_output(output_path, exclusive) as output:
        with Path(input_path).open("rb") as source:
            nonce = csprng.generate_random_bytes(12)
            state = GCMAuthenticator(key, nonce, aad)
            counter = GCTR(state.aes, state.j0)
            output.write(nonce)
            for chunk in iter_chunks(source):
                ciphertext = counter.update(chunk)
                state.update(ciphertext)
                output.write(ciphertext)
            output.write(state.digest())


def decrypt_file(key, input_path, output_path, aad=b"", *, nonce=None, exclusive=False):
    """Проверяет сохранённую копию ciphertext, затем расшифровывает именно её.

    До успешной проверки тега не создаётся ни открытый текст, ни выходной файл.
    Временный поток содержит только ciphertext и закрывается при любой ошибке.
    При явном nonce вход имеет вид ciphertext || tag, без заголовка nonce.
    """
    with TemporaryFile(mode="w+b") as ciphertext_file:
        with Path(input_path).open("rb") as source:
            if nonce is None:
                nonce = source.read(12)
                if len(nonce) != 12:
                    raise AuthenticationError("authentication failed")
            state = GCMAuthenticator(key, nonce, aad)
            tail = b""
            for chunk in iter_chunks(source):
                pending = tail + chunk
                if len(pending) <= 16:
                    tail = pending
                    continue
                body, tail = pending[:-16], pending[-16:]
                state.update(body)
                ciphertext_file.write(body)
            if len(tail) != 16:
                raise AuthenticationError("authentication failed")
            state.verify(tail)
        ciphertext_file.seek(0)
        counter = GCTR(state.aes, state.j0)
        with atomic_output(output_path, exclusive) as output:
            for chunk in iter_chunks(ciphertext_file):
                output.write(counter.update(chunk))

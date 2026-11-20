"""Ленивая загрузка необязательного компилятора собственных раундов."""

import os
from functools import lru_cache
from importlib import import_module
from importlib.util import find_spec


def get_processor(algorithm: str):
    """Возвращает обработчик полных блоков или обычный режим Python."""
    if os.environ.get("CRYPTOCORE_PURE_PYTHON") == "1":
        return None
    return _load_processor(algorithm)


@lru_cache(maxsize=2)
def _load_processor(algorithm: str):
    if find_spec("numba") is None:
        return None
    return import_module(f"cryptocore.hash.accelerated_{algorithm}").process

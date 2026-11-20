"""Коды аутентичности сообщений CryptoCore."""

from cryptocore.mac.hmac import HMAC
from cryptocore.mac.cmac import CMAC

__all__ = ["HMAC", "CMAC"]

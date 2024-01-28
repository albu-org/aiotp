
import hmac
import base64
import hashlib

from ..typing import algorithms
from ..abstracts import AbstractOTP


class OTP(AbstractOTP):
    def __init__(
        self,
        secret: str,
        digit: int = 5,
        algorithm: algorithms = 'sha1'
    ) -> None:
        assert 0 < digit < 11
        assert algorithm.lower() in ('sha1', 'sha256', 'sha512')

        self.digit = digit
        self.secret = secret
        self.algorithm = algorithm

    async def _generate(self, integer: int) -> str:
        int2byte = bytearray()
        secret = self.secret

        if integer < 0:
            raise ValueError('input must be positive integer')

        padding = len(secret) % 8
        if padding != 0:
            secret += '=' * (8 - padding)

        b_secret = base64.b32decode(secret, casefold=True)

        while integer != 0:
            int2byte.append(integer & 0xFF)
            integer >>= 8

        int2bytestring = bytes(bytearray(reversed(int2byte))).rjust(8, b'\0')

        algorithm = getattr(hashlib, self.algorithm)
        hash_hmac = bytearray(hmac.new(b_secret, int2bytestring, algorithm).digest())

        offset = hash_hmac[-1] & 0xF

        code = (
            (hash_hmac[offset] & 0x7F) << 24
            | (hash_hmac[offset + 1] & 0xFF) << 16
            | (hash_hmac[offset + 2] & 0xFF) << 8
            | (hash_hmac[offset + 3] & 0xFF)
        )

        s_code = str(10000000000 + (code % 10 ** self.digit))

        return s_code[-self.digit:]

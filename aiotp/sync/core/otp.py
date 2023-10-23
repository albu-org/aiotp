
import hmac
import struct
import base64

from ...typing import algorithms
from ...abstracts import AbstractSyncOTP


class OTP(AbstractSyncOTP):
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

    def _generate(self, integer: int) -> str:
        if integer < 0:
            raise ValueError('input must be positive integer')

        int2bytes = struct.pack('>q', integer)

        b_secret = base64.b32decode(self.secret + '=' * ((8 - len(self.secret)) % 8), casefold=True)
        
        hash_hmac = hmac.new(b_secret, int2bytes, self.algorithm).digest()

        offset = hash_hmac[-1] & 0xF

        code_bytes = hash_hmac[offset:offset + 4]
        code = str(struct.unpack('>l', code_bytes)[0] & 0X7FFFFFFF)

        return code[-self.digit:].zfill(self.digit)


import hmac
import datetime
import unicodedata
from typing import Optional
from urllib.parse import quote, urlencode, urlparse

from ..core import OTP
from ..utils import conversion
from ..typing import algorithms
from ..abstracts import AbstractTOTP


class TOTP(AbstractTOTP, OTP):
    def __init__(
        self,
        secret: str,
        digits: int = 5,
        interval: int = 60,
        algorithm: algorithms = 'sha1',
    ) -> None:
        self.interval = interval
        super().__init__(secret, digits, algorithm)

    async def __aenter__(self) -> 'TOTP':
        return self

    async def __aexit__(self, *args, **kwargs) -> None:
        ...

    async def create(self, dt: Optional[datetime.datetime] = None) -> str:
        if not dt:
            dt = datetime.datetime.now()

        return await self._generate(await conversion(dt, self.interval))

    async def verify(self, code: str, dt: Optional[datetime.datetime] = None) -> bool:
        if len(str(code)) < self.digit:
            return False

        if not dt:
            dt = datetime.datetime.now()

        s_code = unicodedata.normalize('NFKC', str(code))
        s_counter = unicodedata.normalize('NFKC', await self.create(dt))

        result = hmac.compare_digest(
            s_code.encode('utf-8'),
            s_counter.encode('utf-8')
        )

        return result

    async def uri(self, name: str, issuer: Optional[str] = None, image: Optional[str] = None) -> str:
        base_uri = 'otpauth://{0}/{1}?{2}'

        args: dict = {"secret": self.secret}

        label = quote(name)
        if issuer is not None:
            label = quote(issuer) + ':' + label
            args['issuer'] = issuer

        if self.algorithm and self.algorithm != 'sha1':
            args['algorithm'] = self.algorithm

        if self.digit and self.digit != 6:
            args['digits'] = self.digit

        if self.interval and self.interval != 30:
            args['period'] = self.interval

        if image:
            image_uri = urlparse(image)
            if image_uri.scheme != 'https' or not image_uri.netloc or not image_uri.path:
                raise ValueError("{} is not a valid url".format(image_uri))

            args['image'] = image

        uri = base_uri.format('totp', label, urlencode(args).replace("+", "%20"))
        return uri
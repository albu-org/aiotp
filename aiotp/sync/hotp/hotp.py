
import hmac
import unicodedata
from typing import Optional
from urllib.parse import quote, urlencode, urlparse

from ..core import OTP
from ...typing import algorithms
from ...abstracts import AbstractSyncHOTP


class HOTP(AbstractSyncHOTP, OTP):
    def __init__(
        self,
        secret: str,
        digits: int = 5,
        algorithm: algorithms = 'sha1',
        initial_count: int = 0
    ) -> None:
        self.count = initial_count
        super().__init__(secret, digits, algorithm)

    def __enter__(self) -> 'HOTP':
        return self

    def __exit__(self, *args, **kwargs) -> None:
        ...

    def create(self, count: int) -> str:
        """
        Generates the otp for the given count.

        Param:
            count -> int: the otp hmac counter

        Returns:
            otp-code -> str
        """
        return self._generate(self.count + count)

    def verify(self, code: str, counter: int) -> bool:
        """
        Verifies the otp passed in against the current counter otp

        Param:
            code -> str: the otp to check against
            counter -> int: the otp hmac counter

        Returns:
            True if verification succeeded, False otherwise
        """
        s_code = unicodedata.normalize('NFKC', str(code))
        s_counter = unicodedata.normalize('NFKC', self.create(counter))

        result = hmac.compare_digest(
            s_code.encode('utf-8'),
            s_counter.encode('utf-8')
        )

        return result

    def uri(self, name: str, issuer: Optional[str] = None, image: Optional[str] = None) -> str:
        """
        Returns the provisioning URI for the OTP.  This can then be
        encoded in a QR Code and used to provision an OTP app like
        Google Authenticator.

        See also:
            https://github.com/google/google-authenticator/wiki/Key-Uri-Format
        """

        base_uri = 'otpauth://{0}/{1}?{2}'

        args: dict = {"secret": self.secret}

        label = quote(name)
        if issuer is not None:
            label = quote(issuer) + ':' + label
            args['issuer'] = issuer

        args['counter'] = self.count
        if self.algorithm and self.algorithm != 'sha1':
            args['algorithm'] = self.algorithm

        if self.digit and self.digit != 6:
            args['digits'] = self.digit

        if image:
            image_uri = urlparse(image)
            if image_uri.scheme != 'https' or not image_uri.netloc or not image_uri.path:
                raise ValueError("{} is not a valid url".format(image_uri))

            args['image'] = image

        uri = base_uri.format('hotp', label, urlencode(args).replace("+", "%20"))
        return uri

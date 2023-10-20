
from typing import Optional
from datetime import datetime
from abc import ABC, abstractmethod

class AbstractSyncOTP(ABC):
    """AbstractOTP"""

    @abstractmethod
    def _generate(self, integer: int) -> str:
        """generate otp"""

class AbstractSyncHOTP(ABC):
    """AbstractBase"""

    @abstractmethod
    def create(self, count: int) -> str:
        """generate the HOTP code"""

    @abstractmethod
    def verify(self, code: str, counter: int) -> bool:
        """verify the HOTP code"""

    @abstractmethod
    def uri(self, name: str, issuer: str, image: str) -> str:
        """generate the uri"""

class AbstractSyncTOTP(ABC):
    """AbstractBase"""

    @abstractmethod
    def create(self, dt: datetime) -> str:
        """generate the TOTP code"""

    @abstractmethod
    def verify(self, code: str, dt: datetime) -> bool:
        """verify the TOTP code"""

    @abstractmethod
    def uri(self, name: str, issuer: str, image: str) -> str:
        """generate the uri"""


class AbstractOTP(ABC):
    """AbstractOTP"""

    @abstractmethod
    async def _generate(self, integer: int) -> str:
        """generate otp"""

class AbstractHOTP(ABC):
    """AbstractBase"""

    @abstractmethod
    async def create(self, count: int) -> str:
        """generate the HOTP code"""

    @abstractmethod
    async def verify(self, code: str, counter: int) -> bool:
        """verify the HOTP code"""

    @abstractmethod
    async def uri(self, name: str, issuer: Optional[str], image: Optional[str]) -> str:
        """generate the uri"""

class AbstractTOTP(ABC):
    """AbstractBase"""

    @abstractmethod
    async def create(self, dt: datetime) -> str:
        """generate the TOTP code"""

    @abstractmethod
    async def verify(self, code: str, dt: datetime) -> bool:
        """verify the TOTP code"""

    @abstractmethod
    async def uri(self, name: str, issuer: Optional[str], image: Optional[str]) -> str:
        """generate the uri"""

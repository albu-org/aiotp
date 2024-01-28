### aiotp - One-time password package in Python
---

- Installation

```
pip install aiotp
```
---

- Usage

#### Time-based OTPs

``` python
import asyncio

from aiotp import TOTP
from aiotp import random_b32
# from aiotp.sync import HOTP, TOTP, random_b32, random_hex

async def main():
    key = await random_b32()

    async with TOTP(key, digits=4, interval=5) as totp:
        code = await totp.create()

        result = await totp.verify(code)
        print(result) # -> True

        await asyncio.sleep(5)

        result = await totp.verify(code)
        print(result) # -> False

asyncio.run(main())
```

#### Counter-based OTPs

``` python
import asyncio

from aiotp import HOTP
from aiotp import random_b32
# from aiotp.sync import HOTP, TOTP, random_b32, random_hex

async def main():
    key = await random_b32()

    async with HOTP(key, digits=4) as hotp:
        code = await hotp.create(1000)

        result = await hotp.verify(code, 1000)
        print(result) # -> True

        result = await hotp.verify(code, 1001)
        print(result) # -> False

asyncio.run(main())
```
---

- Links

* [Package (PyPi)](https://pypi.python.org/pypi/aiotp)
* [RFC 6238: TOTP (algorithm)](https://tools.ietf.org/html/rfc6238)
* [RFC 4226: HOTP (algorithm)](https://tools.ietf.org/html/rfc4226)
---
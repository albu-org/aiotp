
import time
import secrets
import datetime
import calendar


async def conversion(date_time: datetime.datetime, interval: int) -> int:
    if date_time.tzinfo:
        return int(calendar.timegm(date_time.utctimetuple()) / interval)

    else:
        return int(time.mktime(date_time.timetuple()) / interval)

async def random_b32(length: int = 32, chars: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") -> str:
    if length < 32:
        raise ValueError("secrets should be at least 160 bits")

    return "".join(secrets.choice(chars) for _ in range(length))


async def random_hex(length: int = 40, chars: str = "ABCDEF0123456789") -> str:
    if length < 40:
        raise ValueError("secrets should be at least 160 bits")

    return await random_b32(length=length, chars=chars)

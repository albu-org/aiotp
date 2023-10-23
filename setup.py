
from setuptools import setup

with open('README.md', 'r') as readme:
    readme = readme.read()

setup(
    name="aiotp",
    version='1.0.1',
    description="One-time password package in Python",

    long_description=readme,
    long_description_content_type="text/markdown",

    url="https://github.com/albu-org/aiotp",

    author="albu", 
    author_email="albuorg@gmail.com",

    license="LGPLv3",

    keywords=['otp', 'totp', 'hotp', '2FA', 'aiotp', 'one-time'],

    python_requires="~=3.7",

    zip_safe=False, 
)
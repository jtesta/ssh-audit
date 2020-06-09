# -*- coding: utf-8 -*-


import re
from setuptools import setup


version = re.search(r'^VERSION\s*=\s*\'v(\d\.\d\.\d)\'', open('sshaudit/sshaudit.py').read(), re.M).group(1)
print("\n\nPackaging ssh-audit v%s...\n\n" % version)

with open("sshaudit/README.md", "rb") as f:
    long_descr = f.read().decode("utf-8")


setup(
    name = "ssh-audit",
    packages = ["sshaudit"],
    license = 'MIT',
    entry_points = {
        "console_scripts": ['ssh-audit = sshaudit.sshaudit:main']
    },
    version = version,
    description = "An SSH server & client configuration security auditing tool",
    long_description = long_descr,
    long_description_content_type = "text/markdown",
    author = "Joe Testa",
    author_email = "jtesta@positronsecurity.com",
    url = "https://github.com/jtesta/ssh-audit",
    classifiers = [
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Security",
        "Topic :: Security :: Cryptography"
    ])

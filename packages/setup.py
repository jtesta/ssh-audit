# -*- coding: utf-8 -*-


import re
import sys
from setuptools import setup

print_warning = False
m = re.search(r'^VERSION\s*=\s*\'v(\d\.\d\.\d)\'', open('sshaudit/sshaudit.py').read(), re.M)
if m is None:
    # If we failed to parse the stable version, see if this is the development version.
    m = re.search(r'^VERSION\s*=\s*\'v(\d\.\d\.\d-dev)\'', open('sshaudit/sshaudit.py').read(), re.M)
    if m is None:
        print("Error: could not parse VERSION variable from ssh-audit.py.")
        sys.exit(1)
    else:  # Continue with the development version, but print a warning later.
        print_warning = True

version = m.group(1)
print("\n\nPackaging ssh-audit v%s...\n\n" % version)

with open("sshaudit/README.md", "rb") as f:
    long_descr = f.read().decode("utf-8")


setup(
    name="ssh-audit",
    packages=["sshaudit"],
    license='MIT',
    entry_points={
        "console_scripts": ['ssh-audit = sshaudit.sshaudit:main']
    },
    version=version,
    description="An SSH server & client configuration security auditing tool",
    long_description=long_descr,
    long_description_content_type="text/markdown",
    author="Joe Testa",
    author_email="jtesta@positronsecurity.com",
    url="https://github.com/jtesta/ssh-audit",
    classifiers=[
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

if print_warning:
    print("\n\n    !!! WARNING: development version detected (%s).  Are you sure you want to package this version?  Probably not...\n" % version)

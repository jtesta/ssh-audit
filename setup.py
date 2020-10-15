import re
import sys
from setuptools import setup

print_warning = False
m = re.search(r'^VERSION\s*=\s*\'v(\d\.\d\.\d)\'', open('src/ssh_audit/globals.py').read(), re.M)
if m is None:
    # If we failed to parse the stable version, see if this is the development version.
    m = re.search(r'^VERSION\s*=\s*\'v(\d\.\d\.\d-dev)\'', open('src/ssh_audit/globals.py').read(), re.M)
    if m is None:
        print("Error: could not parse VERSION variable from ssh_audit.py.")
        sys.exit(1)
    else:  # Continue with the development version, but print a warning later.
        print_warning = True

version = m.group(1)
print("\n\nPackaging ssh-audit v%s...\n\n" % version)

# see setup.cfg
setup()

if print_warning:
    print("\n\n    !!! WARNING: development version detected (%s).  Are you sure you want to package this version?  Probably not...\n" % version)

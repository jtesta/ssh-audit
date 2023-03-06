"""
   The MIT License (MIT)

   Copyright (C) 2020-2023 Joe Testa (jtesta@positronsecurity.com)

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
"""
import sys

from typing import Dict, List, Tuple
from typing import Optional, Any, Union, cast
from datetime import date

from ssh_audit import exitcodes
from ssh_audit.ssh2_kex import SSH2_Kex  # pylint: disable=unused-import
from ssh_audit.banner import Banner  # pylint: disable=unused-import
from ssh_audit.globals import SNAP_PACKAGE, SNAP_PERMISSIONS_ERROR


# Validates policy files and performs policy testing
class Policy:

    # Each field maps directly to a private member variable of the Policy class.
    BUILTIN_POLICIES: Dict[str, Dict[str, Union[Optional[str], Optional[List[str]], bool, Dict[str, int]]]] = {

        # Ubuntu Server policies

        'Hardened Ubuntu Server 16.04 LTS (version 1)': {'version': '1', 'banner': None, 'compressions': None, 'host_keys': ['ssh-ed25519'], 'optional_host_keys': ['ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com'], 'kex': ['curve25519-sha256@libssh.org', 'diffie-hellman-group-exchange-sha256'], 'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'], 'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'], 'hostkey_sizes': None, 'cakey_sizes': None, 'dh_modulus_sizes': {'diffie-hellman-group-exchange-sha256': 2048}, 'server_policy': True},

        'Hardened Ubuntu Server 18.04 LTS (version 1)': {'version': '1', 'banner': None, 'compressions': None, 'host_keys': ['ssh-ed25519'], 'optional_host_keys': ['ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com'], 'kex': ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha256'], 'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'], 'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'], 'hostkey_sizes': None, 'cakey_sizes': None, 'dh_modulus_sizes': {'diffie-hellman-group-exchange-sha256': 2048}, 'server_policy': True},

        'Hardened Ubuntu Server 20.04 LTS (version 1)': {'version': '1', 'banner': None, 'compressions': None, 'host_keys': ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-ed25519'], 'optional_host_keys': ['sk-ssh-ed25519@openssh.com', 'ssh-ed25519-cert-v01@openssh.com', 'sk-ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com'], 'kex': ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha256'], 'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'], 'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'], 'hostkey_sizes': {'rsa-sha2-256': 4096, 'rsa-sha2-512': 4096}, 'cakey_sizes': {'rsa-sha2-256-cert-v01@openssh.com': 4096, 'rsa-sha2-512-cert-v01@openssh.com': 4096}, 'dh_modulus_sizes': {'diffie-hellman-group-exchange-sha256': 2048}, 'server_policy': True},

        'Hardened Ubuntu Server 22.04 LTS (version 1)': {'version': '1', 'banner': None, 'compressions': None, 'host_keys': ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-ed25519'], 'optional_host_keys': ['sk-ssh-ed25519@openssh.com', 'ssh-ed25519-cert-v01@openssh.com', 'sk-ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com'], 'kex': ['sntrup761x25519-sha512@openssh.com', 'curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha256'], 'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'], 'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'], 'hostkey_sizes': {'rsa-sha2-256': 4096, 'rsa-sha2-512': 4096}, 'cakey_sizes': {'rsa-sha2-256-cert-v01@openssh.com': 4096, 'rsa-sha2-512-cert-v01@openssh.com': 4096}, 'dh_modulus_sizes': {'diffie-hellman-group-exchange-sha256': 2048}, 'server_policy': True},


        # Generic OpenSSH Server policies

        'Hardened OpenSSH Server v7.7 (version 1)': {'version': '1', 'banner': None, 'compressions': None, 'host_keys': ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-ed25519'], 'optional_host_keys': ['ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com'], 'kex': ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha256'], 'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'], 'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'], 'hostkey_sizes': None, 'cakey_sizes': None, 'dh_modulus_sizes': {'diffie-hellman-group-exchange-sha256': 2048}, 'server_policy': True},

        'Hardened OpenSSH Server v7.8 (version 1)': {'version': '1', 'banner': None, 'compressions': None, 'host_keys': ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-ed25519'], 'optional_host_keys': ['ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com'], 'kex': ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha256'], 'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'], 'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'], 'hostkey_sizes': None, 'cakey_sizes': None, 'dh_modulus_sizes': {'diffie-hellman-group-exchange-sha256': 2048}, 'server_policy': True},

        'Hardened OpenSSH Server v7.9 (version 1)': {'version': '1', 'banner': None, 'compressions': None, 'host_keys': ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-ed25519'], 'optional_host_keys': ['ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com'], 'kex': ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha256'], 'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'], 'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'], 'hostkey_sizes': None, 'cakey_sizes': None, 'dh_modulus_sizes': {'diffie-hellman-group-exchange-sha256': 2048}, 'server_policy': True},

        'Hardened OpenSSH Server v8.0 (version 1)': {'version': '1', 'banner': None, 'compressions': None, 'host_keys': ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-ed25519'], 'optional_host_keys': ['ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com'], 'kex': ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha256'], 'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'], 'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'], 'hostkey_sizes': None, 'cakey_sizes': None, 'dh_modulus_sizes': {'diffie-hellman-group-exchange-sha256': 2048}, 'server_policy': True},

        'Hardened OpenSSH Server v8.1 (version 1)': {'version': '1', 'banner': None, 'compressions': None, 'host_keys': ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-ed25519'], 'optional_host_keys': ['sk-ssh-ed25519@openssh.com', 'ssh-ed25519-cert-v01@openssh.com', 'sk-ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com'], 'kex': ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha256'], 'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'], 'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'], 'hostkey_sizes': None, 'cakey_sizes': None, 'dh_modulus_sizes': {'diffie-hellman-group-exchange-sha256': 2048}, 'server_policy': True},

        'Hardened OpenSSH Server v8.2 (version 1)': {'version': '1', 'banner': None, 'compressions': None, 'host_keys': ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-ed25519'], 'optional_host_keys': ['sk-ssh-ed25519@openssh.com', 'ssh-ed25519-cert-v01@openssh.com', 'sk-ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com'], 'kex': ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha256'], 'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'], 'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'], 'hostkey_sizes': {'rsa-sha2-256': 4096, 'rsa-sha2-512': 4096}, 'cakey_sizes': {'rsa-sha2-256-cert-v01@openssh.com': 4096, 'rsa-sha2-512-cert-v01@openssh.com': 4096}, 'dh_modulus_sizes': {'diffie-hellman-group-exchange-sha256': 2048}, 'server_policy': True},

        'Hardened OpenSSH Server v8.3 (version 1)': {'version': '1', 'banner': None, 'compressions': None, 'host_keys': ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-ed25519'], 'optional_host_keys': ['sk-ssh-ed25519@openssh.com', 'ssh-ed25519-cert-v01@openssh.com', 'sk-ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com'], 'kex': ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha256'], 'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'], 'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'], 'hostkey_sizes': {'rsa-sha2-256': 4096, 'rsa-sha2-512': 4096}, 'cakey_sizes': {'rsa-sha2-256-cert-v01@openssh.com': 4096, 'rsa-sha2-512-cert-v01@openssh.com': 4096}, 'dh_modulus_sizes': {'diffie-hellman-group-exchange-sha256': 2048}, 'server_policy': True},

        'Hardened OpenSSH Server v8.4 (version 1)': {'version': '1', 'banner': None, 'compressions': None, 'host_keys': ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-ed25519'], 'optional_host_keys': ['sk-ssh-ed25519@openssh.com', 'ssh-ed25519-cert-v01@openssh.com', 'sk-ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com'], 'kex': ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha256'], 'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'], 'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'], 'hostkey_sizes': {'rsa-sha2-256': 4096, 'rsa-sha2-512': 4096}, 'cakey_sizes': {'rsa-sha2-256-cert-v01@openssh.com': 4096, 'rsa-sha2-512-cert-v01@openssh.com': 4096}, 'dh_modulus_sizes': {'diffie-hellman-group-exchange-sha256': 2048}, 'server_policy': True},

        'Hardened OpenSSH Server v8.5 (version 1)': {'version': '1', 'banner': None, 'compressions': None, 'host_keys': ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-ed25519'], 'optional_host_keys': ['sk-ssh-ed25519@openssh.com', 'ssh-ed25519-cert-v01@openssh.com', 'sk-ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com'], 'kex': ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha256'], 'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'], 'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'], 'hostkey_sizes': {'rsa-sha2-256': 4096, 'rsa-sha2-512': 4096}, 'cakey_sizes': {'rsa-sha2-256-cert-v01@openssh.com': 4096, 'rsa-sha2-512-cert-v01@openssh.com': 4096}, 'dh_modulus_sizes': {'diffie-hellman-group-exchange-sha256': 2048}, 'server_policy': True},

        'Hardened OpenSSH Server v8.6 (version 1)': {'version': '1', 'banner': None, 'compressions': None, 'host_keys': ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-ed25519'], 'optional_host_keys': ['sk-ssh-ed25519@openssh.com', 'ssh-ed25519-cert-v01@openssh.com', 'sk-ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com'], 'kex': ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha256'], 'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'], 'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'], 'hostkey_sizes': {'rsa-sha2-256': 4096, 'rsa-sha2-512': 4096}, 'cakey_sizes': {'rsa-sha2-256-cert-v01@openssh.com': 4096, 'rsa-sha2-512-cert-v01@openssh.com': 4096}, 'dh_modulus_sizes': {'diffie-hellman-group-exchange-sha256': 2048}, 'server_policy': True},

        'Hardened OpenSSH Server v8.7 (version 1)': {'version': '1', 'banner': None, 'compressions': None, 'host_keys': ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-ed25519'], 'optional_host_keys': ['sk-ssh-ed25519@openssh.com', 'ssh-ed25519-cert-v01@openssh.com', 'sk-ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com'], 'kex': ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha256'], 'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'], 'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'], 'hostkey_sizes': {'rsa-sha2-256': 4096, 'rsa-sha2-512': 4096}, 'cakey_sizes': {'rsa-sha2-256-cert-v01@openssh.com': 4096, 'rsa-sha2-512-cert-v01@openssh.com': 4096}, 'dh_modulus_sizes': {'diffie-hellman-group-exchange-sha256': 2048}, 'server_policy': True},


        # Ubuntu Client policies

        'Hardened Ubuntu Client 16.04 LTS (version 2)': {'version': '2', 'banner': None, 'compressions': None, 'host_keys': ['ssh-ed25519', 'ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256', 'rsa-sha2-512'], 'optional_host_keys': None, 'kex': ['curve25519-sha256@libssh.org', 'diffie-hellman-group-exchange-sha256', 'ext-info-c'], 'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'], 'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'], 'hostkey_sizes': None, 'cakey_sizes': None, 'dh_modulus_sizes': None, 'server_policy': False},

        'Hardened Ubuntu Client 18.04 LTS (version 2)': {'version': '2', 'banner': None, 'compressions': None, 'host_keys': ['ssh-ed25519', 'ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256', 'rsa-sha2-512'], 'optional_host_keys': None, 'kex': ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha256', 'ext-info-c'], 'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'], 'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'], 'hostkey_sizes': None, 'cakey_sizes': None, 'dh_modulus_sizes': None, 'server_policy': False},

        'Hardened Ubuntu Client 20.04 LTS (version 2)': {'version': '2', 'banner': None, 'compressions': None, 'host_keys': ['ssh-ed25519', 'ssh-ed25519-cert-v01@openssh.com', 'sk-ssh-ed25519@openssh.com', 'sk-ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512', 'rsa-sha2-512-cert-v01@openssh.com'], 'optional_host_keys': None, 'kex': ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha256', 'ext-info-c'], 'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'], 'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'], 'hostkey_sizes': None, 'cakey_sizes': None, 'dh_modulus_sizes': None, 'server_policy': False},

        'Hardened Ubuntu Client 22.04 LTS (version 1)': {'version': '1', 'banner': None, 'compressions': None, 'host_keys': ['ssh-ed25519', 'ssh-ed25519-cert-v01@openssh.com', 'sk-ssh-ed25519@openssh.com', 'sk-ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512', 'rsa-sha2-512-cert-v01@openssh.com'], 'optional_host_keys': None, 'kex': ['sntrup761x25519-sha512@openssh.com', 'curve25519-sha256', 'curve25519-sha256@libssh.org', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group-exchange-sha256', 'ext-info-c'], 'ciphers': ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'aes256-ctr', 'aes192-ctr', 'aes128-ctr'], 'macs': ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-128-etm@openssh.com'], 'hostkey_sizes': None, 'cakey_sizes': None, 'dh_modulus_sizes': None, 'server_policy': False},

    }


    def __init__(self, policy_file: Optional[str] = None, policy_data: Optional[str] = None, manual_load: bool = False) -> None:
        self._name: Optional[str] = None
        self._version: Optional[str] = None
        self._banner: Optional[str] = None
        self._compressions: Optional[List[str]] = None
        self._host_keys: Optional[List[str]] = None
        self._optional_host_keys: Optional[List[str]] = None
        self._kex: Optional[List[str]] = None
        self._ciphers: Optional[List[str]] = None
        self._macs: Optional[List[str]] = None
        self._hostkey_sizes: Optional[Dict[str, int]] = None
        self._cakey_sizes: Optional[Dict[str, int]] = None
        self._dh_modulus_sizes: Optional[Dict[str, int]] = None
        self._server_policy = True

        self._name_and_version: str = ''

        # Ensure that only one mode was specified.
        num_modes = 0
        if policy_file is not None:
            num_modes += 1
        if policy_data is not None:
            num_modes += 1
        if manual_load is True:
            num_modes += 1

        if num_modes != 1:
            raise RuntimeError('Exactly one of the following can be specified only: policy_file, policy_data, or manual_load')

        if manual_load:
            return

        if policy_file is not None:
            try:
                with open(policy_file, "r", encoding='utf-8') as f:
                    policy_data = f.read()
            except FileNotFoundError:
                print("Error: policy file not found: %s" % policy_file)
                sys.exit(exitcodes.UNKNOWN_ERROR)
            except PermissionError as e:
                # If installed as a Snap package, print a more useful message with potential work-arounds.
                if SNAP_PACKAGE:
                    print(SNAP_PERMISSIONS_ERROR)
                else:
                    print("Error: insufficient permissions: %s" % str(e))
                sys.exit(exitcodes.UNKNOWN_ERROR)

        lines = []
        if policy_data is not None:
            lines = policy_data.split("\n")

        for line in lines:
            line = line.strip()
            if (len(line) == 0) or line.startswith('#'):
                continue

            key = None
            val = None
            try:
                key, val = line.split('=')
            except ValueError as ve:
                raise ValueError("could not parse line: %s" % line) from ve

            key = key.strip()
            val = val.strip()

            if key not in ['name', 'version', 'banner', 'compressions', 'host keys', 'optional host keys', 'key exchanges', 'ciphers', 'macs', 'client policy'] and not key.startswith('hostkey_size_') and not key.startswith('cakey_size_') and not key.startswith('dh_modulus_size_'):
                raise ValueError("invalid field found in policy: %s" % line)

            if key in ['name', 'banner']:

                # If the banner value is blank, set it to "" so that the code below handles it.
                if len(val) < 2:
                    val = "\"\""

                if (val[0] != '"') or (val[-1] != '"'):
                    raise ValueError('the value for the %s field must be enclosed in quotes: %s' % (key, val))

                # Remove the surrounding quotes, and unescape quotes & newlines.
                val = val[1:-1]. replace("\\\"", "\"").replace("\\n", "\n")

                if key == 'name':
                    self._name = val
                elif key == 'banner':
                    self._banner = val
            elif key == 'version':
                self._version = val
            elif key in ['compressions', 'host keys', 'optional host keys', 'key exchanges', 'ciphers', 'macs']:
                try:
                    algs = val.split(',')
                except ValueError:
                    # If the value has no commas, then set the algorithm list to just the value.
                    algs = [val]

                # Strip whitespace in each algorithm name.
                algs = [alg.strip() for alg in algs]

                if key == 'compressions':
                    self._compressions = algs
                elif key == 'host keys':
                    self._host_keys = algs
                elif key == 'optional host keys':
                    self._optional_host_keys = algs
                elif key == 'key exchanges':
                    self._kex = algs
                elif key == 'ciphers':
                    self._ciphers = algs
                elif key == 'macs':
                    self._macs = algs
            elif key.startswith('hostkey_size_'):
                hostkey_type = key[13:]
                if self._hostkey_sizes is None:
                    self._hostkey_sizes = {}
                self._hostkey_sizes[hostkey_type] = int(val)
            elif key.startswith('cakey_size_'):
                cakey_type = key[11:]
                if self._cakey_sizes is None:
                    self._cakey_sizes = {}
                self._cakey_sizes[cakey_type] = int(val)
            elif key.startswith('dh_modulus_size_'):
                dh_modulus_type = key[16:]
                if self._dh_modulus_sizes is None:
                    self._dh_modulus_sizes = {}
                self._dh_modulus_sizes[dh_modulus_type] = int(val)
            elif key.startswith('client policy') and val.lower() == 'true':
                self._server_policy = False


        if self._name is None:
            raise ValueError('The policy does not have a name field.')
        if self._version is None:
            raise ValueError('The policy does not have a version field.')

        self._name_and_version = "%s (version %s)" % (self._name, self._version)


    @staticmethod
    def _append_error(errors: List[Any], mismatched_field: str, expected_required: Optional[List[str]], expected_optional: Optional[List[str]], actual: List[str]) -> None:
        if expected_required is None:
            expected_required = ['']
        if expected_optional is None:
            expected_optional = ['']
        errors.append({'mismatched_field': mismatched_field, 'expected_required': expected_required, 'expected_optional': expected_optional, 'actual': actual})


    @staticmethod
    def create(source: Optional[str], banner: Optional['Banner'], kex: Optional['SSH2_Kex'], client_audit: bool) -> str:
        '''Creates a policy based on a server configuration.  Returns a string.'''

        today = date.today().strftime('%Y/%m/%d')
        compressions = None
        host_keys = None
        kex_algs = None
        ciphers = None
        macs = None
        rsa_hostkey_sizes_str = ''
        rsa_cakey_sizes_str = ''
        dh_modulus_sizes_str = ''
        client_policy_str = ''

        if client_audit:
            client_policy_str = "\n# Set to true to signify this is a policy for clients, not servers.\nclient policy = true\n"

        if kex is not None:
            if kex.server.compression is not None:
                compressions = ', '.join(kex.server.compression)
            if kex.key_algorithms is not None:
                host_keys = ', '.join(kex.key_algorithms)
            if kex.kex_algorithms is not None:
                kex_algs = ', '.join(kex.kex_algorithms)
            if kex.server.encryption is not None:
                ciphers = ', '.join(kex.server.encryption)
            if kex.server.mac is not None:
                macs = ', '.join(kex.server.mac)
            if kex.rsa_key_sizes():
                rsa_key_sizes_dict = kex.rsa_key_sizes()
                for host_key_type in sorted(rsa_key_sizes_dict):
                    hostkey_size, cakey_size = rsa_key_sizes_dict[host_key_type]

                    rsa_hostkey_sizes_str = "%shostkey_size_%s = %d\n" % (rsa_hostkey_sizes_str, host_key_type, hostkey_size)
                    if cakey_size != -1:
                        rsa_cakey_sizes_str = "%scakey_size_%s = %d\n" % (rsa_cakey_sizes_str, host_key_type, cakey_size)

                if len(rsa_hostkey_sizes_str) > 0:
                    rsa_hostkey_sizes_str = "\n# RSA host key sizes.\n%s" % rsa_hostkey_sizes_str
                if len(rsa_cakey_sizes_str) > 0:
                    rsa_cakey_sizes_str = "\n# RSA CA key sizes.\n%s" % rsa_cakey_sizes_str
            if kex.dh_modulus_sizes():
                dh_modulus_sizes_dict = kex.dh_modulus_sizes()
                for gex_type in sorted(dh_modulus_sizes_dict):
                    modulus_size, _ = dh_modulus_sizes_dict[gex_type]
                    dh_modulus_sizes_str = "%sdh_modulus_size_%s = %d\n" % (dh_modulus_sizes_str, gex_type, modulus_size)
                if len(dh_modulus_sizes_str) > 0:
                    dh_modulus_sizes_str = "\n# Group exchange DH modulus sizes.\n%s" % dh_modulus_sizes_str


        policy_data = '''#
# Custom policy based on %s (created on %s)
#
%s
# The name of this policy (displayed in the output during scans).  Must be in quotes.
name = "Custom Policy (based on %s on %s)"

# The version of this policy (displayed in the output during scans).  Not parsed, and may be any value, including strings.
version = 1

# The banner that must match exactly.  Commented out to ignore banners, since minor variability in the banner is sometimes normal.
# banner = "%s"

# The compression options that must match exactly (order matters).  Commented out to ignore by default.
# compressions = %s
%s%s%s
# The host key types that must match exactly (order matters).
host keys = %s

# Host key types that may optionally appear.
#optional host keys = ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com

# The key exchange algorithms that must match exactly (order matters).
key exchanges = %s

# The ciphers that must match exactly (order matters).
ciphers = %s

# The MACs that must match exactly (order matters).
macs = %s
''' % (source, today, client_policy_str, source, today, banner, compressions, rsa_hostkey_sizes_str, rsa_cakey_sizes_str, dh_modulus_sizes_str, host_keys, kex_algs, ciphers, macs)

        return policy_data


    def evaluate(self, banner: Optional['Banner'], kex: Optional['SSH2_Kex']) -> Tuple[bool, List[Dict[str, str]], str]:
        '''Evaluates a server configuration against this policy.  Returns a tuple of a boolean (True if server adheres to policy) and an array of strings that holds error messages.'''

        ret = True
        errors: List[Any] = []

        banner_str = str(banner)
        if (self._banner is not None) and (banner_str != self._banner):
            ret = False
            self._append_error(errors, 'Banner', [self._banner], None, [banner_str])

        # All subsequent tests require a valid kex, so end here if we don't have one.
        if kex is None:
            return ret, errors, self._get_error_str(errors)

        if (self._compressions is not None) and (kex.server.compression != self._compressions):
            ret = False
            self._append_error(errors, 'Compression', self._compressions, None, kex.server.compression)

        # If a list of optional host keys was given in the policy, remove any of its entries from the list retrieved from the server.  This allows us to do an exact comparison with the expected list below.
        pruned_host_keys = kex.key_algorithms
        if self._optional_host_keys is not None:
            pruned_host_keys = [x for x in kex.key_algorithms if x not in self._optional_host_keys]

        if (self._host_keys is not None) and (pruned_host_keys != self._host_keys):
            ret = False
            self._append_error(errors, 'Host keys', self._host_keys, self._optional_host_keys, kex.key_algorithms)

        if self._hostkey_sizes is not None:
            hostkey_types = list(self._hostkey_sizes.keys())
            hostkey_types.sort()  # Sorted to make testing output repeatable.
            for hostkey_type in hostkey_types:
                expected_hostkey_size = self._hostkey_sizes[hostkey_type]
                if hostkey_type in kex.rsa_key_sizes():
                    actual_hostkey_size, actual_cakey_size = kex.rsa_key_sizes()[hostkey_type]
                    if actual_hostkey_size != expected_hostkey_size:
                        ret = False
                        self._append_error(errors, 'RSA host key (%s) sizes' % hostkey_type, [str(expected_hostkey_size)], None, [str(actual_hostkey_size)])

        if self._cakey_sizes is not None:
            hostkey_types = list(self._cakey_sizes.keys())
            hostkey_types.sort()  # Sorted to make testing output repeatable.
            for hostkey_type in hostkey_types:
                expected_cakey_size = self._cakey_sizes[hostkey_type]
                if hostkey_type in kex.rsa_key_sizes():
                    actual_hostkey_size, actual_cakey_size = kex.rsa_key_sizes()[hostkey_type]
                    if actual_cakey_size != expected_cakey_size:
                        ret = False
                        self._append_error(errors, 'RSA CA key (%s) sizes' % hostkey_type, [str(expected_cakey_size)], None, [str(actual_cakey_size)])

        if kex.kex_algorithms != self._kex:
            ret = False
            self._append_error(errors, 'Key exchanges', self._kex, None, kex.kex_algorithms)

        if (self._ciphers is not None) and (kex.server.encryption != self._ciphers):
            ret = False
            self._append_error(errors, 'Ciphers', self._ciphers, None, kex.server.encryption)

        if (self._macs is not None) and (kex.server.mac != self._macs):
            ret = False
            self._append_error(errors, 'MACs', self._macs, None, kex.server.mac)

        if self._dh_modulus_sizes is not None:
            dh_modulus_types = list(self._dh_modulus_sizes.keys())
            dh_modulus_types.sort()  # Sorted to make testing output repeatable.
            for dh_modulus_type in dh_modulus_types:
                expected_dh_modulus_size = self._dh_modulus_sizes[dh_modulus_type]
                if dh_modulus_type in kex.dh_modulus_sizes():
                    actual_dh_modulus_size, _ = kex.dh_modulus_sizes()[dh_modulus_type]
                    if expected_dh_modulus_size != actual_dh_modulus_size:
                        ret = False
                        self._append_error(errors, 'Group exchange (%s) modulus sizes' % dh_modulus_type, [str(expected_dh_modulus_size)], None, [str(actual_dh_modulus_size)])

        return ret, errors, self._get_error_str(errors)


    @staticmethod
    def _get_error_str(errors: List[Any]) -> str:
        '''Transforms an error struct to a flat string of error messages.'''

        error_list = []
        spacer = ''
        for e in errors:
            e_str = "  * %s did not match.\n" % e['mismatched_field']
            if ('expected_optional' in e) and (e['expected_optional'] != ['']):
                e_str += "    - Expected (required): %s\n    - Expected (optional): %s\n" % (Policy._normalize_error_field(e['expected_required']), Policy._normalize_error_field(e['expected_optional']))
                spacer = '              '
            else:
                e_str += "    - Expected: %s\n" % Policy._normalize_error_field(e['expected_required'])
                spacer = '   '
            e_str += "    - Actual:%s%s\n" % (spacer, Policy._normalize_error_field(e['actual']))
            error_list.append(e_str)

        error_list.sort()  # To ensure repeatable results for testing.

        error_str = ''
        if len(error_list) > 0:
            error_str = "\n".join(error_list)

        return error_str


    def get_name_and_version(self) -> str:
        '''Returns a string of this Policy's name and version.'''
        return self._name_and_version


    def is_server_policy(self) -> bool:
        '''Returns True if this is a server policy, or False if this is a client policy.'''
        return self._server_policy


    @staticmethod
    def list_builtin_policies() -> Tuple[List[str], List[str]]:
        '''Returns two lists: a list of names of built-in server policies, and a list of names of built-in client policies, respectively.'''
        server_policy_names = []
        client_policy_names = []

        for policy_name, policy in Policy.BUILTIN_POLICIES.items():
            if policy['server_policy']:
                server_policy_names.append(policy_name)
            else:
                client_policy_names.append(policy_name)

        server_policy_names.sort()
        client_policy_names.sort()
        return server_policy_names, client_policy_names


    @staticmethod
    def load_builtin_policy(policy_name: str) -> Optional['Policy']:
        '''Returns a Policy with the specified built-in policy name loaded, or None if no policy of that name exists.'''
        p = None
        if policy_name in Policy.BUILTIN_POLICIES:
            policy_struct = Policy.BUILTIN_POLICIES[policy_name]
            p = Policy(manual_load=True)
            policy_name_without_version = policy_name[0:policy_name.rfind(' (')]
            p._name = policy_name_without_version  # pylint: disable=protected-access
            p._version = cast(str, policy_struct['version'])  # pylint: disable=protected-access
            p._banner = cast(Optional[str], policy_struct['banner'])  # pylint: disable=protected-access
            p._compressions = cast(Optional[List[str]], policy_struct['compressions'])  # pylint: disable=protected-access
            p._host_keys = cast(Optional[List[str]], policy_struct['host_keys'])  # pylint: disable=protected-access
            p._optional_host_keys = cast(Optional[List[str]], policy_struct['optional_host_keys'])  # pylint: disable=protected-access
            p._kex = cast(Optional[List[str]], policy_struct['kex'])  # pylint: disable=protected-access
            p._ciphers = cast(Optional[List[str]], policy_struct['ciphers'])  # pylint: disable=protected-access
            p._macs = cast(Optional[List[str]], policy_struct['macs'])  # pylint: disable=protected-access
            p._hostkey_sizes = cast(Optional[Dict[str, int]], policy_struct['hostkey_sizes'])  # pylint: disable=protected-access
            p._cakey_sizes = cast(Optional[Dict[str, int]], policy_struct['cakey_sizes'])  # pylint: disable=protected-access
            p._dh_modulus_sizes = cast(Optional[Dict[str, int]], policy_struct['dh_modulus_sizes'])  # pylint: disable=protected-access
            p._server_policy = cast(bool, policy_struct['server_policy'])  # pylint: disable=protected-access

            p._name_and_version = "%s (version %s)" % (p._name, p._version)  # pylint: disable=protected-access

        return p


    @staticmethod
    def _normalize_error_field(field: List[str]) -> Any:
        '''If field is an array with a string parsable as an integer, return that integer.  Otherwise, return the field joined with commas.'''
        if len(field) == 1:
            try:
                return int(field[0])
            except ValueError:
                return field[0]
        else:
            return ', '.join(field)


    def __str__(self) -> str:
        undefined = '{undefined}'

        name = undefined
        version = undefined
        banner = undefined
        compressions_str = undefined
        host_keys_str = undefined
        optional_host_keys_str = undefined
        kex_str = undefined
        ciphers_str = undefined
        macs_str = undefined
        hostkey_sizes_str = undefined
        cakey_sizes_str = undefined
        dh_modulus_sizes_str = undefined


        if self._name is not None:
            name = '[%s]' % self._name
        if self._version is not None:
            version = '[%s]' % self._version
        if self._banner is not None:
            banner = '[%s]' % self._banner

        if self._compressions is not None:
            compressions_str = ', '.join(self._compressions)
        if self._host_keys is not None:
            host_keys_str = ', '.join(self._host_keys)
        if self._optional_host_keys is not None:
            optional_host_keys_str = ', '.join(self._optional_host_keys)
        if self._kex is not None:
            kex_str = ', '.join(self._kex)
        if self._ciphers is not None:
            ciphers_str = ', '.join(self._ciphers)
        if self._macs is not None:
            macs_str = ', '.join(self._macs)
        if self._hostkey_sizes is not None:
            hostkey_sizes_str = str(self._hostkey_sizes)
        if self._cakey_sizes is not None:
            cakey_sizes_str = str(self._cakey_sizes)
        if self._dh_modulus_sizes is not None:
            dh_modulus_sizes_str = str(self._dh_modulus_sizes)

        return "Name: %s\nVersion: %s\nBanner: %s\nCompressions: %s\nHost Keys: %s\nOptional Host Keys: %s\nKey Exchanges: %s\nCiphers: %s\nMACs: %s\nHost Key Sizes: %s\nCA Key Sizes: %s\nDH Modulus Sizes: %s\nServer Policy: %r" % (name, version, banner, compressions_str, host_keys_str, optional_host_keys_str, kex_str, ciphers_str, macs_str, hostkey_sizes_str, cakey_sizes_str, dh_modulus_sizes_str, self._server_policy)

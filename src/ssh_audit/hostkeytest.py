"""
   The MIT License (MIT)

   Copyright (C) 2017-2023 Joe Testa (jtesta@positronsecurity.com)

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

# pylint: disable=unused-import
from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401

import traceback

from ssh_audit.kexdh import KexDH, KexDHException, KexGroup1, KexGroup14_SHA1, KexGroup14_SHA256, KexCurve25519_SHA256, KexGroup16_SHA512, KexGroup18_SHA512, KexGroupExchange_SHA1, KexGroupExchange_SHA256, KexNISTP256, KexNISTP384, KexNISTP521
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexdb import SSH2_KexDB
from ssh_audit.ssh_socket import SSH_Socket
from ssh_audit.outputbuffer import OutputBuffer


# Obtains host keys, checks their size, and derives their fingerprints.
class HostKeyTest:
    # Tracks the RSA host key types.  As of this writing, testing one in this family yields valid results for the rest.
    RSA_FAMILY = ['ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512']

    # Dict holding the host key types we should extract & parse.  'cert' is True to denote that a host key type handles certificates (thus requires additional parsing).  'variable_key_len' is True for host key types that can have variable sizes (True only for RSA types, as the rest are of fixed-size).  After the host key type is fully parsed, the key 'parsed' is added with a value of True.
    HOST_KEY_TYPES = {
        'ssh-rsa':      {'cert': False, 'variable_key_len': True},
        'rsa-sha2-256': {'cert': False, 'variable_key_len': True},
        'rsa-sha2-512': {'cert': False, 'variable_key_len': True},

        'ssh-rsa-cert-v01@openssh.com':      {'cert': True, 'variable_key_len': True},
        'rsa-sha2-256-cert-v01@openssh.com': {'cert': True, 'variable_key_len': True},
        'rsa-sha2-512-cert-v01@openssh.com': {'cert': True, 'variable_key_len': True},

        'ssh-ed25519':                      {'cert': False, 'variable_key_len': False},
        'ssh-ed25519-cert-v01@openssh.com': {'cert': True, 'variable_key_len': False},
    }

    TWO2K_MODULUS_WARNING = '2048-bit modulus only provides 112-bits of symmetric strength'
    SMALL_ECC_MODULUS_WARNING = '224-bit ECC modulus only provides 112-bits of symmetric strength'


    @staticmethod
    def run(out: 'OutputBuffer', s: 'SSH_Socket', server_kex: 'SSH2_Kex') -> None:
        KEX_TO_DHGROUP = {
            'diffie-hellman-group1-sha1': KexGroup1,
            'diffie-hellman-group14-sha1': KexGroup14_SHA1,
            'diffie-hellman-group14-sha256': KexGroup14_SHA256,
            'curve25519-sha256': KexCurve25519_SHA256,
            'curve25519-sha256@libssh.org': KexCurve25519_SHA256,
            'diffie-hellman-group16-sha512': KexGroup16_SHA512,
            'diffie-hellman-group18-sha512': KexGroup18_SHA512,
            'diffie-hellman-group-exchange-sha1': KexGroupExchange_SHA1,
            'diffie-hellman-group-exchange-sha256': KexGroupExchange_SHA256,
            'ecdh-sha2-nistp256': KexNISTP256,
            'ecdh-sha2-nistp384': KexNISTP384,
            'ecdh-sha2-nistp521': KexNISTP521,
            # 'kexguess2@matt.ucc.asn.au': ???
        }

        # Pick the first kex algorithm that the server supports, which we
        # happen to support as well.
        kex_str = None
        kex_group = None
        for server_kex_alg in server_kex.kex_algorithms:
            if server_kex_alg in KEX_TO_DHGROUP:
                kex_str = server_kex_alg
                kex_group = KEX_TO_DHGROUP[kex_str](out)
                break

        if kex_str is not None and kex_group is not None:
            HostKeyTest.perform_test(out, s, server_kex, kex_str, kex_group, HostKeyTest.HOST_KEY_TYPES)

    @staticmethod
    def perform_test(out: 'OutputBuffer', s: 'SSH_Socket', server_kex: 'SSH2_Kex', kex_str: str, kex_group: 'KexDH', host_key_types: Dict[str, Dict[str, bool]]) -> None:
        hostkey_modulus_size = 0
        ca_modulus_size = 0

        # If the connection still exists, close it so we can test
        # using a clean slate (otherwise it may exist in a non-testable
        # state).
        if s.is_connected():
            s.close()

        # For each host key type...
        for host_key_type in host_key_types:
            key_fail_comments = []
            key_warn_comments = []

            # Skip those already handled (i.e.: those in the RSA family, as testing one tests them all).
            if 'parsed' in host_key_types[host_key_type] and host_key_types[host_key_type]['parsed']:
                continue

            # If this host key type is supported by the server, we test it.
            if host_key_type in server_kex.key_algorithms:
                out.d('Preparing to obtain ' + host_key_type + ' host key...', write_now=True)

                cert = host_key_types[host_key_type]['cert']

                # If the connection is closed, re-open it and get the kex again.
                if not s.is_connected():
                    err = s.connect()
                    if err is not None:
                        out.v(err, write_now=True)
                        return

                    _, _, err = s.get_banner()
                    if err is not None:
                        out.v(err, write_now=True)
                        s.close()
                        return

                    # Send our KEX using the specified group-exchange and most of the server's own values.
                    s.send_kexinit(key_exchanges=[kex_str], hostkeys=[host_key_type], ciphers=server_kex.server.encryption, macs=server_kex.server.mac, compressions=server_kex.server.compression, languages=server_kex.server.languages)

                    try:
                        # Parse the server's KEX.
                        _, payload = s.read_packet()
                        SSH2_Kex.parse(out, payload)
                    except Exception:
                        out.v("Failed to parse server's kex.  Stack trace:\n%s" % str(traceback.format_exc()), write_now=True)
                        return

                # Do the initial DH exchange.  The server responds back
                # with the host key and its length.  Bingo.  We also get back the host key fingerprint.
                kex_group.send_init(s)
                raw_hostkey_bytes = b''
                try:
                    kex_reply = kex_group.recv_reply(s)
                    raw_hostkey_bytes = kex_reply if kex_reply is not None else b''
                except KexDHException:
                    out.v("Failed to parse server's host key.  Stack trace:\n%s" % str(traceback.format_exc()), write_now=True)

                    # Since parsing this host key failed, there's nothing more to do but close the socket and move on to the next host key type.
                    s.close()
                    continue

                hostkey_modulus_size = kex_group.get_hostkey_size()
                ca_key_type = kex_group.get_ca_type()
                ca_modulus_size = kex_group.get_ca_size()
                out.d("Hostkey type: [%s]; hostkey size: %u; CA type: [%s]; CA modulus size: %u" % (host_key_type, hostkey_modulus_size, ca_key_type, ca_modulus_size), write_now=True)

                # Record all the host key info.
                server_kex.set_host_key(host_key_type, raw_hostkey_bytes, hostkey_modulus_size, ca_key_type, ca_modulus_size)

                # Set the hostkey size for all RSA key types since 'ssh-rsa', 'rsa-sha2-256', etc. are all using the same host key.  Note, however, that this may change in the future.
                if cert is False and host_key_type in HostKeyTest.RSA_FAMILY:
                    for rsa_type in HostKeyTest.RSA_FAMILY:
                        server_kex.set_host_key(rsa_type, raw_hostkey_bytes, hostkey_modulus_size, ca_key_type, ca_modulus_size)

                # Close the socket, as the connection has
                # been put in a state that later tests can't use.
                s.close()

                # If the host key modulus or CA modulus was successfully parsed, check to see that its a safe size.
                if hostkey_modulus_size > 0 or ca_modulus_size > 0:
                    # The minimum good modulus size for RSA host keys is 3072.  However, since ECC cryptosystems are fundamentally different, the minimum good is 256.
                    hostkey_min_good = cakey_min_good = 3072
                    hostkey_min_warn = cakey_min_warn = 2048
                    hostkey_warn_str = cakey_warn_str = HostKeyTest.TWO2K_MODULUS_WARNING
                    if host_key_type.startswith('ssh-ed25519') or host_key_type.startswith('ecdsa-sha2-nistp'):
                        hostkey_min_good = 256
                        hostkey_min_warn = 224
                        hostkey_warn_str = HostKeyTest.SMALL_ECC_MODULUS_WARNING
                    if ca_key_type.startswith('ssh-ed25519') or ca_key_type.startswith('ecdsa-sha2-nistp'):
                        cakey_min_good = 256
                        cakey_min_warn = 224
                        cakey_warn_str = HostKeyTest.SMALL_ECC_MODULUS_WARNING

                    # Keys smaller than 2048 result in a failure.  Keys smaller 3072 result in a warning.  Update the database accordingly.
                    if (cert is False) and (hostkey_modulus_size < hostkey_min_good):

                        # If the key is under 2048, add to the failure list.
                        if hostkey_modulus_size < hostkey_min_warn:
                            key_fail_comments.append('using small %d-bit modulus' % hostkey_modulus_size)
                        elif hostkey_warn_str not in key_warn_comments:  # Issue a warning about 2048-bit moduli.
                            key_warn_comments.append(hostkey_warn_str)

                    elif (cert is True) and ((hostkey_modulus_size < hostkey_min_good) or (0 < ca_modulus_size < cakey_min_good)):
                        # If the host key is smaller than 2048-bit/224-bit, flag this as a failure.
                        if hostkey_modulus_size < hostkey_min_warn:
                            key_fail_comments.append('using small %d-bit hostkey modulus' % hostkey_modulus_size)
                        # Otherwise, this is just a warning.
                        elif (hostkey_modulus_size < hostkey_min_good) and (hostkey_warn_str not in key_warn_comments):
                            key_warn_comments.append(hostkey_warn_str)

                        # If the CA key is smaller than 2048-bit/224-bit, flag this as a failure.
                        if 0 < ca_modulus_size < cakey_min_warn:
                            key_fail_comments.append('using small %d-bit CA key modulus' % ca_modulus_size)
                        # Otherwise, this is just a warning.
                        elif (0 < ca_modulus_size < cakey_min_good) and (cakey_warn_str not in key_warn_comments):
                            key_warn_comments.append(cakey_warn_str)

                    # If the CA key type uses ECDSA with a NIST P-curve, fail it for possibly being back-doored.
                    if ca_key_type.startswith('ecdsa-sha2-nistp'):
                        key_fail_comments.append('CA key uses elliptic curves that are suspected as being backdoored by the U.S. National Security Agency')

                # If this host key type is in the RSA family, then mark them all as parsed (since results in one are valid for them all).
                if host_key_type in HostKeyTest.RSA_FAMILY:
                    for rsa_type in HostKeyTest.RSA_FAMILY:
                        host_key_types[rsa_type]['parsed'] = True

                        # If the current key is a member of the RSA family, then populate all RSA family members with the same
                        # failure and/or warning comments.
                        db = SSH2_KexDB.get_db()
                        while len(db['key'][rsa_type]) < 3:
                            db['key'][rsa_type].append([])

                        db['key'][rsa_type][1].extend(key_fail_comments)
                        db['key'][rsa_type][2].extend(key_warn_comments)

                else:
                    host_key_types[host_key_type]['parsed'] = True
                    db = SSH2_KexDB.get_db()
                    while len(db['key'][host_key_type]) < 3:
                        db['key'][host_key_type].append([])

                    db['key'][host_key_type][1].extend(key_fail_comments)
                    db['key'][host_key_type][2].extend(key_warn_comments)

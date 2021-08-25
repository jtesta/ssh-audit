"""
   The MIT License (MIT)

   Copyright (C) 2017-2021 Joe Testa (jtesta@positronsecurity.com)

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

from ssh_audit.kexdh import KexGroupExchange_SHA1, KexGroupExchange_SHA256
from ssh_audit.ssh2_kexdb import SSH2_KexDB
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh_socket import SSH_Socket
from ssh_audit.outputbuffer import OutputBuffer


# Performs DH group exchanges to find what moduli are supported, and checks
# their size.
class GEXTest:

    # Creates a new connection to the server.  Returns True on success, or False.
    @staticmethod
    def reconnect(out: 'OutputBuffer', s: 'SSH_Socket', kex: 'SSH2_Kex', gex_alg: str) -> bool:
        if s.is_connected():
            return True

        err = s.connect()
        if err is not None:
            out.v(err, write_now=True)
            return False

        _, _, err = s.get_banner()
        if err is not None:
            out.v(err, write_now=True)
            s.close()
            return False

        # Send our KEX using the specified group-exchange and most of the
        # server's own values.
        s.send_kexinit(key_exchanges=[gex_alg], hostkeys=kex.key_algorithms, ciphers=kex.server.encryption, macs=kex.server.mac, compressions=kex.server.compression, languages=kex.server.languages)

        try:
            # Parse the server's KEX.
            _, payload = s.read_packet(2)
            SSH2_Kex.parse(payload)
        except Exception:
            out.v("Failed to parse server's kex.  Stack trace:\n%s" % str(traceback.format_exc()), write_now=True)
            return False

        return True

    # Runs the DH moduli test against the specified target.
    @staticmethod
    def run(out: 'OutputBuffer', s: 'SSH_Socket', kex: 'SSH2_Kex') -> None:
        GEX_ALGS = {
            'diffie-hellman-group-exchange-sha1': KexGroupExchange_SHA1,
            'diffie-hellman-group-exchange-sha256': KexGroupExchange_SHA256,
        }

        # The previous RSA tests put the server in a state we can't
        # test.  So we need a new connection to start with a clean
        # slate.
        if s.is_connected():
            s.close()

        # Check if the server supports any of the group-exchange
        # algorithms.  If so, test each one.
        for gex_alg, kex_group_class in GEX_ALGS.items():
            if gex_alg in kex.kex_algorithms:
                out.d('Preparing to perform DH group exchange using ' + gex_alg + '...', write_now=True)

                if GEXTest.reconnect(out, s, kex, gex_alg) is False:
                    break

                kex_group = kex_group_class()
                smallest_modulus = -1

                # First try a range of weak sizes.
                try:
                    kex_group.send_init_gex(s, 512, 1024, 1536)
                    kex_group.recv_reply(s, False)

                    # Its been observed that servers will return a group
                    # larger than the requested max.  So just because we
                    # got here, doesn't mean the server is vulnerable...
                    smallest_modulus = kex_group.get_dh_modulus_size()

                except Exception:
                    pass
                finally:
                    s.close()

                # Try an array of specific modulus sizes... one at a time.
                reconnect_failed = False
                for bits in [512, 768, 1024, 1536, 2048, 3072, 4096]:

                    # If we found one modulus size already, but we're about
                    # to test a larger one, don't bother.
                    if bits >= smallest_modulus > 0:
                        break

                    out.d('Preparing to perform DH group exchange using ' + gex_alg + ' with modulus size ' + str(bits) + '...', write_now=True)

                    if GEXTest.reconnect(out, s, kex, gex_alg) is False:
                        reconnect_failed = True
                        break

                    try:
                        kex_group.send_init_gex(s, bits, bits, bits)
                        kex_group.recv_reply(s, False)
                        smallest_modulus = kex_group.get_dh_modulus_size()
                    except Exception:
                        # import traceback
                        # print(traceback.format_exc())
                        pass
                    finally:
                        # The server is in a state that is not re-testable,
                        # so there's nothing else to do with this open
                        # connection.
                        s.close()

                if smallest_modulus > 0:
                    kex.set_dh_modulus_size(gex_alg, smallest_modulus)

                    # We flag moduli smaller than 2048 as a failure.
                    if smallest_modulus < 2048:
                        text = 'using small %d-bit modulus' % smallest_modulus
                        lst = SSH2_KexDB.ALGORITHMS['kex'][gex_alg]
                        # For 'diffie-hellman-group-exchange-sha256', add
                        # a failure reason.
                        if len(lst) == 1:
                            lst.append([text])
                        # For 'diffie-hellman-group-exchange-sha1', delete
                        # the existing failure reason (which is vague), and
                        # insert our own.
                        else:
                            del lst[1]
                            lst.insert(1, [text])

                if reconnect_failed:
                    break

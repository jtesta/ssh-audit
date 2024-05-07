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
import struct
import traceback

# pylint: disable=unused-import
from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401

from ssh_audit.banner import Banner
from ssh_audit.kexdh import KexDHException, KexGroupExchange, KexGroupExchange_SHA1, KexGroupExchange_SHA256
from ssh_audit.ssh2_kexdb import SSH2_KexDB
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh_socket import SSH_Socket
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit import exitcodes


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
            SSH2_Kex.parse(out, payload)
        except (KexDHException, struct.error):
            out.v("Failed to parse server's kex.  Stack trace:\n%s" % str(traceback.format_exc()), write_now=True)
            return False

        return True

    @staticmethod
    def granular_modulus_size_test(out: 'OutputBuffer', s: 'SSH_Socket', kex: 'SSH2_Kex', bits_min: int, bits_pref: int, bits_max: int, modulus_dict: Dict[str, List[int]]) -> int:
        '''
        Tests for granular modulus sizes.
        Builds a dictionary, where a key represents a DH algorithm name and the
        values are the modulus sizes (in bits) that have been returned by the
        target server.
        Returns an exitcodes.* flag.
        '''

        retval = exitcodes.GOOD

        out.d("Starting modulus_size_test...")
        out.d("Bits Min:  " + str(bits_min))
        out.d("Bits Pref: " + str(bits_pref))
        out.d("Bits Max:  " + str(bits_max))

        GEX_ALGS = {
            'diffie-hellman-group-exchange-sha1': KexGroupExchange_SHA1,
            'diffie-hellman-group-exchange-sha256': KexGroupExchange_SHA256,
        }

        # Check if the server supports any of the group-exchange
        # algorithms.  If so, test each one.
        for gex_alg, kex_group_class in GEX_ALGS.items():
            if gex_alg not in kex.kex_algorithms:
                out.d('Server does not support the algorithm "' + gex_alg + '".', write_now=True)
            else:
                kex_group = kex_group_class(out)
                out.d('Preparing to perform DH group exchange using ' + gex_alg + ' with min, pref and max modulus sizes of ' + str(bits_min) + ' bits, ' + str(bits_pref) + ' bits and ' + str(bits_max) + ' bits...', write_now=True)

                # It has been observed that reconnecting to some SSH servers
                # multiple times in quick succession can eventually result
                # in a "connection reset by peer" error. It may be possible
                # to recover from such an error by sleeping for some time
                # before continuing to issue reconnects.
                modulus_size_returned, reconnect_failed = GEXTest._send_init(out, s, kex_group, kex, gex_alg, bits_min, bits_pref, bits_max)
                if reconnect_failed:
                    out.fail('Reconnect failed.')
                    return exitcodes.FAILURE

                if modulus_size_returned > 0:
                    if gex_alg in modulus_dict:
                        if modulus_size_returned not in modulus_dict[gex_alg]:
                            modulus_dict[gex_alg].append(modulus_size_returned)
                    else:
                        modulus_dict[gex_alg] = [modulus_size_returned]

        return retval

    # Runs the DH moduli test against the specified target.
    @staticmethod
    def run(out: 'OutputBuffer', s: 'SSH_Socket', banner: Optional['Banner'], kex: 'SSH2_Kex') -> None:
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
        for gex_alg, kex_group_class in GEX_ALGS.items():  # pylint: disable=too-many-nested-blocks
            if gex_alg in kex.kex_algorithms:
                out.d('Preparing to perform DH group exchange using ' + gex_alg + ' with min, pref and max modulus sizes of 512 bits, 1024 bits and 1536 bits...', write_now=True)

                kex_group = kex_group_class(out)
                smallest_modulus, reconnect_failed = GEXTest._send_init(out, s, kex_group, kex, gex_alg, 512, 1024, 1536)
                if reconnect_failed:
                    break

                # Try an array of specific modulus sizes... one at a time.
                reconnect_failed = False
                for bits in [512, 768, 1024, 1536, 2048, 3072, 4096]:

                    # If we found one modulus size already, but we're about
                    # to test a larger one, don't bother.
                    if bits >= smallest_modulus > 0:
                        break

                    smallest_modulus, reconnect_failed = GEXTest._send_init(out, s, kex_group, kex, gex_alg, bits, bits, bits)

                # If the smallest modulus is 2048 and the server is OpenSSH, then we may have triggered the fallback mechanism, which tends to happen in testing scenarios such as this but not in most real-world conditions (see X).  To better test this condition, we will do an additional check to see if the server supports sizes between 2048 and 4096, and consider this the definitive result.
                openssh_test_updated = False
                if (smallest_modulus == 2048) and (banner is not None) and (banner.software is not None) and (banner.software.find('OpenSSH') != -1):
                    out.d('First pass found a minimum GEX modulus of 2048 against OpenSSH server.  Performing a second pass to get a more accurate result...')
                    smallest_modulus, _ = GEXTest._send_init(out, s, kex_group, kex, gex_alg, 2048, 3072, 4096)
                    out.d('Modulus size returned by server during second pass: %d bits' % smallest_modulus, write_now=True)
                    openssh_test_updated = bool((smallest_modulus > 0) and (smallest_modulus != 2048))

                if smallest_modulus > 0:
                    kex.set_dh_modulus_size(gex_alg, smallest_modulus)

                    lst = SSH2_KexDB.get_db()['kex'][gex_alg]

                    # We flag moduli smaller than 2048 as a failure.
                    if smallest_modulus < 2048:
                        text = 'using small %d-bit modulus' % smallest_modulus

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

                    # Moduli smaller than 3072 get flagged as a warning.
                    elif smallest_modulus < 3072:

                        # Ensure that a warning list exists for us to append to, below.
                        while len(lst) < 3:
                            lst.append([])

                        # Ensure this is only added once.
                        text = '2048-bit modulus only provides 112-bits of symmetric strength'
                        if text not in lst[2]:
                            lst[2].append(text)

                    # If we retested against OpenSSH (because its fallback mechanism was triggered), add a special note for the user.
                    if openssh_test_updated:
                        text = "OpenSSH's GEX fallback mechanism was triggered during testing. Very old SSH clients will still be able to create connections using a 2048-bit modulus, though modern clients will use %u. This can only be disabled by recompiling the code (see https://github.com/openssh/openssh-portable/blob/V_9_4/dh.c#L477)." % smallest_modulus

                        # Ensure that an info list exists for us to append to, below.
                        while len(lst) < 4:
                            lst.append([])

                        # Ensure this is only added once.
                        if text not in lst[3]:
                            lst[3].append(text)

                if reconnect_failed:
                    break

    @staticmethod
    def _send_init(out: 'OutputBuffer', s: 'SSH_Socket', kex_group: 'KexGroupExchange', kex: 'SSH2_Kex', gex_alg: str, min_bits: int, pref_bits: int, max_bits: int) -> Tuple[int, bool]:
        '''Internal function for sending the GEX initialization to the server with the minimum, preferred, and maximum modulus bits.  Returns a Tuple of the modulus size received from the server (or -1 on error) and boolean signifying that the connection to the server failed.'''

        smallest_modulus = -1
        reconnect_failed = False
        try:
            if GEXTest.reconnect(out, s, kex, gex_alg) is False:
                reconnect_failed = True
                out.d('GEXTest._send_init(%s, %u, %u, %u): reconnection failed.' % (gex_alg, min_bits, pref_bits, max_bits), write_now=True)
            else:
                kex_group.send_init_gex(s, min_bits, pref_bits, max_bits)
                kex_group.recv_reply(s, False)
                smallest_modulus = kex_group.get_dh_modulus_size()
                out.d('GEXTest._send_init(%s, %u, %u, %u): received modulus size: %d' % (gex_alg, min_bits, pref_bits, max_bits, smallest_modulus), write_now=True)
        except KexDHException as e:
            out.d('GEXTest._send_init(%s, %u, %u, %u): exception when performing DH group exchange init: %s' % (gex_alg, min_bits, pref_bits, max_bits, str(e)), write_now=True)
        finally:
            s.close()

        return smallest_modulus, reconnect_failed

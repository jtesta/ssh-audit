"""
   The MIT License (MIT)

   Copyright (C) 2017-2025 Joe Testa (jtesta@positronsecurity.com)

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
import json
import struct
from typing import Dict

from ssh_audit import exitcodes
from ssh_audit.auditconf import AuditConf
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.protocol import Protocol
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh_socket import SSH_Socket


class ClientGEXTest:
    ALGORITHMS = ['diffie-hellman-group-exchange-sha256', 'diffie-hellman-group-exchange-sha1']

    @staticmethod
    def parse_request(payload: bytes) -> Dict[str, int]:
        if len(payload) != 12:
            raise ValueError('expected exactly three uint32 group sizes')
        minimum, preferred, maximum = struct.unpack('>III', payload)
        if not 0 < minimum <= preferred <= maximum:
            raise ValueError('group sizes must satisfy 0 < minimum <= preferred <= maximum')
        return {'minimum': minimum, 'preferred': preferred, 'maximum': maximum}

    @staticmethod
    def run(out: OutputBuffer, sock: SSH_Socket, kex: SSH2_Kex, conf: AuditConf) -> int:
        cipher = 'aes%d-ctr' % conf.client_gex_test
        algorithm = next((name for name in kex.kex_algorithms if name in ClientGEXTest.ALGORITHMS), None)
        hostkey = next((name for name in kex.key_algorithms if name in SSH_Socket.DEFAULT_HOST_KEYS), None)
        try:
            if algorithm is None or hostkey is None or cipher not in kex.client.encryption or cipher not in kex.server.encryption:
                raise ValueError('client does not offer the required GEX, host-key, or cipher algorithm')
            # RFC4253 section7: discard exactly one incorrect optimistic KEX guess.
            if kex.follows and (kex.kex_algorithms[0] != algorithm or kex.key_algorithms[0] != hostkey):
                guessed_type, _ = sock.read_packet()
                if guessed_type < 0:
                    raise ValueError('connection ended while discarding an incorrect KEX guess')
            packet_type, payload = sock.read_packet()
            if packet_type != Protocol.MSG_KEXDH_GEX_REQUEST:
                raise ValueError('expected SSH_MSG_KEX_DH_GEX_REQUEST (34), received %d' % packet_type)
            sizes = ClientGEXTest.parse_request(payload)
            if conf.json:
                result = {'client-gex-request': dict(sizes, cipher=cipher, kex=algorithm)}
                out.info(json.dumps(result, indent=4 if conf.json_print_indent else None, sort_keys=True))
            else:
                out.head('# client diffie-hellman group exchange request')
                out.info('%s / %s: minimum=%d, preferred=%d, maximum=%d bits' %
                         (algorithm, cipher, sizes['minimum'], sizes['preferred'], sizes['maximum']))
            return exitcodes.GOOD
        except ValueError as error:
            out.fail('Client GEX test failed: %s' % error)
            return exitcodes.CONNECTION_ERROR
        finally:
            sock.close()

"""
   The MIT License (MIT)

   Copyright (C) 2017-2021 Joe Testa (jtesta@positronsecurity.com)
   Copyright (C) 2017 Andris Raugulis (moo@arthepsy.eu)

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
import errno
import os
import select
import socket
import struct
import sys

# pylint: disable=unused-import
from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401

from ssh_audit import exitcodes
from ssh_audit.banner import Banner
from ssh_audit.globals import SSH_HEADER
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.protocol import Protocol
from ssh_audit.readbuf import ReadBuf
from ssh_audit.ssh1 import SSH1
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexparty import SSH2_KexParty
from ssh_audit.utils import Utils
from ssh_audit.writebuf import WriteBuf


class SSH_Socket(ReadBuf, WriteBuf):
    class InsufficientReadException(Exception):
        pass

    SM_BANNER_SENT = 1

    def __init__(self, outputbuffer: 'OutputBuffer', host: Optional[str], port: int, ip_version_preference: List[int] = [], timeout: Union[int, float] = 5, timeout_set: bool = False) -> None:  # pylint: disable=dangerous-default-value
        super(SSH_Socket, self).__init__()
        self.__outputbuffer = outputbuffer
        self.__sock: Optional[socket.socket] = None
        self.__sock_map: Dict[int, socket.socket] = {}
        self.__block_size = 8
        self.__state = 0
        self.__header: List[str] = []
        self.__banner: Optional[Banner] = None
        if host is None:
            raise ValueError('undefined host')
        nport = Utils.parse_int(port)
        if nport < 1 or nport > 65535:
            raise ValueError('invalid port: {}'.format(port))
        self.__host = host
        self.__port = nport
        self.__ip_version_preference = ip_version_preference  # Holds only 5 possible values: [] (no preference), [4] (use IPv4 only), [6] (use IPv6 only), [46] (use both IPv4 and IPv6, but prioritize v4), and [64] (use both IPv4 and IPv6, but prioritize v6).
        self.__timeout = timeout
        self.__timeout_set = timeout_set
        self.client_host: Optional[str] = None
        self.client_port = None

    def _resolve(self) -> Iterable[Tuple[int, Tuple[Any, ...]]]:
        # If __ip_version_preference has only one entry, then it means that ONLY that IP version should be used.
        if len(self.__ip_version_preference) == 1:
            family = socket.AF_INET if self.__ip_version_preference[0] == 4 else socket.AF_INET6
        else:
            family = socket.AF_UNSPEC
        try:
            stype = socket.SOCK_STREAM
            r = socket.getaddrinfo(self.__host, self.__port, family, stype)

            # If the user has a preference for using IPv4 over IPv6 (or vice-versa), then sort the list returned by getaddrinfo() so that the preferred address type comes first.
            if len(self.__ip_version_preference) == 2:
                r = sorted(r, key=lambda x: x[0], reverse=(self.__ip_version_preference[0] == 6))  # pylint: disable=superfluous-parens
            for af, socktype, _proto, _canonname, addr in r:
                if socktype == socket.SOCK_STREAM:
                    yield af, addr
        except socket.error as e:
            self.__outputbuffer.fail('[exception] {}'.format(e)).write()
            sys.exit(exitcodes.CONNECTION_ERROR)

    # Listens on a server socket and accepts one connection (used for
    # auditing client connections).
    def listen_and_accept(self) -> None:

        try:
            # Socket to listen on all IPv4 addresses.
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', self.__port))
            s.listen()
            self.__sock_map[s.fileno()] = s
        except Exception:
            print("Warning: failed to listen on any IPv4 interfaces.")

        try:
            # Socket to listen on all IPv6 addresses.
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s.bind(('::', self.__port))
            s.listen()
            self.__sock_map[s.fileno()] = s
        except Exception:
            print("Warning: failed to listen on any IPv6 interfaces.")

        # If we failed to listen on any interfaces, terminate.
        if len(self.__sock_map.keys()) == 0:
            print("Error: failed to listen on any IPv4 and IPv6 interfaces!")
            sys.exit(exitcodes.CONNECTION_ERROR)

        # Wait for an incoming connection.  If a timeout was explicitly
        # set by the user, terminate when it elapses.
        fds = None
        time_elapsed = 0.0
        interval = 1.0
        while True:
            # Wait for a connection on either socket.
            fds = select.select(self.__sock_map.keys(), [], [], interval)
            time_elapsed += interval

            # We have incoming data on at least one of the sockets.
            if len(fds[0]) > 0:
                break

            if self.__timeout_set and time_elapsed >= self.__timeout:
                print("Timeout elapsed.  Terminating...")
                sys.exit(exitcodes.CONNECTION_ERROR)

        # Accept the connection.
        c, addr = self.__sock_map[fds[0][0]].accept()
        self.client_host = addr[0]
        self.client_port = addr[1]
        c.settimeout(self.__timeout)
        self.__sock = c

    def connect(self) -> Optional[str]:
        '''Returns None on success, or an error string.'''
        err = None
        for af, addr in self._resolve():
            s = None
            try:
                s = socket.socket(af, socket.SOCK_STREAM)
                s.settimeout(self.__timeout)
                self.__outputbuffer.d(("Connecting to %s:%d..." % ('[%s]' % addr[0] if Utils.is_ipv6_address(addr[0]) else addr[0], addr[1])), write_now=True)
                s.connect(addr)
                self.__sock = s
                return None
            except socket.error as e:
                err = e
                self._close_socket(s)
        if err is None:
            errm = 'host {} has no DNS records'.format(self.__host)
        else:
            errt = (self.__host, self.__port, err)
            errm = 'cannot connect to {} port {}: {}'.format(*errt)
        return '[exception] {}'.format(errm)

    def get_banner(self, sshv: int = 2) -> Tuple[Optional['Banner'], List[str], Optional[str]]:
        self.__outputbuffer.d('Getting banner...', write_now=True)

        if self.__sock is None:
            return self.__banner, self.__header, 'not connected'
        if self.__banner is not None:
            return self.__banner, self.__header, None

        banner = SSH_HEADER.format('1.5' if sshv == 1 else '2.0')
        if self.__state < self.SM_BANNER_SENT:
            self.send_banner(banner)

        s = 0
        e = None
        while s >= 0:
            s, e = self.recv()
            if s < 0:
                continue
            while self.unread_len > 0:
                line = self.read_line()
                if len(line.strip()) == 0:
                    continue
                self.__banner = Banner.parse(line)
                if self.__banner is not None:
                    return self.__banner, self.__header, None
                self.__header.append(line)

        return self.__banner, self.__header, e

    def recv(self, size: int = 2048) -> Tuple[int, Optional[str]]:
        if self.__sock is None:
            return -1, 'not connected'
        try:
            data = self.__sock.recv(size)
        except socket.timeout:
            return -1, 'timed out'
        except socket.error as e:
            if e.args[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
                return 0, 'retry'
            return -1, str(e.args[-1])
        if len(data) == 0:
            return -1, None
        pos = self._buf.tell()
        self._buf.seek(0, 2)
        self._buf.write(data)
        self._len += len(data)
        self._buf.seek(pos, 0)
        return len(data), None

    def send(self, data: bytes) -> Tuple[int, Optional[str]]:
        if self.__sock is None:
            return -1, 'not connected'
        try:
            self.__sock.send(data)
            return 0, None
        except socket.error as e:
            return -1, str(e.args[-1])

    # Send a KEXINIT with the lists of key exchanges, hostkeys, ciphers, MACs, compressions, and languages that we "support".
    def send_kexinit(self, key_exchanges: List[str] = ['curve25519-sha256', 'curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'diffie-hellman-group-exchange-sha256', 'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group14-sha256'], hostkeys: List[str] = ['rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ssh-ed25519'], ciphers: List[str] = ['chacha20-poly1305@openssh.com', 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com'], macs: List[str] = ['umac-64-etm@openssh.com', 'umac-128-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'umac-64@openssh.com', 'umac-128@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1'], compressions: List[str] = ['none', 'zlib@openssh.com'], languages: List[str] = ['']) -> None:  # pylint: disable=dangerous-default-value
        '''Sends the list of supported host keys, key exchanges, ciphers, and MACs.  Emulates OpenSSH v8.2.'''

        self.__outputbuffer.d('KEX initialisation...', write_now=True)

        kexparty = SSH2_KexParty(ciphers, macs, compressions, languages)
        kex = SSH2_Kex(os.urandom(16), key_exchanges, hostkeys, kexparty, kexparty, False, 0)

        self.write_byte(Protocol.MSG_KEXINIT)
        kex.write(self)
        self.send_packet()

    def send_banner(self, banner: str) -> None:
        self.send(banner.encode() + b'\r\n')
        if self.__state < self.SM_BANNER_SENT:
            self.__state = self.SM_BANNER_SENT

    def ensure_read(self, size: int) -> None:
        while self.unread_len < size:
            s, e = self.recv()
            if s < 0:
                raise SSH_Socket.InsufficientReadException(e)

    def read_packet(self, sshv: int = 2) -> Tuple[int, bytes]:
        try:
            header = WriteBuf()
            self.ensure_read(4)
            packet_length = self.read_int()
            header.write_int(packet_length)
            # XXX: validate length
            if sshv == 1:
                padding_length = 8 - packet_length % 8
                self.ensure_read(padding_length)
                padding = self.read(padding_length)
                header.write(padding)
                payload_length = packet_length
                check_size = padding_length + payload_length
            else:
                self.ensure_read(1)
                padding_length = self.read_byte()
                header.write_byte(padding_length)
                payload_length = packet_length - padding_length - 1
                check_size = 4 + 1 + payload_length + padding_length
            if check_size % self.__block_size != 0:
                self.__outputbuffer.fail('[exception] invalid ssh packet (block size)').write()
                sys.exit(exitcodes.CONNECTION_ERROR)
            self.ensure_read(payload_length)
            if sshv == 1:
                payload = self.read(payload_length - 4)
                header.write(payload)
                crc = self.read_int()
                header.write_int(crc)
            else:
                payload = self.read(payload_length)
                header.write(payload)
            packet_type = ord(payload[0:1])
            if sshv == 1:
                rcrc = SSH1.crc32(padding + payload)
                if crc != rcrc:
                    self.__outputbuffer.fail('[exception] packet checksum CRC32 mismatch.').write()
                    sys.exit(exitcodes.CONNECTION_ERROR)
            else:
                self.ensure_read(padding_length)
                padding = self.read(padding_length)
            payload = payload[1:]
            return packet_type, payload
        except SSH_Socket.InsufficientReadException as ex:
            if ex.args[0] is None:
                header.write(self.read(self.unread_len))
                e = header.write_flush().strip()
            else:
                e = ex.args[0].encode('utf-8')
            return -1, e

    def send_packet(self) -> Tuple[int, Optional[str]]:
        payload = self.write_flush()
        padding = -(len(payload) + 5) % 8
        if padding < 4:
            padding += 8
        plen = len(payload) + padding + 1
        pad_bytes = b'\x00' * padding
        data = struct.pack('>Ib', plen, padding) + payload + pad_bytes
        return self.send(data)

    def is_connected(self) -> bool:
        """Returns true if this Socket is connected, False otherwise."""
        return self.__sock is not None

    def close(self) -> None:
        self.__cleanup()
        self.reset()
        self.__state = 0
        self.__header = []
        self.__banner = None

    def _close_socket(self, s: Optional[socket.socket]) -> None:
        try:
            if s is not None:
                s.shutdown(socket.SHUT_RDWR)
                s.close()  # pragma: nocover
        except Exception:
            pass

    def __del__(self) -> None:
        self.__cleanup()

    def __cleanup(self) -> None:
        self._close_socket(self.__sock)
        for sock in self.__sock_map.values():
            self._close_socket(sock)
        self.__sock = None

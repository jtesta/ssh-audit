"""
   The MIT License (MIT)

   Copyright (C) 2017-2023 Joe Testa (jtesta@positronsecurity.com)
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
import binascii
import os
import random
import struct
import traceback

# pylint: disable=unused-import
from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401

from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.protocol import Protocol
from ssh_audit.ssh_socket import SSH_Socket


class KexDHException(Exception):
    pass


class KexDH:  # pragma: nocover
    def __init__(self, out: 'OutputBuffer', kex_name: str, hash_alg: str, g: int, p: int) -> None:
        self.out = out
        self.__kex_name = kex_name  # pylint: disable=unused-private-member
        self.__hash_alg = hash_alg  # pylint: disable=unused-private-member
        self.__g = 0
        self.__p = 0
        self.__q = 0
        self.__x = 0
        self.__e = 0
        self.set_params(g, p)

        self.__ed25519_pubkey: Optional[bytes] = None  # pylint: disable=unused-private-member
        self.__hostkey_type = ''
        self.__hostkey_e = 0  # pylint: disable=unused-private-member
        self.__hostkey_n = 0  # pylint: disable=unused-private-member
        self.__hostkey_n_len = 0  # Length of the host key modulus.
        self.__ca_key_type = ''  # Type of CA key ('ssh-rsa', etc).
        self.__ca_n_len = 0  # Length of the CA key modulus (if hostkey is a cert).

    def set_params(self, g: int, p: int) -> None:
        self.__g = g
        self.__p = p
        self.__q = (self.__p - 1) // 2
        self.__x = 0
        self.__e = 0

    def send_init(self, s: SSH_Socket, init_msg: int = Protocol.MSG_KEXDH_INIT) -> None:
        r = random.SystemRandom()
        self.__x = r.randrange(2, self.__q)
        self.__e = pow(self.__g, self.__x, self.__p)
        s.write_byte(init_msg)
        s.write_mpint2(self.__e)
        s.send_packet()

    # Parse a KEXDH_REPLY or KEXDH_GEX_REPLY message from the server.  This
    # contains the host key, among other things.  Function returns the host
    # key blob (from which the fingerprint can be calculated).
    def recv_reply(self, s: 'SSH_Socket', parse_host_key_size: bool = True) -> Optional[bytes]:
        # Reset the CA info, in case it was set from a prior invocation.
        self.__hostkey_type = ''
        self.__hostkey_e = 0  # pylint: disable=unused-private-member
        self.__hostkey_n = 0  # pylint: disable=unused-private-member
        self.__hostkey_n_len = 0
        self.__ca_key_type = ''
        self.__ca_n_len = 0

        packet_type, payload = s.read_packet(2)

        # Skip any & all MSG_DEBUG messages.
        while packet_type == Protocol.MSG_DEBUG:
            packet_type, payload = s.read_packet(2)

        if packet_type != -1 and packet_type not in [Protocol.MSG_KEXDH_REPLY, Protocol.MSG_KEXDH_GEX_REPLY]:  # pylint: disable=no-else-raise
            raise KexDHException('Expected MSG_KEXDH_REPLY (%d) or MSG_KEXDH_GEX_REPLY (%d), but got %d instead.' % (Protocol.MSG_KEXDH_REPLY, Protocol.MSG_KEXDH_GEX_REPLY, packet_type))
        elif packet_type == -1:
            # A connection error occurred.  We can't parse anything, so just
            # return.  The host key modulus (and perhaps certificate modulus)
            # will remain at length 0.
            self.out.d("KexDH.recv_reply(): received package_type == -1.")
            return None

        # Get the host key blob, F, and signature.
        ptr = 0
        hostkey, _, ptr = KexDH.__get_bytes(payload, ptr)

        # If we are not supposed to parse the host key size (i.e.: it is a type that is of fixed size such as ed25519), then stop here.
        if not parse_host_key_size:
            return hostkey

        _, _, ptr = KexDH.__get_bytes(payload, ptr)
        _, _, ptr = KexDH.__get_bytes(payload, ptr)

        # Now pick apart the host key blob.
        # Get the host key type (i.e.: 'ssh-rsa', 'ssh-ed25519', etc).
        ptr = 0
        hostkey_type, _, ptr = KexDH.__get_bytes(hostkey, ptr)
        self.__hostkey_type = hostkey_type.decode('ascii')
        self.out.d("Parsing host key type: %s" % self.__hostkey_type)

        # If this is an RSA certificate, skip over the nonce.
        if self.__hostkey_type.startswith('ssh-rsa-cert-v0'):
            self.out.d("RSA certificate found, so skipping nonce.")
            _, _, ptr = KexDH.__get_bytes(hostkey, ptr)  # Read & skip over the nonce.

        # The public key exponent.
        hostkey_e, _, ptr = KexDH.__get_bytes(hostkey, ptr)
        self.__hostkey_e = int(binascii.hexlify(hostkey_e), 16)  # pylint: disable=unused-private-member

        # ED25519 moduli are fixed at 32 bytes.
        if self.__hostkey_type == 'ssh-ed25519':
            self.out.d("%s has a fixed host key modulus of 32." % self.__hostkey_type)
            self.__hostkey_n_len = 32
        else:
            # Here is the modulus size & actual modulus of the host key public key.
            hostkey_n, self.__hostkey_n_len, ptr = KexDH.__get_bytes(hostkey, ptr)
            self.__hostkey_n = int(binascii.hexlify(hostkey_n), 16)  # pylint: disable=unused-private-member

        # If this is a certificate, continue parsing to extract the CA type and key length.  Even though a hostkey type might be 'ssh-ed25519-cert-v01@openssh.com', its CA may still be RSA.
        if self.__hostkey_type.startswith('ssh-rsa-cert-v0') or self.__hostkey_type.startswith('ssh-ed25519-cert-v0'):
            # Get the CA key type and key length.
            self.__ca_key_type, self.__ca_n_len = self.__parse_ca_key(hostkey, self.__hostkey_type, ptr)
            self.out.d("KexDH.__parse_ca_key(): CA key type: [%s]; CA key length: %u" % (self.__ca_key_type, self.__ca_n_len))

        return hostkey

    def __parse_ca_key(self, hostkey: bytes, hostkey_type: str, ptr: int) -> Tuple[str, int]:
        ca_key_type = ''
        ca_key_n_len = 0

        # If this is a certificate, continue parsing to extract the CA type and key length.  Even though a hostkey type might be 'ssh-ed25519-cert-v01@openssh.com', its CA may still be RSA.
        # if hostkey_type.startswith('ssh-rsa-cert-v0') or hostkey_type.startswith('ssh-ed25519-cert-v0'):
        self.out.d("Parsing CA for hostkey type [%s]..." % hostkey_type)

        # Skip over the serial number.
        ptr += 8

        # Get the certificate type.
        cert_type = int(binascii.hexlify(hostkey[ptr:ptr + 4]), 16)
        ptr += 4

        # Only SSH2_CERT_TYPE_HOST (2) makes sense in this context.
        if cert_type == 2:

            # Skip the key ID (this is the serial number of the
            # certificate).
            key_id, key_id_len, ptr = KexDH.__get_bytes(hostkey, ptr)  # pylint: disable=unused-variable

            # The principles, which are... I don't know what.
            principles, principles_len, ptr = KexDH.__get_bytes(hostkey, ptr)  # pylint: disable=unused-variable

            # Skip over the timestamp that this certificate is valid after.
            ptr += 8

            # Skip over the timestamp that this certificate is valid before.
            ptr += 8

            # TODO: validate the principles, and time range.

            # The critical options.
            critical_options, critical_options_len, ptr = KexDH.__get_bytes(hostkey, ptr)  # pylint: disable=unused-variable

            # Certificate extensions.
            extensions, extensions_len, ptr = KexDH.__get_bytes(hostkey, ptr)  # pylint: disable=unused-variable

            # Another nonce.
            nonce, nonce_len, ptr = KexDH.__get_bytes(hostkey, ptr)  # pylint: disable=unused-variable

            # Finally, we get to the CA key.
            ca_key, ca_key_len, ptr = KexDH.__get_bytes(hostkey, ptr)  # pylint: disable=unused-variable

            # Last in the host key blob is the CA signature.  It isn't
            # interesting to us, so we won't bother parsing any further.
            # The CA key has the modulus, however...
            ptr = 0

            # 'ssh-rsa', 'rsa-sha2-256', etc.
            ca_key_type_bytes, ca_key_type_len, ptr = KexDH.__get_bytes(ca_key, ptr)  # pylint: disable=unused-variable
            ca_key_type = ca_key_type_bytes.decode('ascii')
            self.out.d("Found CA type: [%s]" % ca_key_type)

            # ED25519 CA's don't explicitly include the modulus size in the public key, since its fixed at 32 in all cases.
            if ca_key_type == 'ssh-ed25519':
                ca_key_n_len = 32
            else:
                # CA's public key exponent.
                ca_key_e, ca_key_e_len, ptr = KexDH.__get_bytes(ca_key, ptr)  # pylint: disable=unused-variable

                # CA's modulus.  Bingo.
                ca_key_n, ca_key_n_len, ptr = KexDH.__get_bytes(ca_key, ptr)  # pylint: disable=unused-variable

                if ca_key_type.startswith("ecdsa-sha2-nistp") and ca_key_n_len > 0:
                    self.out.d("Found ecdsa-sha2-nistp* CA key type.")

                    # 0x04 signifies that this is an uncompressed public key (meaning that full X and Y values are provided in ca_key_n.
                    if ca_key_n[0] == 4:
                        ca_key_n_len = ca_key_n_len - 1  # Subtract the 0x04 byte.
                        ca_key_n_len = int(ca_key_n_len / 2)  # Divide by 2 since the modulus is the size of either the X or Y value.


        else:
            self.out.d("Certificate type %u found; this is not usually valid in the context of a host key!  Skipping it..." % cert_type)

        return ca_key_type, ca_key_n_len

    @staticmethod
    def __get_bytes(buf: bytes, ptr: int) -> Tuple[bytes, int, int]:
        num_bytes = struct.unpack('>I', buf[ptr:ptr + 4])[0]
        ptr += 4
        return buf[ptr:ptr + num_bytes], num_bytes, ptr + num_bytes

    # Converts a modulus length in bytes to its size in bits, after some
    # possible adjustments.
    @staticmethod
    def __adjust_key_size(size: int) -> int:
        size = size * 8
        # Actual keys are observed to be about 8 bits bigger than expected
        # (i.e.: 1024-bit keys have a 1032-bit modulus).  Check if this is
        # the case, and subtract 8 if so.  This simply improves readability
        # in the UI.
        if (size >> 3) % 2 != 0:
            size = size - 8
        return size

    # Returns the hostkey type.
    def get_hostkey_type(self) -> str:
        return self.__hostkey_type

    # Returns the size of the hostkey, in bits.
    def get_hostkey_size(self) -> int:
        return KexDH.__adjust_key_size(self.__hostkey_n_len)

    # Returns the CA type ('ssh-rsa', 'ssh-ed25519', etc).
    def get_ca_type(self) -> str:
        return self.__ca_key_type

    # Returns the size of the CA key, in bits.
    def get_ca_size(self) -> int:
        return KexDH.__adjust_key_size(self.__ca_n_len)

    # Returns the size of the DH modulus, in bits.
    def get_dh_modulus_size(self) -> int:
        # -2 to account for the '0b' prefix in the string.
        return len(bin(self.__p)) - 2


class KexGroup1(KexDH):  # pragma: nocover
    def __init__(self, out: 'OutputBuffer') -> None:
        # rfc2409: second oakley group
        p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff', 16)
        super(KexGroup1, self).__init__(out, 'KexGroup1', 'sha1', 2, p)


class KexGroup14(KexDH):  # pragma: nocover
    def __init__(self, out: 'OutputBuffer', hash_alg: str) -> None:
        # rfc3526: 2048-bit modp group
        p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff', 16)
        super(KexGroup14, self).__init__(out, 'KexGroup14', hash_alg, 2, p)


class KexGroup14_SHA1(KexGroup14):
    def __init__(self, out: 'OutputBuffer') -> None:
        super(KexGroup14_SHA1, self).__init__(out, 'sha1')


class KexGroup14_SHA256(KexGroup14):
    def __init__(self, out: 'OutputBuffer') -> None:
        super(KexGroup14_SHA256, self).__init__(out, 'sha256')


class KexGroup16_SHA512(KexDH):
    def __init__(self, out: 'OutputBuffer') -> None:
        # rfc3526: 4096-bit modp group
        p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199ffffffffffffffff', 16)
        super(KexGroup16_SHA512, self).__init__(out, 'KexGroup16_SHA512', 'sha512', 2, p)


class KexGroup18_SHA512(KexDH):
    def __init__(self, out: 'OutputBuffer') -> None:
        # rfc3526: 8192-bit modp group
        p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1bdb7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aacc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dbe115974a3926f12fee5e438777cb6a932df8cd8bec4d073b931ba3bc832b68d9dd300741fa7bf8afc47ed2576f6936ba424663aab639c5ae4f5683423b4742bf1c978238f16cbe39d652de3fdb8befc848ad922222e04a4037c0713eb57a81a23f0c73473fc646cea306b4bcbc8862f8385ddfa9d4b7fa2c087e879683303ed5bdd3a062b3cf5b3a278a66d2a13f83f44f82ddf310ee074ab6a364597e899a0255dc164f31cc50846851df9ab48195ded7ea1b1d510bd7ee74d73faf36bc31ecfa268359046f4eb879f924009438b481c6cd7889a002ed5ee382bc9190da6fc026e479558e4475677e9aa9e3050e2765694dfc81f56e880b96e7160c980dd98edd3dfffffffffffffffff', 16)
        super(KexGroup18_SHA512, self).__init__(out, 'KexGroup18_SHA512', 'sha512', 2, p)


class KexCurve25519_SHA256(KexDH):
    def __init__(self, out: 'OutputBuffer') -> None:
        super(KexCurve25519_SHA256, self).__init__(out, 'KexCurve25519_SHA256', 'sha256', 0, 0)

    # To start an ED25519 kex, we simply send a random 256-bit number as the
    # public key.
    def send_init(self, s: 'SSH_Socket', init_msg: int = Protocol.MSG_KEXDH_INIT) -> None:
        self.__ed25519_pubkey = os.urandom(32)
        s.write_byte(init_msg)
        s.write_string(self.__ed25519_pubkey)
        s.send_packet()


class KexNISTP256(KexDH):
    def __init__(self, out: 'OutputBuffer') -> None:
        super(KexNISTP256, self).__init__(out, 'KexNISTP256', 'sha256', 0, 0)

    # Because the server checks that the value sent here is valid (i.e.: it lies
    # on the curve, among other things), we would have to write a lot of code
    # or import an elliptic curve library in order to randomly generate a
    # valid elliptic point each time.  Hence, we will simply send a static
    # value, which is enough for us to extract the server's host key.
    def send_init(self, s: 'SSH_Socket', init_msg: int = Protocol.MSG_KEXDH_INIT) -> None:
        s.write_byte(init_msg)
        s.write_string(b'\x04\x0b\x60\x44\x9f\x8a\x11\x9e\xc7\x81\x0c\xa9\x98\xfc\xb7\x90\xaa\x6b\x26\x8c\x12\x4a\xc0\x09\xbb\xdf\xc4\x2c\x4c\x2c\x99\xb6\xe1\x71\xa0\xd4\xb3\x62\x47\x74\xb3\x39\x0c\xf2\x88\x4a\x84\x6b\x3b\x15\x77\xa5\x77\xd2\xa9\xc9\x94\xf9\xd5\x66\x19\xcd\x02\x34\xd1')
        s.send_packet()


class KexNISTP384(KexDH):
    def __init__(self, out: 'OutputBuffer') -> None:
        super(KexNISTP384, self).__init__(out, 'KexNISTP384', 'sha256', 0, 0)

    # See comment for KexNISTP256.send_init().
    def send_init(self, s: 'SSH_Socket', init_msg: int = Protocol.MSG_KEXDH_INIT) -> None:
        s.write_byte(init_msg)
        s.write_string(b'\x04\xe2\x9b\x84\xce\xa1\x39\x50\xfe\x1e\xa3\x18\x70\x1c\xe2\x7a\xe4\xb5\x6f\xdf\x93\x9f\xd4\xf4\x08\xcc\x9b\x02\x10\xa4\xca\x77\x9c\x2e\x51\x44\x1d\x50\x7a\x65\x4e\x7e\x2f\x10\x2d\x2d\x4a\x32\xc9\x8e\x18\x75\x90\x6c\x19\x10\xda\xcc\xa8\xe9\xf4\xc4\x3a\x53\x80\x35\xf4\x97\x9c\x04\x16\xf9\x5a\xdc\xcc\x05\x94\x29\xfa\xc4\xd6\x87\x4e\x13\x21\xdb\x3d\x12\xac\xbd\x20\x3b\x60\xff\xe6\x58\x42')
        s.send_packet()


class KexNISTP521(KexDH):
    def __init__(self, out: 'OutputBuffer') -> None:
        super(KexNISTP521, self).__init__(out, 'KexNISTP521', 'sha256', 0, 0)

    # See comment for KexNISTP256.send_init().
    def send_init(self, s: 'SSH_Socket', init_msg: int = Protocol.MSG_KEXDH_INIT) -> None:
        s.write_byte(init_msg)
        s.write_string(b'\x04\x01\x02\x90\x29\xe9\x8f\xa8\x04\xaf\x1c\x00\xf9\xc6\x29\xc0\x39\x74\x8e\xea\x47\x7e\x7c\xf7\x15\x6e\x43\x3b\x59\x13\x53\x43\xb0\xae\x0b\xe7\xe6\x7c\x55\x73\x52\xa5\x2a\xc1\x42\xde\xfc\xf4\x1f\x8b\x5a\x8d\xfa\xcd\x0a\x65\x77\xa8\xce\x68\xd2\xc6\x26\xb5\x3f\xee\x4b\x01\x7b\xd2\x96\x23\x69\x53\xc7\x01\xe1\x0d\x39\xe9\x87\x49\x3b\xc8\xec\xda\x0c\xf9\xca\xad\x89\x42\x36\x6f\x93\x78\x78\x31\x55\x51\x09\x51\xc0\x96\xd7\xea\x61\xbf\xc2\x44\x08\x80\x43\xed\xc6\xbb\xfb\x94\xbd\xf8\xdf\x2b\xd8\x0b\x2e\x29\x1b\x8c\xc4\x8a\x04\x2d\x3a')
        s.send_packet()


class KexGroupExchange(KexDH):
    def __init__(self, out: 'OutputBuffer', classname: str, hash_alg: str) -> None:
        super(KexGroupExchange, self).__init__(out, classname, hash_alg, 0, 0)

    def send_init(self, s: 'SSH_Socket', init_msg: int = Protocol.MSG_KEXDH_GEX_REQUEST) -> None:
        self.send_init_gex(s)

    # The group exchange starts with sending a message to the server with
    # the minimum, maximum, and preferred number of bits are for the DH group.
    # The server responds with a generator and prime modulus that matches that,
    # then the handshake continues on like a normal DH handshake (except the
    # SSH message types differ).
    def send_init_gex(self, s: 'SSH_Socket', minbits: int = 1024, prefbits: int = 2048, maxbits: int = 8192) -> None:

        # Send the initial group exchange request.  Tell the server what range
        # of modulus sizes we will accept, along with our preference.
        s.write_byte(Protocol.MSG_KEXDH_GEX_REQUEST)
        s.write_int(minbits)
        s.write_int(prefbits)
        s.write_int(maxbits)
        s.send_packet()

        packet_type, payload = s.read_packet(2)
        if packet_type not in [Protocol.MSG_KEXDH_GEX_GROUP, Protocol.MSG_DEBUG]:
            raise KexDHException('Expected MSG_KEXDH_GEX_REPLY (%d), but got %d instead.' % (Protocol.MSG_KEXDH_GEX_REPLY, packet_type))

        # Skip any & all MSG_DEBUG messages.
        while packet_type == Protocol.MSG_DEBUG:
            packet_type, payload = s.read_packet(2)

        try:
            # Parse the modulus (p) and generator (g) values from the server.
            ptr = 0
            p_len = struct.unpack('>I', payload[ptr:ptr + 4])[0]
            ptr += 4

            p = int(binascii.hexlify(payload[ptr:ptr + p_len]), 16)
            ptr += p_len

            g_len = struct.unpack('>I', payload[ptr:ptr + 4])[0]
            ptr += 4

            g = int(binascii.hexlify(payload[ptr:ptr + g_len]), 16)
            ptr += g_len
        except struct.error:
            raise KexDHException("Error while parsing modulus and generator during GEX init: %s" % str(traceback.format_exc())) from None

        # Now that we got the generator and modulus, perform the DH exchange
        # like usual.
        super(KexGroupExchange, self).set_params(g, p)
        super(KexGroupExchange, self).send_init(s, Protocol.MSG_KEXDH_GEX_INIT)


class KexGroupExchange_SHA1(KexGroupExchange):
    def __init__(self, out: 'OutputBuffer') -> None:
        super(KexGroupExchange_SHA1, self).__init__(out, 'KexGroupExchange_SHA1', 'sha1')


class KexGroupExchange_SHA256(KexGroupExchange):
    def __init__(self, out: 'OutputBuffer') -> None:
        super(KexGroupExchange_SHA256, self).__init__(out, 'KexGroupExchange_SHA256', 'sha256')

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
# pylint: disable=unused-import
import copy
import threading

from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401


class SSH2_KexDB:  # pylint: disable=too-few-public-methods
    FAIL_1024BIT_MODULUS = 'using small 1024-bit modulus'
    FAIL_3DES = 'using broken & deprecated 3DES cipher'
    FAIL_BLOWFISH = 'using weak & deprecated Blowfish cipher'
    FAIL_CAST = 'using weak & deprecated CAST cipher'
    FAIL_DES = 'using broken DES cipher'
    FAIL_IDEA = 'using deprecated IDEA cipher'
    FAIL_LOGJAM_ATTACK = 'vulnerable to the Logjam attack: https://en.wikipedia.org/wiki/Logjam_(computer_security)'
    FAIL_MD5 = 'using broken MD5 hash algorithm'
    FAIL_NSA_BACKDOORED_CURVE = 'using elliptic curves that are suspected as being backdoored by the U.S. National Security Agency'
    FAIL_PLAINTEXT = 'no encryption/integrity'
    FAIL_RC4 = 'using broken RC4 cipher'
    FAIL_RIJNDAEL = 'using deprecated & non-standardized Rijndael cipher'
    FAIL_RIPEMD = 'using deprecated RIPEMD hash algorithm'
    FAIL_SEED = 'using deprecated SEED cipher'
    FAIL_SERPENT = 'using deprecated Serpent cipher'
    FAIL_SHA1 = 'using broken SHA-1 hash algorithm'
    FAIL_SMALL_ECC_MODULUS = 'using small ECC modulus'
    FAIL_UNKNOWN = 'using unknown algorithm'
    FAIL_UNPROVEN = 'using unproven algorithm'
    FAIL_UNTRUSTED = 'using untrusted algorithm developed in secret by a government entity'

    WARN_2048BIT_MODULUS = '2048-bit modulus only provides 112-bits of symmetric strength'
    WARN_BLOCK_SIZE = 'using small 64-bit block size'
    WARN_CIPHER_MODE = 'using weak cipher mode'
    WARN_ENCRYPT_AND_MAC = 'using encrypt-and-MAC mode'
    WARN_EXPERIMENTAL = 'using experimental algorithm'
    WARN_RNDSIG_KEY = 'using weak random number generator could reveal the key'
    WARN_TAG_SIZE = 'using small 64-bit tag size'
    WARN_TAG_SIZE_96 = 'using small 96-bit tag size'

    INFO_DEFAULT_OPENSSH_CIPHER = 'default cipher since OpenSSH 6.9'
    INFO_DEFAULT_OPENSSH_KEX_65_TO_73 = 'default key exchange from OpenSSH 6.5 to 7.3'
    INFO_DEFAULT_OPENSSH_KEX_74_TO_89 = 'default key exchange from OpenSSH 7.4 to 8.9'
    INFO_DEFAULT_OPENSSH_KEX_90 = 'default key exchange since OpenSSH 9.0'
    INFO_DEPRECATED_IN_OPENSSH88 = 'deprecated in OpenSSH 8.8: https://www.openssh.com/txt/release-8.8'
    INFO_DISABLED_IN_DBEAR67 = 'disabled in Dropbear SSH 2015.67'
    INFO_DISABLED_IN_OPENSSH70 = 'disabled in OpenSSH 7.0: https://www.openssh.com/txt/release-7.0'
    INFO_NEVER_IMPLEMENTED_IN_OPENSSH = 'despite the @openssh.com tag, this was never implemented in OpenSSH'
    INFO_REMOVED_IN_OPENSSH61 = 'removed since OpenSSH 6.1, removed from specification'
    INFO_REMOVED_IN_OPENSSH69 = 'removed in OpenSSH 6.9: https://www.openssh.com/txt/release-6.9'
    INFO_REMOVED_IN_OPENSSH70 = 'removed in OpenSSH 7.0: https://www.openssh.com/txt/release-7.0'
    INFO_WITHDRAWN_PQ_ALG = 'the sntrup4591761 algorithm was withdrawn, as it may not provide strong post-quantum security'
    INFO_EXTENSION_NEGOTIATION = 'pseudo-algorithm that denotes the peer supports RFC8308 extensions'
    INFO_STRICT_KEX = 'pseudo-algorithm that denotes the peer supports a stricter key exchange method as a counter-measure to the Terrapin attack (CVE-2023-48795)'

    WEIGHT_FAIL = 1
    WEIGHT_EAM = 100
    WEIGHT_NEVER_OSSH = 200
    WEIGHT_128 = 1000
    WEIGHT_192 = 1500
    WEIGHT_384 = 1500
    WEIGHT_CURVE_256 = 5000
    WEIGHT_DH_G14_256 = 2000
    WEIGHT_DH_G15_256 = 2500
    WEIGHT_DH_G15_384 = 2550
    WEIGHT_DH_G15_512 = 2575
    WEIGHT_DH_G16_256 = 2600
    WEIGHT_DH_G16_384 = 2650
    WEIGHT_DH_G16_512 = 2675
    WEIGHT_DH_G16_256 = 2700
    WEIGHT_DH_G16_384 = 2750
    WEIGHT_DH_G16_512 = 2775
    WEIGHT_DH_G17_512 = 2875
    WEIGHT_DH_G18_512 = 2975
    WEIGHT_DH_256 = 2000
    WEIGHT_DH_384 = 2200
    WEIGHT_DH_512 = 2300

    WEIGHT_DISABLED = 1300
    WEIGHT_SSH_NOT_IMP_OR_DISABLED = 250

    DESIRED_WEIGHT = 9000
    WEIGHT_CHACHA = 1200 # until patch
    STRONG_CURVE = 9000
    GOOD_CURVE = 8500

    NEVER_SUGGEST_ALG = 1

    WEIGHT_STRICT_KEX = 5000

    # Maintains a dictionary per calling thread that yields its own copy of MASTER_DB.  This prevents results from one thread polluting the results of another thread.
    DB_PER_THREAD: Dict[int, Dict[str, Dict[str, List[List[Optional[str]]]]]] = {}

    MASTER_DB: Dict[str, Dict[str, List[List[Optional[str]]]]] = {
        # Format: 'algorithm_name': [['version_first_appeared_in'], [reason_for_failure1, reason_for_failure2, ...], [warning1, warning2, ...], [info1, info2, ...], [preference_weight]]
        'kex': {
            'Curve25519SHA256': [[], [], [], [], [STRONG_CURVE]],
            'curve25519-sha256': [['7.4,d2018.76'], [], [], [INFO_DEFAULT_OPENSSH_KEX_74_TO_89], [STRONG_CURVE]],
            'curve25519-sha256@libssh.org': [['6.4,d2013.62,l10.6.0'], [], [], [INFO_DEFAULT_OPENSSH_KEX_65_TO_73], [STRONG_CURVE]],
            'curve448-sha512': [[], [], [], [], [GOOD_CURVE]],
            'curve448-sha512@libssh.org': [[], [], [], [], [GOOD_CURVE]],
            'diffie-hellman-group14-sha1': [['3.9,d0.53,l10.6.0'], [FAIL_SHA1], [WARN_2048BIT_MODULUS], [], [WEIGHT_FAIL]],
            'diffie-hellman-group14-sha224@ssh.com': [[], [], [], [], [WEIGHT_DH_G14_256]],
            'diffie-hellman-group14-sha256': [['7.3,d2016.73'], [], [WARN_2048BIT_MODULUS], [], [WEIGHT_DH_G14_256]],
            'diffie-hellman-group14-sha256@ssh.com': [[], [], [WARN_2048BIT_MODULUS], [], [WEIGHT_DH_G14_256]],
            'diffie-hellman-group15-sha256': [[], [], [], [], [WEIGHT_DH_G15_256]],
            'diffie-hellman-group15-sha256@ssh.com': [[], [], [], [], [WEIGHT_DH_G15_256]],
            'diffie-hellman-group15-sha384@ssh.com': [[], [], [], [], [WEIGHT_DH_G15_384]],
            'diffie-hellman-group15-sha512': [[], [], [], [], [WEIGHT_DH_G15_512]],
            'diffie-hellman-group16-sha256': [[], [], [], [], [WEIGHT_DH_G16_256]],
            'diffie-hellman-group16-sha384@ssh.com': [[], [], [], [], [WEIGHT_DH_G16_384]],
            'diffie-hellman-group16-sha512': [['7.3,d2016.73'], [], [], [], [WEIGHT_DH_G16_512]],
            'diffie-hellman-group16-sha512@ssh.com': [[], [], [], [], [WEIGHT_DH_G16_512]],
            'diffie-hellman-group17-sha512': [[], [], [], [], [WEIGHT_DH_G17_512]],
            'diffie-hellman_group17-sha512': [[], [], [], [], [WEIGHT_DH_G17_512]],
            'diffie-hellman-group18-sha512': [['7.3'], [], [], [], [WEIGHT_DH_G18_512]],
            'diffie-hellman-group18-sha512@ssh.com': [[], [], [], [], [WEIGHT_DH_G18_512]],
            'diffie-hellman-group1-sha1': [['2.3.0,d0.28,l10.2', '6.6', '6.9'], [FAIL_1024BIT_MODULUS, FAIL_LOGJAM_ATTACK, FAIL_SHA1], [], [INFO_REMOVED_IN_OPENSSH69], [WEIGHT_FAIL]],
            'diffie-hellman-group1-sha256': [[], [FAIL_1024BIT_MODULUS], [], [], [WEIGHT_FAIL]],
            'diffie-hellman-group-exchange-sha1': [['2.3.0', '6.6', None], [FAIL_SHA1], [], [], [WEIGHT_FAIL]],
            'diffie-hellman-group-exchange-sha224@ssh.com': [[], [], [], [], [WEIGHT_FAIL]],
            'diffie-hellman-group-exchange-sha256': [['4.4'], [], [], [], [WEIGHT_DH_256]],
            'diffie-hellman-group-exchange-sha256@ssh.com': [[], [], [], [], [WEIGHT_DH_256]],
            'diffie-hellman-group-exchange-sha384@ssh.com': [[], [], [], [], [WEIGHT_DH_384]],
            'diffie-hellman-group-exchange-sha512@ssh.com': [[], [], [], [], [WEIGHT_DH_512]],
            'ecdh-nistp256-kyber-512r3-sha256-d00@openquantumsafe.org': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],
            'ecdh-nistp384-kyber-768r3-sha384-d00@openquantumsafe.org': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],
            'ecdh-nistp521-kyber-1024r3-sha512-d00@openquantumsafe.org': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],
            'ecdh-sha2-1.2.840.10045.3.1.1': [[], [FAIL_SMALL_ECC_MODULUS, FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],  # NIST P-192 / secp192r1
            'ecdh-sha2-1.2.840.10045.3.1.7': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],  # NIST P-256 / secp256r1
            'ecdh-sha2-1.3.132.0.10': [[], [], [], [], [WEIGHT_FAIL]],  # ECDH over secp256k1 (i.e.: the Bitcoin curve)
            'ecdh-sha2-1.3.132.0.16': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],  # sect283k1
            'ecdh-sha2-1.3.132.0.1': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [], [], [WEIGHT_FAIL]],  # sect163k1
            'ecdh-sha2-1.3.132.0.26': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [], [], [WEIGHT_FAIL]],  # sect233k1
            'ecdh-sha2-1.3.132.0.27': [[], [FAIL_SMALL_ECC_MODULUS, FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],  # sect233r1
            'ecdh-sha2-1.3.132.0.33': [[], [FAIL_SMALL_ECC_MODULUS, FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],  # NIST P-224 / secp224r1
            'ecdh-sha2-1.3.132.0.34': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],  # NIST P-384 / secp384r1
            'ecdh-sha2-1.3.132.0.35': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],  # NIST P-521 / secp521r1
            'ecdh-sha2-1.3.132.0.36': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],  # sect409k1
            'ecdh-sha2-1.3.132.0.37': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],  # sect409r1
            'ecdh-sha2-1.3.132.0.38': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],  # sect571k1

            # Note: the base64 strings, according to draft 6 of RFC5656, is Base64(MD5(DER(OID))).  The final RFC5656 dropped the base64 strings in favor of plain OID concatenation, but apparently some SSH servers implement them anyway.  See: https://datatracker.ietf.org/doc/html/draft-green-secsh-ecc-06#section-9.2
            'ecdh-sha2-4MHB+NBt3AlaSRQ7MnB4cg==': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [], [], [WEIGHT_FAIL]],  # sect163k1
            'ecdh-sha2-5pPrSUQtIaTjUSt5VZNBjg==': [[], [FAIL_SMALL_ECC_MODULUS, FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],  # NIST P-192 / secp192r1
            'ecdh-sha2-9UzNcgwTlEnSCECZa7V1mw==': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],  # NIST P-256 / secp256r1
            'ecdh-sha2-brainpoolp256r1@genua.de': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],
            'ecdh-sha2-brainpoolp384r1@genua.de': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],
            'ecdh-sha2-brainpoolp521r1@genua.de': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],
            'ecdh-sha2-curve25519': [[], [], [], [], [2200]],
            'ecdh-sha2-D3FefCjYoJ/kfXgAyLddYA==': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],  # sect409r1
            'ecdh-sha2-h/SsxnLCtRBh7I9ATyeB3A==': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],  # NIST P-521 / secp521r1
            'ecdh-sha2-m/FtSAmrV4j/Wy6RVUaK7A==': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],  # sect409k1
            'ecdh-sha2-mNVwCXAoS1HGmHpLvBC94w==': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],  # sect571k1
            'ecdh-sha2-nistb233': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [], [], [WEIGHT_FAIL]],
            'ecdh-sha2-nistb409': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],
            'ecdh-sha2-nistk163': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [], [], [WEIGHT_FAIL]],
            'ecdh-sha2-nistk233': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [], [], [WEIGHT_FAIL]],
            'ecdh-sha2-nistk283': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],
            'ecdh-sha2-nistk409': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],
            'ecdh-sha2-nistp192': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],
            'ecdh-sha2-nistp224': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],
            'ecdh-sha2-nistp256': [['5.7,d2013.62,l10.6.0'], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],
            'ecdh-sha2-nistp384': [['5.7,d2013.62'], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],
            'ecdh-sha2-nistp521': [['5.7,d2013.62'], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],
            'ecdh-sha2-nistt571': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],
            'ecdh-sha2-qCbG5Cn/jjsZ7nBeR7EnOA==': [[], [FAIL_SMALL_ECC_MODULUS, FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],  # sect233r1
            'ecdh-sha2-qcFQaMAMGhTziMT0z+Tuzw==': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],  # NIST P-384 / secp384r1
            'ecdh-sha2-VqBg4QRPjxx1EXZdV0GdWQ==': [[], [FAIL_NSA_BACKDOORED_CURVE, FAIL_SMALL_ECC_MODULUS], [], [], [WEIGHT_FAIL]],  # NIST P-224 / secp224r1
            'ecdh-sha2-wiRIU8TKjMZ418sMqlqtvQ==': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],  # sect283k1
            'ecdh-sha2-zD/b3hu/71952ArpUG4OjQ==': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [], [], [WEIGHT_FAIL]],  # sect233k1
            'ecmqv-sha2': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],
            'ext-info-c': [[], [], [], [INFO_EXTENSION_NEGOTIATION], [100]],  # Extension negotiation (RFC 8308)
            'ext-info-s': [[], [], [], [INFO_EXTENSION_NEGOTIATION], [100]],  # Extension negotiation (RFC 8308)
            'kex-strict-c-v00@openssh.com': [[], [], [], [INFO_STRICT_KEX], [WEIGHT_STRICT_KEX]],  # Strict KEX marker (countermeasure for CVE-2023-48795).
            'kex-strict-s-v00@openssh.com': [[], [], [], [INFO_STRICT_KEX], [WEIGHT_STRICT_KEX]],  # Strict KEX marker (countermeasure for CVE-2023-48795).

            # The GSS kex algorithms get special wildcard handling, since they include variable base64 data after their standard prefixes.
            'gss-13.3.132.0.10-sha256-*': [[], [FAIL_UNKNOWN], [], [] ,[WEIGHT_FAIL]],
            'gss-curve25519-sha256-*': [[], [], [], [], [2000]],
            'gss-curve448-sha512-*': [[], [], [], [], [2000]],
            'gss-gex-sha1-*': [[], [FAIL_SHA1], [], [], [WEIGHT_FAIL]],
            'gss-gex-sha256-*': [[], [], [], [], [2000]],
            'gss-group14-sha1-*': [[], [FAIL_SHA1], [WARN_2048BIT_MODULUS], [], [WEIGHT_FAIL]],
            'gss-group14-sha256-*': [[], [], [WARN_2048BIT_MODULUS], [], [100]],
            'gss-group15-sha512-*': [[], [], [], [], [2000]],
            'gss-group16-sha512-*': [[], [], [], [], [2200]],
            'gss-group17-sha512-*': [[], [], [], [], [2200]],
            'gss-group18-sha512-*': [[], [], [], [], [2300]],
            'gss-group1-sha1-*': [[], [FAIL_1024BIT_MODULUS, FAIL_LOGJAM_ATTACK, FAIL_SHA1], [], [], [WEIGHT_FAIL]],
            'gss-nistp256-sha256-*': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],
            'gss-nistp384-sha256-*': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],
            'gss-nistp384-sha384-*': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],
            'gss-nistp521-sha512-*': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],
            'kexAlgoCurve25519SHA256': [[], [], [], [], [2000]],
            'kexAlgoDH14SHA1': [[], [FAIL_SHA1], [WARN_2048BIT_MODULUS], [], [WEIGHT_FAIL]],
            'kexAlgoDH1SHA1': [[], [FAIL_1024BIT_MODULUS, FAIL_LOGJAM_ATTACK, FAIL_SHA1], [], [], [WEIGHT_FAIL]],
            'kexAlgoECDH256': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],
            'kexAlgoECDH384': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],
            'kexAlgoECDH521': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],
            'kexguess2@matt.ucc.asn.au': [['d2013.57'], [], [], [], [200]],
            'm383-sha384@libassh.org': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],
            'm511-sha512@libassh.org': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],
            'rsa1024-sha1': [[], [FAIL_1024BIT_MODULUS, FAIL_SHA1], [], [], [WEIGHT_FAIL]],
            'rsa2048-sha256': [[], [], [WARN_2048BIT_MODULUS], [], [100]],
            'sm2kep-sha2-nistp256': [[], [FAIL_NSA_BACKDOORED_CURVE, FAIL_UNTRUSTED], [], [], [WEIGHT_FAIL]],
            'sntrup4591761x25519-sha512@tinyssh.org': [['8.0', '8.4'], [], [WARN_EXPERIMENTAL], [INFO_WITHDRAWN_PQ_ALG], [1]],
            'sntrup761x25519-sha512@openssh.com': [['8.5'], [], [], [INFO_DEFAULT_OPENSSH_KEX_90], [1]],
            'x25519-kyber-512r3-sha256-d00@amazon.com': [[], [], [], [], [2000]],
            'x25519-kyber512-sha512@aws.amazon.com': [[], [], [], [], [2000]],
        },
        'key': {
            'dsa2048-sha224@libassh.org': [[], [FAIL_UNPROVEN], [WARN_2048BIT_MODULUS], [], [WEIGHT_FAIL]],
            'dsa2048-sha256@libassh.org': [[], [FAIL_UNPROVEN], [WARN_2048BIT_MODULUS], [], [WEIGHT_FAIL]],
            'dsa3072-sha256@libassh.org': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],
            'ecdsa-sha2-1.3.132.0.10-cert-v01@openssh.com': [[], [FAIL_UNKNOWN], [], [], [WEIGHT_FAIL]],
            'ecdsa-sha2-1.3.132.0.10': [[], [], [WARN_RNDSIG_KEY], [], [900]],  # ECDSA over secp256k1 (i.e.: the Bitcoin curve)
            'ecdsa-sha2-curve25519': [[], [], [WARN_RNDSIG_KEY], [], [900]],  # ECDSA with Curve25519?  Bizarre...
            'ecdsa-sha2-nistb233': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'ecdsa-sha2-nistb409': [[], [FAIL_UNPROVEN], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'ecdsa-sha2-nistk163': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'ecdsa-sha2-nistk233': [[], [FAIL_UNPROVEN, FAIL_SMALL_ECC_MODULUS], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'ecdsa-sha2-nistk283': [[], [FAIL_UNPROVEN], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'ecdsa-sha2-nistk409': [[], [FAIL_UNPROVEN], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'ecdsa-sha2-nistp224': [[], [FAIL_NSA_BACKDOORED_CURVE, FAIL_SMALL_ECC_MODULUS], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'ecdsa-sha2-nistp192': [[], [FAIL_NSA_BACKDOORED_CURVE, FAIL_SMALL_ECC_MODULUS], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'ecdsa-sha2-nistp256': [['5.7,d2013.62,l10.6.4'], [FAIL_NSA_BACKDOORED_CURVE], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'ecdsa-sha2-nistp256-cert-v01@openssh.com': [['5.7'], [FAIL_NSA_BACKDOORED_CURVE], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'ecdsa-sha2-nistp384': [['5.7,d2013.62,l10.6.4'], [FAIL_NSA_BACKDOORED_CURVE], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'ecdsa-sha2-nistp384-cert-v01@openssh.com': [['5.7'], [FAIL_NSA_BACKDOORED_CURVE], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'ecdsa-sha2-nistp521': [['5.7,d2013.62,l10.6.4'], [FAIL_NSA_BACKDOORED_CURVE], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'ecdsa-sha2-nistp521-cert-v01@openssh.com': [['5.7'], [FAIL_NSA_BACKDOORED_CURVE], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'ecdsa-sha2-nistt571': [[], [FAIL_UNPROVEN], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'eddsa-e382-shake256@libassh.org': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],
            'eddsa-e521-shake256@libassh.org': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],
            'null': [[], [FAIL_PLAINTEXT], [], [], [WEIGHT_FAIL]],
            'pgp-sign-dss': [[], [FAIL_1024BIT_MODULUS], [], [], [WEIGHT_FAIL]],
            'pgp-sign-rsa': [[], [FAIL_1024BIT_MODULUS], [], [], [WEIGHT_FAIL]],
            'rsa-sha2-256': [['7.2,d2020.79'], [], [], [], [2000]],
            'rsa-sha2-256-cert-v01@openssh.com': [['7.8'], [], [], [], [NEVER_SUGGEST_ALG]],
            'rsa-sha2-512': [['7.2'], [], [], [], [2200]],
            'rsa-sha2-512-cert-v01@openssh.com': [['7.8'], [], [], [], [NEVER_SUGGEST_ALG]],
            'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com': [['8.2'], [FAIL_NSA_BACKDOORED_CURVE], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'sk-ecdsa-sha2-nistp256@openssh.com': [['8.2'], [FAIL_NSA_BACKDOORED_CURVE], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'sk-ssh-ed25519-cert-v01@openssh.com': [['8.2'], [], [], [], [NEVER_SUGGEST_ALG]],
            'sk-ssh-ed25519@openssh.com': [['8.2'], [], [], [], [NEVER_SUGGEST_ALG]],
            'spi-sign-rsa': [[], [], [], [], [200]],
            'spki-sign-dss': [[], [FAIL_1024BIT_MODULUS], [], [], [WEIGHT_FAIL]],
            'spki-sign-rsa': [[], [FAIL_1024BIT_MODULUS], [], [], [WEIGHT_FAIL]],
            'ssh-dsa': [[], [FAIL_1024BIT_MODULUS], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'ssh-dss': [['2.1.0,d0.28,l10.2', '6.9'], [FAIL_1024BIT_MODULUS], [WARN_RNDSIG_KEY], [INFO_DISABLED_IN_OPENSSH70], [WEIGHT_FAIL]],
            'ssh-dss-cert-v00@openssh.com': [['5.4', '6.9'], [FAIL_1024BIT_MODULUS], [WARN_RNDSIG_KEY], [INFO_DISABLED_IN_OPENSSH70], [WEIGHT_FAIL]],
            'ssh-dss-cert-v01@openssh.com': [['5.6', '6.9'], [FAIL_1024BIT_MODULUS], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'ssh-dss-sha224@ssh.com': [[], [FAIL_1024BIT_MODULUS], [], [], [WEIGHT_FAIL]],
            'ssh-dss-sha256@ssh.com': [[], [FAIL_1024BIT_MODULUS], [], [], [WEIGHT_FAIL]],
            'ssh-dss-sha384@ssh.com': [[], [FAIL_1024BIT_MODULUS], [], [], [WEIGHT_FAIL]],
            'ssh-dss-sha512@ssh.com': [[], [FAIL_1024BIT_MODULUS], [], [], [WEIGHT_FAIL]],
            'ssh-ed25519': [['6.5,d2020.79,l10.7.0'], [], [], [], [2000]],
            'ssh-ed25519-cert-v01@openssh.com': [['6.5'], [], [], [], [NEVER_SUGGEST_ALG]],
            'ssh-ed448': [[], [], [], [], [1500]],
            'ssh-ed448-cert-v01@openssh.com': [[], [], [], [INFO_NEVER_IMPLEMENTED_IN_OPENSSH], [NEVER_SUGGEST_ALG]],
            'ssh-gost2001': [[], [FAIL_UNTRUSTED], [], [], [WEIGHT_FAIL]],
            'ssh-gost2012-256': [[], [FAIL_UNTRUSTED], [], [], [WEIGHT_FAIL]],
            'ssh-gost2012-512': [[], [FAIL_UNTRUSTED], [], [], [WEIGHT_FAIL]],
            'ssh-rsa1': [[], [FAIL_SHA1], [], [], [WEIGHT_FAIL]],
            'ssh-rsa': [['2.5.0,d0.28,l10.2'], [FAIL_SHA1], [], [INFO_DEPRECATED_IN_OPENSSH88], [WEIGHT_SSH_NOT_IMP_OR_DISABLED]],
            'ssh-rsa-cert-v00@openssh.com': [['5.4', '6.9'], [FAIL_SHA1], [], [INFO_REMOVED_IN_OPENSSH70], [NEVER_SUGGEST_ALG]],
            'ssh-rsa-cert-v01@openssh.com': [['5.6'], [FAIL_SHA1], [], [INFO_DEPRECATED_IN_OPENSSH88], [NEVER_SUGGEST_ALG]],
            'ssh-rsa-sha224@ssh.com': [[], [], [], [], [200]],
            'ssh-rsa-sha2-256': [[], [], [], [], [1000]],
            'ssh-rsa-sha2-512': [[], [], [], [], [1010]],
            'ssh-rsa-sha256@ssh.com': [[], [], [], [], [1020]],
            'ssh-rsa-sha384@ssh.com': [[], [], [], [], [1030]],
            'ssh-rsa-sha512@ssh.com': [[], [], [], [], [1040]],
            'ssh-xmss-cert-v01@openssh.com': [['7.7'], [], [WARN_EXPERIMENTAL], [], [NEVER_SUGGEST_ALG]],
            'ssh-xmss@openssh.com': [['7.7'], [], [WARN_EXPERIMENTAL], [], [WEIGHT_FAIL]],
            'webauthn-sk-ecdsa-sha2-nistp256@openssh.com': [['8.3'], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],
            'x509v3-ecdsa-sha2-1.3.132.0.10': [[], [FAIL_UNKNOWN], [], [], [WEIGHT_FAIL]],
            'x509v3-ecdsa-sha2-nistp256': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],
            'x509v3-ecdsa-sha2-nistp384': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],
            'x509v3-ecdsa-sha2-nistp521': [[], [FAIL_NSA_BACKDOORED_CURVE], [], [], [WEIGHT_FAIL]],
            'x509v3-rsa2048-sha256': [[], [], [], [], [1050]],
            'x509v3-sign-dss': [[], [FAIL_1024BIT_MODULUS], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'x509v3-sign-dss-sha1': [[], [FAIL_1024BIT_MODULUS, FAIL_SHA1], [], [], [WEIGHT_FAIL]],
            'x509v3-sign-dss-sha224@ssh.com': [[], [FAIL_1024BIT_MODULUS], [], [], [WEIGHT_FAIL]],
            'x509v3-sign-dss-sha256@ssh.com': [[], [FAIL_1024BIT_MODULUS], [], [], [WEIGHT_FAIL]],
            'x509v3-sign-dss-sha384@ssh.com': [[], [FAIL_1024BIT_MODULUS], [], [], [WEIGHT_FAIL]],
            'x509v3-sign-dss-sha512@ssh.com': [[], [FAIL_1024BIT_MODULUS], [], [], [WEIGHT_FAIL]],
            'x509v3-sign-rsa': [[], [FAIL_SHA1], [], [], [WEIGHT_FAIL]],
            'x509v3-sign-rsa-sha1': [[], [FAIL_SHA1], [], [], [WEIGHT_FAIL]],
            'x509v3-sign-rsa-sha224@ssh.com': [[], [], [], [], [1060]],
            'x509v3-sign-rsa-sha256': [[], [], [], [], [1070]],
            'x509v3-sign-rsa-sha256@ssh.com': [[], [], [], [], [1080]],
            'x509v3-sign-rsa-sha384@ssh.com': [[], [], [], [], [1090]],
            'x509v3-sign-rsa-sha512@ssh.com': [[], [], [], [], [2000]],
            'x509v3-ssh-dss': [[], [FAIL_1024BIT_MODULUS], [WARN_RNDSIG_KEY], [], [WEIGHT_FAIL]],
            'x509v3-ssh-rsa': [[], [FAIL_SHA1], [], [INFO_DEPRECATED_IN_OPENSSH88], [WEIGHT_FAIL]],
        },
        'enc': {
            '3des-cbc': [['1.2.2,d0.28,l10.2', '6.6', None], [FAIL_3DES], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE], [], [WEIGHT_FAIL]],
            '3des-cfb': [[], [FAIL_3DES], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            '3des-ctr': [['d0.52'], [FAIL_3DES], [], [], [WEIGHT_FAIL]],
            '3des-ecb': [[], [FAIL_3DES], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            '3des': [[], [FAIL_3DES], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE], [], [WEIGHT_FAIL]],
            '3des-ofb': [[], [FAIL_3DES], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'AEAD_AES_128_GCM': [[], [], [], [], [2010]],
            'AEAD_AES_256_GCM': [[], [], [], [], [2020]],
            'aes128-cbc': [['2.3.0,d0.28,l10.2', '6.6', None], [], [WARN_CIPHER_MODE], [], [1000]],
            'aes128-ctr': [['3.7,d0.52,l10.4.1'], [], [], [], [1100]],
            'aes128-gcm': [[], [], [], [], [500]],
            'aes128-gcm@openssh.com': [['6.2'], [], [], [], [1600]],
            'aes192-cbc': [['2.3.0,l10.2', '6.6', None], [], [WARN_CIPHER_MODE], [], [1900]],
            'aes192-ctr': [['3.7,l10.4.1'], [], [], [], [2100]],
            'aes192-gcm@openssh.com': [[], [], [], [INFO_NEVER_IMPLEMENTED_IN_OPENSSH], [WEIGHT_SSH_NOT_IMP_OR_DISABLED]],
            'aes256-cbc': [['2.3.0,d0.47,l10.2', '6.6', None], [], [WARN_CIPHER_MODE], [], [2800]],
            'aes256-ctr': [['3.7,d0.52,l10.4.1'], [], [], [], [2900]],
            'aes256-gcm': [[], [], [], [], [3300]],
            'aes256-gcm@openssh.com': [['6.2'], [], [], [], [3500]],
            'arcfour128': [['4.2', '6.6', '7.1'], [FAIL_RC4], [], [], [WEIGHT_FAIL]],
            'arcfour': [['2.1.0', '6.6', '7.1'], [FAIL_RC4], [], [], [WEIGHT_FAIL]],
            'arcfour256': [['4.2', '6.6', '7.1'], [FAIL_RC4], [], [], [WEIGHT_FAIL]],
            'blowfish-cbc': [['1.2.2,d0.28,l10.2', '6.6,d0.52', '7.1,d0.52'], [FAIL_BLOWFISH], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE], [], [WEIGHT_FAIL]],
            'blowfish-cfb': [[], [FAIL_BLOWFISH], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'blowfish-ctr': [[], [FAIL_BLOWFISH], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE], [], [WEIGHT_FAIL]],
            'blowfish-ecb': [[], [FAIL_BLOWFISH], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'blowfish': [[], [FAIL_BLOWFISH], [WARN_BLOCK_SIZE], [], [WEIGHT_FAIL]],
            'blowfish-ofb': [[], [FAIL_BLOWFISH], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'camellia128-cbc@openssh.org': [[], [], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'camellia128-cbc': [[], [], [WARN_CIPHER_MODE], [], [1900]],
            'camellia128-ctr': [[], [], [], [], [1925]],
            'camellia128-ctr@openssh.org': [[], [], [], [], [1950]],
            'camellia192-cbc@openssh.org': [[], [], [WARN_CIPHER_MODE], [], [1975]],
            'camellia192-cbc': [[], [], [WARN_CIPHER_MODE], [], [2000]],
            'camellia192-ctr': [[], [], [], [], [2025]],
            'camellia192-ctr@openssh.org': [[], [], [], [], [2050]],
            'camellia256-cbc@openssh.org': [[], [], [WARN_CIPHER_MODE], [], [2100]],
            'camellia256-cbc': [[], [], [WARN_CIPHER_MODE], [], [2125]],
            'camellia256-ctr': [[], [], [], [], [2200]],
            'camellia256-ctr@openssh.org': [[], [], [], [], [2250]],
            'cast128-12-cbc@ssh.com': [[], [FAIL_CAST], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'cast128-cbc': [['2.1.0', '6.6', '7.1'], [FAIL_CAST], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE], [], [WEIGHT_FAIL]],
            'cast128-12-cbc': [[], [FAIL_CAST], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'cast128-12-cfb': [[], [FAIL_CAST], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'cast128-12-ecb': [[], [FAIL_CAST], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'cast128-12-ofb': [[], [FAIL_CAST], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'cast128-cfb': [[], [FAIL_CAST], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'cast128-ctr': [[], [FAIL_CAST],[] ,[], [WEIGHT_FAIL]],
            'cast128-ecb': [[], [FAIL_CAST], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'cast128-ofb': [[], [FAIL_CAST], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'chacha20-poly1305': [[], [], [], [INFO_DEFAULT_OPENSSH_CIPHER], [WEIGHT_CHACHA]],
            'chacha20-poly1305@openssh.com': [['6.5,d2020.79'], [], [], [INFO_DEFAULT_OPENSSH_CIPHER], [WEIGHT_CHACHA]],
            'crypticore128@ssh.com': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],
            'des-cbc': [[], [FAIL_DES], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE], [], [WEIGHT_FAIL]],
            'des-cfb': [[], [FAIL_DES], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE], [], [WEIGHT_FAIL]],
            'des-ecb': [[], [FAIL_DES], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE], [], [WEIGHT_FAIL]],
            'des-ofb': [[], [FAIL_DES], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE], [], [WEIGHT_FAIL]],
            'des-cbc-ssh1': [[], [FAIL_DES], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE], [], [WEIGHT_FAIL]],
            'des-cbc@ssh.com': [[], [FAIL_DES], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE], [], [WEIGHT_FAIL]],
            'des': [[], [FAIL_DES], [WARN_CIPHER_MODE, WARN_BLOCK_SIZE], [], [WEIGHT_FAIL]],
            'idea-cbc': [[], [FAIL_IDEA], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'idea-cfb': [[], [FAIL_IDEA], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'idea-ctr': [[], [FAIL_IDEA], [], [], [WEIGHT_FAIL]],
            'idea-ecb': [[], [FAIL_IDEA], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'idea-ofb': [[], [FAIL_IDEA], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'none': [['1.2.2,d2013.56,l10.2'], [FAIL_PLAINTEXT], [], [], [WEIGHT_FAIL]],
            'rijndael128-cbc': [['2.3.0', '7.0'], [FAIL_RIJNDAEL], [WARN_CIPHER_MODE], [INFO_DISABLED_IN_OPENSSH70], [WEIGHT_FAIL]],
            'rijndael192-cbc': [['2.3.0', '7.0'], [FAIL_RIJNDAEL], [WARN_CIPHER_MODE], [INFO_DISABLED_IN_OPENSSH70], [WEIGHT_FAIL]],
            'rijndael256-cbc': [['2.3.0', '7.0'], [FAIL_RIJNDAEL], [WARN_CIPHER_MODE], [INFO_DISABLED_IN_OPENSSH70], [WEIGHT_FAIL]],
            'rijndael-cbc@lysator.liu.se': [['2.3.0', '6.6', '7.0'], [FAIL_RIJNDAEL], [WARN_CIPHER_MODE], [INFO_DISABLED_IN_OPENSSH70], [WEIGHT_FAIL]],
            'rijndael-cbc@ssh.com': [[], [FAIL_RIJNDAEL], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'seed-cbc@ssh.com': [[], [FAIL_SEED], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'seed-ctr@ssh.com': [[], [FAIL_SEED], [], [], [WEIGHT_FAIL]],
            'serpent128-cbc': [[], [FAIL_SERPENT], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'serpent128-ctr': [[], [FAIL_SERPENT], [], [], [WEIGHT_FAIL]],
            'serpent128-gcm@libassh.org': [[], [FAIL_SERPENT], [], [], [WEIGHT_FAIL]],
            'serpent192-cbc': [[], [FAIL_SERPENT], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'serpent192-ctr': [[], [FAIL_SERPENT], [], [], [WEIGHT_FAIL]],
            'serpent256-cbc': [[], [FAIL_SERPENT], [WARN_CIPHER_MODE], [], [WEIGHT_FAIL]],
            'serpent256-ctr': [[], [FAIL_SERPENT], [], [], [WEIGHT_FAIL]],
            'serpent256-gcm@libassh.org': [[], [FAIL_SERPENT], [], [], [WEIGHT_FAIL]],
            'twofish128-cbc': [['d0.47', 'd2014.66'], [], [WARN_CIPHER_MODE], [INFO_DISABLED_IN_DBEAR67], [WEIGHT_DISABLED]],
            'twofish128-ctr': [['d2015.68'], [], [], [], [1500]],
            'twofish128-gcm@libassh.org': [[], [], [], [], [1550]],
            'twofish192-cbc': [[], [], [WARN_CIPHER_MODE], [], [1600]],
            'twofish192-ctr': [[], [], [], [], [1650]],
            'twofish256-cbc': [['d0.47', 'd2014.66'], [], [WARN_CIPHER_MODE], [INFO_DISABLED_IN_DBEAR67], [WEIGHT_DISABLED]],
            'twofish256-ctr': [['d2015.68'], [], [], [], [1700]],
            'twofish256-gcm@libassh.org': [[], [], [], [], [1800]],
            'twofish-cbc': [['d0.28', 'd2014.66'], [], [WARN_CIPHER_MODE], [INFO_DISABLED_IN_DBEAR67], [WEIGHT_DISABLED]],
            'twofish-cfb': [[], [], [WARN_CIPHER_MODE], [], [1500]],
            'twofish-ctr': [[], [], [], [], [1500]],
            'twofish-ecb': [[], [], [WARN_CIPHER_MODE], [], [1500]],
            'twofish-ofb': [[], [], [WARN_CIPHER_MODE], [], [1500]],
        },
        'mac': {
            'AEAD_AES_128_GCM': [[], [], [], [], [4000]],
            'AEAD_AES_256_GCM': [[], [], [], [], [5100]],
            'aes128-gcm': [[], [], [], [], [4000]],
            'aes256-gcm': [[], [], [], [], [5200]],
            'cbcmac-3des': [[], [FAIL_UNPROVEN, FAIL_3DES], [], [], [WEIGHT_FAIL]],
            'cbcmac-aes': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],
            'cbcmac-blowfish': [[], [FAIL_UNPROVEN, FAIL_BLOWFISH], [], [], [WEIGHT_FAIL]],
            'cbcmac-des': [[], [FAIL_UNPROVEN, FAIL_DES], [], [], [WEIGHT_FAIL]],
            'cbcmac-rijndael': [[], [FAIL_UNPROVEN, FAIL_RIJNDAEL], [], [], [WEIGHT_FAIL]],
            'cbcmac-twofish': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],
            'chacha20-poly1305@openssh.com': [[], [], [], [INFO_NEVER_IMPLEMENTED_IN_OPENSSH], [WEIGHT_SSH_NOT_IMP_OR_DISABLED]],  # Despite the @openssh.com tag, this was never shipped as a MAC in OpenSSH (only as a cipher); it is only implemented as a MAC in Syncplify.
            'crypticore-mac@ssh.com': [[], [FAIL_UNPROVEN], [], [], [WEIGHT_FAIL]],
            'hmac-md5': [['2.1.0,d0.28', '6.6', '7.1'], [FAIL_MD5], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_FAIL]],
            'hmac-md5-96': [['2.5.0', '6.6', '7.1'], [FAIL_MD5], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_FAIL]],
            'hmac-md5-96-etm@openssh.com': [['6.2', '6.6', '7.1'], [FAIL_MD5], [], [], [WEIGHT_FAIL]],
            'hmac-md5-etm@openssh.com': [['6.2', '6.6', '7.1'], [FAIL_MD5], [], [], [WEIGHT_FAIL]],
            'hmac-ripemd160': [['2.5.0', '6.6', '7.1'], [FAIL_RIPEMD], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_FAIL]],
            'hmac-ripemd160-96': [[], [FAIL_RIPEMD], [WARN_ENCRYPT_AND_MAC, WARN_TAG_SIZE], [], [WEIGHT_FAIL]],
            'hmac-ripemd160-etm@openssh.com': [['6.2', '6.6', '7.1'], [FAIL_RIPEMD], [], [], [WEIGHT_FAIL]],
            'hmac-ripemd160@openssh.com': [['2.1.0', '6.6', '7.1'], [FAIL_RIPEMD], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_FAIL]],
            'hmac-ripemd': [[], [FAIL_RIPEMD], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_FAIL]],
            'hmac-sha1': [['2.1.0,d0.28,l10.2'], [FAIL_SHA1], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_FAIL]],
            'hmac-sha1-96': [['2.5.0,d0.47', '6.6', '7.1'], [FAIL_SHA1], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_FAIL]],
            'hmac-sha1-96-etm@openssh.com': [['6.2', '6.6', None], [FAIL_SHA1], [], [], [WEIGHT_FAIL]],
            'hmac-sha1-96@openssh.com': [[], [FAIL_SHA1], [WARN_TAG_SIZE, WARN_ENCRYPT_AND_MAC], [INFO_NEVER_IMPLEMENTED_IN_OPENSSH], [WEIGHT_FAIL]],
            'hmac-sha1-etm@openssh.com': [['6.2'], [FAIL_SHA1], [], [], [WEIGHT_FAIL]],
            'hmac-sha2-224': [[], [], [WARN_TAG_SIZE, WARN_ENCRYPT_AND_MAC], [], [WEIGHT_EAM]],
            'hmac-sha224@ssh.com': [[], [], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_EAM]],
            'hmac-sha2-256': [['5.9,d2013.56,l10.7.0'], [], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_EAM]],
            'hmac-sha2-256-96': [['5.9', '6.0'], [], [WARN_ENCRYPT_AND_MAC], [INFO_REMOVED_IN_OPENSSH61], [WEIGHT_EAM]],
            'hmac-sha2-256-96-etm@openssh.com': [[], [], [WARN_TAG_SIZE_96], [INFO_NEVER_IMPLEMENTED_IN_OPENSSH], [WEIGHT_EAM]],  # Only ever implemented in AsyncSSH (?).
            'hmac-sha2-256-etm@openssh.com': [['6.2'], [], [], [], [WEIGHT_FAIL]],
            'hmac-sha2-384': [[], [], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_EAM]],
            'hmac-sha2-512': [['5.9,d2013.56,l10.7.0'], [], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_EAM]],
            'hmac-sha2-512-96': [['5.9', '6.0'], [], [WARN_ENCRYPT_AND_MAC], [INFO_REMOVED_IN_OPENSSH61], [WEIGHT_EAM]],
            'hmac-sha2-512-96-etm@openssh.com': [[], [], [WARN_TAG_SIZE_96], [INFO_NEVER_IMPLEMENTED_IN_OPENSSH], [WEIGHT_EAM]],  # Only ever implemented in AsyncSSH (?).
            'hmac-sha2-512-etm@openssh.com': [['6.2'], [], [], [], [150]],
            'hmac-sha256-2@ssh.com': [[], [], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_EAM]],
            'hmac-sha256-96@ssh.com': [[], [], [WARN_ENCRYPT_AND_MAC, WARN_TAG_SIZE], [], [WEIGHT_EAM]],
            'hmac-sha256-96': [[], [], [WARN_ENCRYPT_AND_MAC, WARN_TAG_SIZE], [], [WEIGHT_EAM]],
            'hmac-sha256@ssh.com': [[], [], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_EAM]],
            'hmac-sha256': [[], [], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_EAM]],
            'hmac-sha2-56': [[], [], [WARN_TAG_SIZE, WARN_ENCRYPT_AND_MAC], [], [WEIGHT_EAM]],
            'hmac-sha3-224': [[], [], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_EAM]],
            'hmac-sha3-256': [[], [], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_EAM]],
            'hmac-sha3-384': [[], [], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_EAM]],
            'hmac-sha3-512': [[], [], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_EAM]],
            'hmac-sha384@ssh.com': [[], [], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_EAM]],
            'hmac-sha512@ssh.com': [[], [], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_EAM]],
            'hmac-sha512': [[], [], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_EAM]],
            'hmac-whirlpool': [[], [], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_EAM]],
            'md5':  [[], [FAIL_PLAINTEXT], [], [], [WEIGHT_FAIL]],
            'md5-8':  [[], [FAIL_PLAINTEXT], [], [], [WEIGHT_FAIL]],
            'none': [['d2013.56'], [FAIL_PLAINTEXT], [], [], [WEIGHT_FAIL]],
            'ripemd160':  [[], [FAIL_PLAINTEXT], [], [], [WEIGHT_FAIL]],
            'ripemd160-8':  [[], [FAIL_PLAINTEXT], [], [], [WEIGHT_FAIL]],
            'sha1':  [[], [FAIL_PLAINTEXT], [], [], [WEIGHT_FAIL]],
            'sha1-8':  [[], [FAIL_PLAINTEXT], [], [], [WEIGHT_FAIL]],
            'umac-128': [[], [], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_EAM]],
            'umac-128-etm@openssh.com': [['6.2'], [], [], [], [1500]],
            'umac-128@openssh.com': [['6.2'], [], [WARN_ENCRYPT_AND_MAC], [], [WEIGHT_EAM]],
            'umac-32@openssh.com': [[], [], [WARN_ENCRYPT_AND_MAC, WARN_TAG_SIZE], [INFO_NEVER_IMPLEMENTED_IN_OPENSSH], [WEIGHT_EAM]],
            'umac-64-etm@openssh.com': [['6.2'], [], [WARN_TAG_SIZE],[] ,[WEIGHT_EAM]],
            'umac-64@openssh.com': [['4.7'], [], [WARN_ENCRYPT_AND_MAC, WARN_TAG_SIZE], [], [WEIGHT_EAM]],
            'umac-96@openssh.com': [[], [], [WARN_ENCRYPT_AND_MAC], [INFO_NEVER_IMPLEMENTED_IN_OPENSSH],[WEIGHT_EAM]],
        }
    }


    @staticmethod
    def get_db() -> Dict[str, Dict[str, List[List[Optional[str]]]]]:
        '''Returns a copy of the MASTER_DB that is private to the calling thread.  This prevents multiple threads from polluting the results of other threads.'''
        calling_thread_id = threading.get_ident()

        if calling_thread_id not in SSH2_KexDB.DB_PER_THREAD:
            SSH2_KexDB.DB_PER_THREAD[calling_thread_id] = copy.deepcopy(SSH2_KexDB.MASTER_DB)

        return SSH2_KexDB.DB_PER_THREAD[calling_thread_id]


    @staticmethod
    def thread_exit() -> None:
        '''Deletes the calling thread's copy of the MASTER_DB.  This is needed because, in rare circumstances, a terminated thread's ID can be re-used by new threads.'''

        calling_thread_id = threading.get_ident()

        if calling_thread_id in SSH2_KexDB.DB_PER_THREAD:
            del SSH2_KexDB.DB_PER_THREAD[calling_thread_id]

#!/usr/bin/env python3
"""
   The MIT License (MIT)

   Copyright (C) 2017-2025 Joe Testa (jtesta@positronsecurity.com)
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
import argparse
import concurrent.futures
import copy
import json
import multiprocessing
import os
import re
import sys
import traceback


# pylint: disable=unused-import
from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import cast, Callable, Optional, Union, Any  # noqa: F401

from ssh_audit.globals import SNAP_PACKAGE
from ssh_audit.globals import SNAP_PERMISSIONS_ERROR
from ssh_audit.globals import VERSION
from ssh_audit.globals import BUILTIN_MAN_PAGE
from ssh_audit.algorithm import Algorithm
from ssh_audit.algorithms import Algorithms
from ssh_audit.auditconf import AuditConf
from ssh_audit.banner import Banner
from ssh_audit.dheat import DHEat
from ssh_audit import exitcodes
from ssh_audit.fingerprint import Fingerprint
from ssh_audit.gextest import GEXTest
from ssh_audit.hostkeytest import HostKeyTest
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.policy import Policy
from ssh_audit.product import Product
from ssh_audit.protocol import Protocol
from ssh_audit.software import Software
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexdb import SSH2_KexDB
from ssh_audit.ssh_socket import SSH_Socket
from ssh_audit.utils import Utils


# no_idna_workaround = False

# Only import colorama under Windows.  Other OSes can natively handle terminal colors.
if sys.platform == 'win32':
    try:
        from colorama import just_fix_windows_console  # type: ignore
        just_fix_windows_console()
    except ImportError:
        pass

    # This is a workaround for a Python bug that causes a crash on Windows when multiple threads are used (see https://github.com/python/cpython/issues/73474).  Importing the idna module and using it in a no-op seems to fix the issue.  Otherwise, if idna isn't available at run-time, force single threaded scans.
    # try:
    #     import idna  # noqa: F401
    #
    #     ''.encode('idna')
    # except ImportError:
    #     no_idna_workaround = True


def output_algorithms(out: OutputBuffer, title: str, alg_db: Dict[str, Dict[str, List[List[Optional[str]]]]], alg_type: str, algorithms: List[str], unknown_algs: List[str], is_json_output: bool, program_retval: int, maxlen: int = 0, host_keys: Optional[Dict[str, Dict[str, Union[bytes, str, int]]]] = None, dh_modulus_sizes: Optional[Dict[str, int]] = None) -> int:  # pylint: disable=too-many-arguments
    with out:
        for algorithm in algorithms:
            program_retval = output_algorithm(out, alg_db, alg_type, algorithm, unknown_algs, program_retval, maxlen, host_keys=host_keys, dh_modulus_sizes=dh_modulus_sizes)
    if not out.is_section_empty() and not is_json_output:
        out.head('# ' + title)
        out.flush_section()
        out.sep()

    return program_retval


def output_algorithm(out: OutputBuffer, alg_db: Dict[str, Dict[str, List[List[Optional[str]]]]], alg_type: str, alg_name: str, unknown_algs: List[str], program_retval: int, alg_max_len: int = 0, host_keys: Optional[Dict[str, Dict[str, Union[bytes, str, int]]]] = None, dh_modulus_sizes: Optional[Dict[str, int]] = None) -> int:  # pylint: disable=too-many-arguments
    prefix = '(' + alg_type + ') '
    if alg_max_len == 0:
        alg_max_len = len(alg_name)
    padding = '' if out.batch else ' ' * (alg_max_len - len(alg_name))

    # If this is an RSA host key or DH GEX, append the size to its name and fix
    # the padding.
    alg_name_with_size = None
    if (dh_modulus_sizes is not None) and (alg_name in dh_modulus_sizes):
        alg_name_with_size = '%s (%u-bit)' % (alg_name, dh_modulus_sizes[alg_name])
        padding = padding[0:-11]
    elif (host_keys is not None) and (alg_name in host_keys):
        hostkey_size = cast(int, host_keys[alg_name]['hostkey_size'])
        ca_key_type = cast(str, host_keys[alg_name]['ca_key_type'])
        ca_key_size = cast(int, host_keys[alg_name]['ca_key_size'])

        # If this is an RSA variant, just print "RSA".
        if ca_key_type in HostKeyTest.RSA_FAMILY:
            ca_key_type = "RSA"

        if len(ca_key_type) > 0 and ca_key_size > 0:
            alg_name_with_size = '%s (%u-bit cert/%u-bit %s CA)' % (alg_name, hostkey_size, ca_key_size, ca_key_type)
            padding = padding[0:-15]
        elif alg_name in HostKeyTest.RSA_FAMILY:
            alg_name_with_size = '%s (%u-bit)' % (alg_name, hostkey_size)
            padding = padding[0:-11]

    # If this is a kex algorithm and starts with 'gss-', then normalize its name (i.e.: 'gss-gex-sha1-vz8J1E9PzLr8b1K+0remTg==' => 'gss-gex-sha1-*').  The base64 field can vary, so we'll convert it to the wildcard that our database uses and we'll just resume doing a straight match like all other algorithm names.
    alg_name_original = alg_name
    if alg_type == 'kex' and alg_name.startswith('gss-'):
        last_dash = alg_name.rindex('-')
        alg_name = "%s-*" % alg_name[0:last_dash]

    texts = []
    if len(alg_name.strip()) == 0:
        return program_retval
    alg_name_native = Utils.to_text(alg_name)
    if alg_name_native in alg_db[alg_type]:
        alg_desc = alg_db[alg_type][alg_name_native]
        ldesc = len(alg_desc)
        for idx, level in enumerate(['fail', 'warn', 'info']):
            if level == 'info':
                versions = alg_desc[0]
                since_text = Algorithm.get_since_text(versions)
                if since_text is not None and len(since_text) > 0:
                    texts.append((level, since_text))
            idx = idx + 1
            if ldesc > idx:
                for t in alg_desc[idx]:
                    if t is None:
                        continue
                    texts.append((level, t))
        if len(texts) == 0:
            texts.append(('info', ''))
    else:
        texts.append(('warn', 'unknown algorithm'))
        unknown_algs.append(alg_name)

    # For kex GSS algorithms, now that we already did the database lookup (above), restore the original algorithm name so its reported properly in the output.
    if alg_name != alg_name_original:
        alg_name = alg_name_original

    alg_name = alg_name_with_size if alg_name_with_size is not None else alg_name
    first = True
    use_good_for_all = False
    for level, text in texts:
        if level == 'fail':
            program_retval = exitcodes.FAILURE
        elif level == 'warn' and program_retval != exitcodes.FAILURE:  # If a failure was found previously, don't downgrade to warning.
            program_retval = exitcodes.WARNING

        f = getattr(out, level)
        comment = (padding + ' -- [' + level + '] ' + text) if text != '' else ''

        # If the first algorithm's comment is an 'info', this implies that it is rated good.  Hence, the out.good() function should be used to write all subsequent notes for this algorithm as well.
        if (first and level == 'info') or use_good_for_all:
            f = out.good
            use_good_for_all = True

        if first:
            f(prefix + alg_name + comment)
            first = False
        else:  # pylint: disable=else-if-used
            if out.verbose:
                f(prefix + alg_name + comment)
            elif text != '':
                comment = padding + ' `- [' + level + '] ' + text
                f(' ' * len(prefix + alg_name) + comment)

    return program_retval


def output_compatibility(out: OutputBuffer, algs: Algorithms, client_audit: bool, for_server: bool = True) -> None:

    # Don't output any compatibility info if we're doing a client audit.
    if client_audit:
        return

    ssh_timeframe = algs.get_ssh_timeframe(for_server)
    comp_text = []
    for ssh_prod in [Product.OpenSSH, Product.DropbearSSH]:
        if ssh_prod not in ssh_timeframe:
            continue
        v_from = ssh_timeframe.get_from(ssh_prod, for_server)
        v_till = ssh_timeframe.get_till(ssh_prod, for_server)
        if v_from is None:
            continue
        if v_till is None:
            comp_text.append('{} {}+'.format(ssh_prod, v_from))
        elif v_from == v_till:
            comp_text.append('{} {}'.format(ssh_prod, v_from))
        else:
            software = Software(None, ssh_prod, v_from, None, None)
            if software.compare_version(v_till) > 0:
                tfmt = '{0} {1}+ (some functionality from {2})'
            else:
                tfmt = '{0} {1}-{2}'
            comp_text.append(tfmt.format(ssh_prod, v_from, v_till))
    if len(comp_text) > 0:
        out.good('(gen) compatibility: ' + ', '.join(comp_text))


def output_security(out: OutputBuffer, banner: Optional[Banner], padlen: int, is_json_output: bool) -> None:

    with out:
        if (banner is not None) and (banner.protocol[0] == 1):
            p = '' if out.batch else ' ' * (padlen - 14)
            out.fail('(sec) SSH v1 enabled{} -- SSH v1 can be exploited to recover plaintext passwords'.format(p))

    if not out.is_section_empty() and not is_json_output:
        out.head('# security')
        out.flush_section()
        out.sep()


def output_fingerprints(out: OutputBuffer, algs: Algorithms, is_json_output: bool) -> None:
    with out:
        fps = {}
        if algs.ssh2kex is not None:
            host_keys = algs.ssh2kex.host_keys()
            for host_key_type in algs.ssh2kex.host_keys():
                if host_keys[host_key_type] is None:
                    continue

                fp = Fingerprint(cast(bytes, host_keys[host_key_type]['raw_hostkey_bytes']))

                # Workaround for Python's order-indifference in dicts.  We might get a random RSA type (ssh-rsa, rsa-sha2-256, or rsa-sha2-512), so running the tool against the same server three times may give three different host key types here.  So if we have any RSA type, we will simply hard-code it to 'ssh-rsa'.
                if host_key_type in HostKeyTest.RSA_FAMILY:
                    host_key_type = 'ssh-rsa'

                # Skip over certificate host types (or we would return invalid fingerprints), and only add one fingerprint in the RSA family.
                if '-cert-' not in host_key_type:
                    fps[host_key_type] = fp
        # Similarly, the host keys can be processed in random order due to Python's order-indifference in dicts.  So we sort this list before printing; this makes automated testing possible.
        fp_types = sorted(fps.keys())
        for fp_type in fp_types:
            fp = fps[fp_type]

            # Don't output any ECDSA or DSS fingerprints unless verbose mode is enabled.
            if fp_type.startswith("ecdsa-") or (fp_type == "ssh-dss"):
                if out.verbose:
                    out.warn('(fin) {}: {} -- [info] this fingerprint type is insecure and should not be relied upon'.format(fp_type, fp.sha256))
                else:
                    continue  # If verbose mode is not enabled, skip this type entirely.
            else:
                out.good('(fin) {}: {}'.format(fp_type, fp.sha256))

            # Output the MD5 hash too if verbose mode is enabled.
            if out.verbose:
                out.warn('(fin) {}: {} -- [info] do not rely on MD5 fingerprints for server identification; it is insecure for this use case'.format(fp_type, fp.md5))

    if not out.is_section_empty() and not is_json_output:
        out.head('# fingerprints')
        out.flush_section()
        out.sep()


# Returns True if no warnings or failures encountered in configuration.
def output_recommendations(out: OutputBuffer, algs: Algorithms, algorithm_recommendation_suppress_list: List[str], software: Optional[Software], is_json_output: bool, padlen: int = 0) -> bool:

    ret = True
    level_to_output = {
        "informational": out.good,
        "warning": out.warn,
        "critical": out.fail
    }

    with out:
        recommendations = get_algorithm_recommendations(algs, algorithm_recommendation_suppress_list, software, for_server=True)

        for level in recommendations:  # pylint: disable=consider-using-dict-items
            for action in recommendations[level]:
                for alg_type in recommendations[level][action]:
                    for alg_name_and_notes in recommendations[level][action][alg_type]:
                        name = alg_name_and_notes['name']
                        notes = alg_name_and_notes['notes']

                        p = '' if out.batch else ' ' * (padlen - len(name))

                        fn = level_to_output[level]

                        an = '?'
                        sg = '?'
                        if action == 'del':
                            an, sg = 'remove', '-'
                            ret = False
                        elif action == 'add':
                            an, sg = 'append', '+'
                        elif action == 'chg':
                            an, sg = 'change', '!'
                            ret = False

                        if notes != '':
                            notes = " (%s)" % notes

                        fm = '(rec) {0}{1}{2}-- {3} algorithm to {4}{5} '
                        fn(fm.format(sg, name, p, alg_type, an, notes))  # type: ignore[operator]

    if not out.is_section_empty() and not is_json_output:
        if software is not None:
            title = '(for {})'.format(software.display(False))
        else:
            title = ''
        out.head('# algorithm recommendations {}'.format(title))
        out.flush_section(sort_section=True)  # Sort the output so that it is always stable (needed for repeatable testing).
        out.sep()
    return ret


# Output additional information & notes.
def output_info(out: OutputBuffer, software: Optional['Software'], client_audit: bool, any_problems: bool, is_json_output: bool, additional_notes: List[str]) -> None:
    with out:
        # Tell user that PuTTY cannot be hardened at the protocol-level.
        if client_audit and (software is not None) and (software.product == Product.PuTTY):
            out.warn('(nfo) PuTTY does not have the option of restricting any algorithms during the SSH handshake.')

        # If any warnings or failures were given, print a link to the hardening guides.
        if any_problems:
            out.warn('(nfo) For hardening guides on common OSes, please see: <https://www.ssh-audit.com/hardening_guides.html>')

        # Add any additional notes.
        for additional_note in additional_notes:
            if len(additional_note) > 0:
                out.warn("(nfo) %s" % additional_note)

    if not out.is_section_empty() and not is_json_output:
        out.head('# additional info')
        out.flush_section()
        out.sep()


def post_process_findings(banner: Optional[Banner], algs: Algorithms, client_audit: bool, dh_rate_test_notes: str) -> Tuple[List[str], List[str]]:
    '''Perform post-processing on scan results before reporting them to the user.  Returns a list of algorithms that should not be recommended and a list of notes.'''

    def _add_terrapin_warning(db: Dict[str, Dict[str, List[List[Optional[str]]]]], category: str, algorithm_name: str) -> None:
        '''Adds a warning regarding the Terrapin vulnerability for the specified algorithm.'''
        # Ensure that a slot for warnings exists for this algorithm.
        while len(db[category][algorithm_name]) < 3:
            db[category][algorithm_name].append([])

        db[category][algorithm_name][2].append("vulnerable to the Terrapin attack (CVE-2023-48795), allowing message prefix truncation")

    def _get_chacha_ciphers_enabled(algs: Algorithms) -> List[str]:
        '''Returns a list of chacha20-poly1305 ciphers that the peer supports.'''
        ret = []

        if algs.ssh2kex is not None:
            ciphers_supported = algs.ssh2kex.client.encryption if client_audit else algs.ssh2kex.server.encryption
            for cipher in ciphers_supported:
                if cipher.startswith("chacha20-poly1305"):
                    ret.append(cipher)

        return ret

    def _get_chacha_ciphers_not_enabled(db: Dict[str, Dict[str, List[List[Optional[str]]]]], algs: Algorithms) -> List[str]:
        '''Returns a list of all chacha20-poly1305 in our algorithm database.'''
        ret = []

        for cipher in db["enc"]:
            if cipher.startswith("chacha20-poly1305") and cipher not in _get_chacha_ciphers_enabled(algs):
                ret.append(cipher)

        return ret

    def _get_cbc_ciphers_enabled(algs: Algorithms) -> List[str]:
        '''Returns a list of CBC ciphers that the peer supports.'''
        ret = []

        if algs.ssh2kex is not None:
            ciphers_supported = algs.ssh2kex.client.encryption if client_audit else algs.ssh2kex.server.encryption
            for cipher in ciphers_supported:
                if cipher.endswith("-cbc") or cipher.endswith("-cbc@openssh.org") or cipher.endswith("-cbc@ssh.com") or cipher == "rijndael-cbc@lysator.liu.se":
                    ret.append(cipher)

        return ret

    def _get_cbc_ciphers_not_enabled(db: Dict[str, Dict[str, List[List[Optional[str]]]]], algs: Algorithms) -> List[str]:
        '''Returns a list of all CBC ciphers in our algorithm database.'''
        ret = []

        for cipher in db["enc"]:
            if (cipher.endswith("-cbc") or cipher.endswith("-cbc@openssh.org") or cipher.endswith("-cbc@ssh.com") or cipher == "rijndael-cbc@lysator.liu.se") and cipher not in _get_cbc_ciphers_enabled(algs):
                ret.append(cipher)

        return ret

    def _get_etm_macs_enabled(algs: Algorithms) -> List[str]:
        '''Returns a list of ETM MACs that the peer supports.'''
        ret = []

        if algs.ssh2kex is not None:
            macs_supported = algs.ssh2kex.client.mac if client_audit else algs.ssh2kex.server.mac
            for mac in macs_supported:
                if mac.endswith("-etm@openssh.com"):
                    ret.append(mac)

        return ret

    def _get_etm_macs_not_enabled(db: Dict[str, Dict[str, List[List[Optional[str]]]]], algs: Algorithms) -> List[str]:
        '''Returns a list of ETM MACs in our algorithm database.'''
        ret = []

        for mac in db["mac"]:
            if mac.endswith("-etm@openssh.com") and mac not in _get_etm_macs_enabled(algs):
                ret.append(mac)

        return ret


    algorithm_recommendation_suppress_list = []
    algs_to_note = []


    #
    # Post-processing of the OpenSSH diffie-hellman-group-exchange-sha256 fallback mechanism bug/feature.
    #

    # If the server is OpenSSH, and the diffie-hellman-group-exchange-sha256 key exchange was found with modulus size 2048, add a note regarding the bug that causes the server to support 2048-bit moduli no matter the configuration.
    if (algs.ssh2kex is not None and 'diffie-hellman-group-exchange-sha256' in algs.ssh2kex.kex_algorithms and 'diffie-hellman-group-exchange-sha256' in algs.ssh2kex.dh_modulus_sizes() and algs.ssh2kex.dh_modulus_sizes()['diffie-hellman-group-exchange-sha256'] == 2048) and (banner is not None and banner.software is not None and banner.software.find('OpenSSH') != -1):

        # Ensure a list for notes exists.
        db = SSH2_KexDB.get_db()
        while len(db['kex']['diffie-hellman-group-exchange-sha256']) < 4:
            db['kex']['diffie-hellman-group-exchange-sha256'].append([])

        db['kex']['diffie-hellman-group-exchange-sha256'][3].append("A bug in OpenSSH causes it to fall back to a 2048-bit modulus regardless of server configuration (https://bugzilla.mindrot.org/show_bug.cgi?id=2793)")

        # Ensure that this algorithm doesn't appear in the recommendations section since the user cannot control this OpenSSH bug.
        algorithm_recommendation_suppress_list.append('diffie-hellman-group-exchange-sha256')

    # Check for the Terrapin vulnerability (CVE-2023-48795), and mark the vulnerable algorithms.
    kex_strict_marker = False
    if algs.ssh2kex is not None and \
       ((client_audit and 'kex-strict-c-v00@openssh.com' in algs.ssh2kex.kex_algorithms) or (not client_audit and 'kex-strict-s-v00@openssh.com' in algs.ssh2kex.kex_algorithms)):  # Strict KEX marker is present.
        kex_strict_marker = True

    db = SSH2_KexDB.get_db()


    #
    # Post-processing of algorithms related to the Terrapin vulnerability (CVE-2023-48795).
    #

    # Without the strict KEX marker, the chacha20-poly1305 ciphers are always vulnerable.
    for chacha_cipher in _get_chacha_ciphers_enabled(algs):
        if kex_strict_marker:
            # Inform the user that the target is correctly configured, but another peer may still choose this algorithm without using strict KEX negotiation, which would still result in vulnerability.
            algs_to_note.append(chacha_cipher)
        else:
            _add_terrapin_warning(db, "enc", chacha_cipher)

    cbc_ciphers_enabled = _get_cbc_ciphers_enabled(algs)
    etm_macs_enabled = _get_etm_macs_enabled(algs)

    # Without the strict KEX marker, if at least one CBC cipher and at least one ETM MAC is supported, mark them all as vulnerable.
    if len(cbc_ciphers_enabled) > 0 and len(etm_macs_enabled) > 0:
        for cipher in cbc_ciphers_enabled:
            if kex_strict_marker:
                # Inform the user that the target is correctly configured, but another peer may still choose this algorithm without using strict KEX negotiation, which would still result in vulnerability.
                algs_to_note.append(cipher)
            else:
                _add_terrapin_warning(db, "enc", cipher)

        for mac in etm_macs_enabled:
            if kex_strict_marker:
                # Inform the user that the target is correctly configured, but another peer may still choose this algorithm without using strict KEX negotiation, which would still result in vulnerability.
                algs_to_note.append(mac)
            else:
                _add_terrapin_warning(db, "mac", mac)

    # Return a note telling the user that, while this target is properly configured, if connected to a vulnerable peer, then a vulnerable connection is still possible.
    additional_notes = []
    if len(algs_to_note) > 0:
        additional_notes.append("Be aware that, while this target properly supports the strict key exchange method (via the kex-strict-?-v00@openssh.com marker) needed to protect against the Terrapin vulnerability (CVE-2023-48795), all peers must also support this feature as well, otherwise the vulnerability will still be present.  The following algorithms would allow an unpatched peer to create vulnerable SSH channels with this target: %s.  If any CBC ciphers are in this list, you may remove them while leaving the *-etm@openssh.com MACs in place; these MACs are fine while paired with non-CBC cipher types." % ", ".join(algs_to_note))

    # Add the chacha ciphers, CBC ciphers, and ETM MACs to the recommendation suppression list if they are not enabled on the server.  That way they are not recommended to the user to enable if they were explicitly disabled to handle the Terrapin vulnerability.  However, they can still be recommended for disabling.
    algorithm_recommendation_suppress_list += _get_chacha_ciphers_not_enabled(db, algs)
    algorithm_recommendation_suppress_list += _get_cbc_ciphers_not_enabled(db, algs)
    algorithm_recommendation_suppress_list += _get_etm_macs_not_enabled(db, algs)

    # Append any notes related to the DH rate test.
    if len(dh_rate_test_notes) > 0:
        additional_notes.append(dh_rate_test_notes)

    return algorithm_recommendation_suppress_list, additional_notes


# Returns a exitcodes.* flag to denote if any failures or warnings were encountered.
def output(out: OutputBuffer, aconf: AuditConf, banner: Optional[Banner], header: List[str], client_host: Optional[str] = None, kex: Optional[SSH2_Kex] = None, print_target: bool = False, dh_rate_test_notes: str = "") -> int:

    program_retval = exitcodes.GOOD
    client_audit = client_host is not None  # If set, this is a client audit.
    algs = Algorithms(kex)

    # Perform post-processing on the findings to make final adjustments before outputting the results.
    algorithm_recommendation_suppress_list, additional_notes = post_process_findings(banner, algs, client_audit, dh_rate_test_notes)

    with out:
        if print_target:
            host = aconf.host

            # Print the port if it's not the default of 22.
            if aconf.port != 22:

                # Check if this is an IPv6 address, as that is printed in a different format.
                if Utils.is_ipv6_address(aconf.host):
                    host = '[%s]:%d' % (aconf.host, aconf.port)
                else:
                    host = '%s:%d' % (aconf.host, aconf.port)

            out.good('(gen) target: {}'. format(host), always_print=True)
        if client_audit:
            out.good('(gen) client IP: {}'.format(client_host), always_print=True)
        if len(header) > 0:
            out.info('(gen) header: ' + '\n'.join(header))
        if banner is not None:
            banner_line = '(gen) banner: {}'.format(banner)
            if banner.protocol[0] == 1:
                out.fail(banner_line)
                out.fail('(gen) protocol SSH1 enabled')
            else:
                out.good(banner_line)

            if not banner.valid_ascii:
                # NOTE: RFC 4253, Section 4.2
                out.warn('(gen) banner contains non-printable ASCII')

            software = Software.parse(banner)
            if software is not None:
                out.good('(gen) software: {}'.format(software))
        else:
            software = None
        output_compatibility(out, algs, client_audit)
        if kex is not None:
            compressions = [x for x in kex.server.compression if x != 'none']
            if len(compressions) > 0:
                cmptxt = 'enabled ({})'.format(', '.join(compressions))
            else:
                cmptxt = 'disabled'
            out.good('(gen) compression: {}'.format(cmptxt))
    if not out.is_section_empty() and not aconf.json:  # Print output when it exists and JSON output isn't requested.
        out.head('# general')
        out.flush_section()
        out.sep()
    maxlen = algs.maxlen + 1
    output_security(out, banner, maxlen, aconf.json)
    # Filled in by output_algorithms() with unidentified algs.
    unknown_algorithms: List[str] = []

    # SSHv2
    if kex is not None:
        adb = SSH2_KexDB.get_db()
        title, atype = 'key exchange algorithms', 'kex'
        program_retval = output_algorithms(out, title, adb, atype, kex.kex_algorithms, unknown_algorithms, aconf.json, program_retval, maxlen, dh_modulus_sizes=kex.dh_modulus_sizes())
        title, atype = 'host-key algorithms', 'key'
        program_retval = output_algorithms(out, title, adb, atype, kex.key_algorithms, unknown_algorithms, aconf.json, program_retval, maxlen, host_keys=kex.host_keys())
        title, atype = 'encryption algorithms (ciphers)', 'enc'
        program_retval = output_algorithms(out, title, adb, atype, kex.server.encryption, unknown_algorithms, aconf.json, program_retval, maxlen)
        title, atype = 'message authentication code algorithms', 'mac'
        program_retval = output_algorithms(out, title, adb, atype, kex.server.mac, unknown_algorithms, aconf.json, program_retval, maxlen)

    output_fingerprints(out, algs, aconf.json)
    perfect_config = output_recommendations(out, algs, algorithm_recommendation_suppress_list, software, aconf.json, maxlen)
    output_info(out, software, client_audit, not perfect_config, aconf.json, additional_notes)

    if aconf.json:
        out.reset()
        # Build & write the JSON struct.
        out.info(json.dumps(build_struct(aconf.host + ":" + str(aconf.port), banner, kex=kex, client_host=client_host, software=software, algorithms=algs, algorithm_recommendation_suppress_list=algorithm_recommendation_suppress_list, additional_notes=additional_notes), indent=4 if aconf.json_print_indent else None, sort_keys=True))
    elif len(unknown_algorithms) > 0:  # If we encountered any unknown algorithms, ask the user to report them.
        out.warn("\n\n!!! WARNING: unknown algorithm(s) found!: %s.  If this is the latest version of ssh-audit (see <https://github.com/jtesta/ssh-audit/releases>), please create a new Github issue at <https://github.com/jtesta/ssh-audit/issues> with the full output above.\n" % ','.join(unknown_algorithms))

    return program_retval


def evaluate_policy(out: OutputBuffer, aconf: AuditConf, banner: Optional['Banner'], client_host: Optional[str], kex: Optional['SSH2_Kex'] = None) -> bool:

    if aconf.policy is None:
        raise RuntimeError('Internal error: cannot evaluate against null Policy!')

    passed, error_struct, error_str = aconf.policy.evaluate(banner, kex)
    if aconf.json:
        warnings: List[str] = []
        if aconf.policy.is_outdated_builtin_policy():
            warnings.append("A newer version of this built-in policy is available.")

        json_struct = {'host': aconf.host, 'port': aconf.port, 'policy': aconf.policy.get_name_and_version(), 'passed': passed, 'errors': error_struct, 'warnings': warnings}

        out.info(json.dumps(json_struct, indent=4 if aconf.json_print_indent else None, sort_keys=True))
    else:
        spacing = ''
        if aconf.client_audit:
            out.info("Client IP: %s" % client_host)
            spacing = "   "  # So the fields below line up with 'Client IP: '.
        else:
            host = aconf.host
            if aconf.port != 22:
                # Check if this is an IPv6 address, as that is printed in a different format.
                if Utils.is_ipv6_address(aconf.host):
                    host = '[%s]:%d' % (aconf.host, aconf.port)
                else:
                    host = '%s:%d' % (aconf.host, aconf.port)

            out.info("Host:   %s" % host)
        out.info("Policy: %s%s" % (spacing, aconf.policy.get_name_and_version()))
        out.info("Result: %s" % spacing, line_ended=False)

        # Use these nice unicode characters in the result message, unless we're on Windows (the cmd.exe terminal doesn't display them properly).
        icon_good = "✔ "
        icon_fail = "❌ "
        if Utils.is_windows():
            icon_good = ""
            icon_fail = ""

        if passed:
            out.good("%sPassed" % icon_good)
        else:
            out.fail("%sFailed!" % icon_fail)
            out.warn("\nErrors:\n%s" % error_str)

        # If the user selected an out-dated built-in policy then issue a warning.
        if aconf.policy.is_outdated_builtin_policy():
            out.warn("Note: A newer version of this built-in policy is available.  Use the -L option to view all available versions.")

    return passed


def get_algorithm_recommendations(algs: Optional[Algorithms], algorithm_recommendation_suppress_list: Optional[List[str]], software: Optional[Software], for_server: bool = True) -> Dict[str, Any]:
    '''Returns the algorithm recommendations.'''
    ret: Dict[str, Any] = {}

    if algs is None or software is None:
        return ret

    software, alg_rec = algs.get_recommendations(software, for_server)
    for sshv in range(2, 0, -1):
        if sshv not in alg_rec:
            continue
        for alg_type in ['kex', 'key', 'enc', 'mac']:
            if alg_type not in alg_rec[sshv]:
                continue
            for action in ['del', 'add', 'chg']:
                if action not in alg_rec[sshv][alg_type]:
                    continue

                for name in alg_rec[sshv][alg_type][action]:

                    # If this algorithm should be suppressed, skip it.
                    if algorithm_recommendation_suppress_list is not None and name in algorithm_recommendation_suppress_list:
                        continue

                    level = 'informational'
                    points = alg_rec[sshv][alg_type][action][name]
                    if points >= 10:
                        level = 'critical'
                    elif points >= 1:
                        level = 'warning'

                    if level not in ret:
                        ret[level] = {}

                    if action not in ret[level]:
                        ret[level][action] = {}

                    if alg_type not in ret[level][action]:
                        ret[level][action][alg_type] = []

                    notes = ''
                    if action == 'chg':
                        notes = 'increase modulus size to 3072 bits or larger'

                    ret[level][action][alg_type].append({'name': name, 'notes': notes})

    return ret


def list_policies(out: OutputBuffer, verbose: bool) -> None:
    '''Prints a list of server & client policies.'''

    server_policy_names, client_policy_names = Policy.list_builtin_policies(verbose)

    if len(server_policy_names) > 0:
        out.head('\nServer policies:\n')
        out.info("  * %s" % "\n  * ".join(server_policy_names))

    if len(client_policy_names) > 0:
        out.head('\nClient policies:\n')
        out.info("  * %s" % "\n  * ".join(client_policy_names))

    out.sep()
    if len(server_policy_names) == 0 and len(client_policy_names) == 0:
        out.fail("Error: no built-in policies found!")
    else:
        out.info("\nHint: Use -P and provide the full name of a policy to run a policy scan with.\n")
        out.info("Hint: Use -L -v to see the change log for each policy, as well as previous versions.\n")
        out.info("Note: the general OpenSSH policies apply to the official releases only. OS distributions may back-port changes that cause failures (for example, Debian 11 back-ported the strict KEX mode into their package of OpenSSH v8.4, whereas it was only officially added to OpenSSH v9.6 and later).  In these cases, consider creating a custom policy (-M option).\n")
        out.info("Note: instructions for hardening targets, which correspond to the above policies, can be found at: <https://ssh-audit.com/hardening_guides.html>\n")
    out.write()


def make_policy(aconf: AuditConf, banner: Optional['Banner'], kex: Optional['SSH2_Kex'], client_host: Optional[str]) -> None:

    # Set the source of this policy to the server host if this is a server audit, otherwise set it to the client address.
    source: Optional[str] = aconf.host
    if aconf.client_audit:
        source = client_host

    policy_data = Policy.create(source, banner, kex, aconf.client_audit)

    if aconf.policy_file is None:
        raise RuntimeError('Internal error: cannot write policy file since filename is None!')

    succeeded = False
    err = ''
    try:
        # Open with mode 'x' (creates the file, or fails if it already exist).
        with open(aconf.policy_file, 'x', encoding='utf-8') as f:
            f.write(policy_data)
        succeeded = True
    except FileExistsError:
        err = "Error: file already exists: %s" % aconf.policy_file
    except PermissionError as e:
        # If installed as a Snap package, print a more useful message with potential work-arounds.
        if SNAP_PACKAGE:
            print(SNAP_PERMISSIONS_ERROR)
            sys.exit(exitcodes.UNKNOWN_ERROR)
        else:
            err = "Error: insufficient permissions: %s" % str(e)

    if succeeded:
        print("Wrote policy to %s.  Customize as necessary, then run a policy scan with -P option." % aconf.policy_file)
    else:
        print(err)


def process_commandline(out: OutputBuffer, args: List[str]) -> 'AuditConf':  # pylint: disable=too-many-statements
    # pylint: disable=too-many-branches
    aconf = AuditConf()

    enable_colors = not any(i in args for i in ['--no-colors', '-n'])

    # Disable colors if the NO_COLOR environment variable is set.
    if "NO_COLOR" in os.environ:
        enable_colors = False

    aconf.colors = enable_colors
    out.use_colors = enable_colors

    host: str = ''
    port: int = 22

    parser = argparse.ArgumentParser(description="# {} {}, https://github.com/jtesta/ssh-audit".format(os.path.basename(sys.argv[0]), VERSION), allow_abbrev=False)

    # Add short options to the parser
    parser.add_argument("-4", "--ipv4", action="store_true", dest="ipv4", default=False, help="enable IPv4 (order of precedence)")
    parser.add_argument("-6", "--ipv6", action="store_true", dest="ipv6", default=False, help="enable IPv6 (order of precedence)")
    parser.add_argument("-b", "--batch", action="store_true", dest="batch", default=False, help="batch output")
    parser.add_argument("-c", "--client-audit", action="store_true", dest="client_audit", default=False, help="starts a server on port 2222 to audit client software config (use -p to change port; use -t to change timeout)")
    parser.add_argument("-d", "--debug", action="store_true", dest="debug", default=False, help="enable debugging output")
    parser.add_argument("-g", "--gex-test", action="store", dest="gex_test", metavar="<min1:pref1:max1[,min2:pref2:max2,...]> / <x-y[:step]>", type=str, default=None, help="conducts a very customized Diffie-Hellman GEX modulus size test. Tests an array of minimum, preferred, and maximum values, or a range of values with an optional incremental step amount")
    parser.add_argument("-j", "--json", action="count", dest="json", default=0, help="enable JSON output (use -jj to enable indentation for better readability)")
    parser.add_argument("-l", "--level", action="store", dest="level", type=str, choices=["info", "warn", "fail"], default="info", help="minimum output level (default: %(default)s)")
    parser.add_argument("-L", "--list-policies", action="store_true", dest="list_policies", default=False, help="list all the official, built-in policies. Combine with -v to view policy change logs")
    parser.add_argument("-M", "--make-policy", action="store", dest="make_policy", metavar="custom_policy.txt", type=str, default=None, help="creates a policy based on the target server (i.e.: the target server has the ideal configuration that other servers should adhere to), and stores it in the file path specified")
    parser.add_argument("-m", "--manual", action="store_true", dest="manual", default=False, help="print the man page (Docker, PyPI, Snap, and Windows builds only)")
    parser.add_argument("-n", "--no-colors", action="store_true", dest="no_colors", default=False, help="disable colors (automatic when the NO_COLOR environment variable is set)")
    parser.add_argument("-P", "--policy", action="store", dest="policy", metavar="\"Built-In Policy Name\" / custom_policy.txt", type=str, default=None, help="run a policy test using the specified policy (use -L to see built-in policies, or specify filesystem path to custom policy created by -M)")
    parser.add_argument("-p", "--port", action="store", dest="oport", metavar="N", type=int, default=None, help="the TCP port to connect to (or to listen on when -c is used)")
    parser.add_argument("-T", "--targets", action="store", dest="targets", metavar="targets.txt", type=str, default=None, help="a file containing a list of target hosts (one per line, format HOST[:PORT]). Use -p/--port to set the default port for all hosts.  Use --threads to control concurrent scans")
    parser.add_argument("-t", "--timeout", action="store", dest="timeout", metavar="N", type=int, default=5, help="timeout (in seconds) for connection and reading (default: %(default)s)")
    parser.add_argument("-v", "--verbose", action="store_true", dest="verbose", default=False, help="enable verbose output")

    # Add long options to the parser
    parser.add_argument("--conn-rate-test", action="store", dest="conn_rate_test", metavar="N[:max_rate]", type=str, default=None, help="perform a connection rate test (useful for collecting metrics related to susceptibility of the DHEat vuln). Testing is conducted with N concurrent sockets with an optional maximum rate of connections per second")
    parser.add_argument("--dheat", action="store", dest="dheat", metavar="N[:kex[:e_len]]", type=str, default=None, help="continuously perform the DHEat DoS attack (CVE-2002-20001) against the target using N concurrent sockets.  Optionally, a specific key exchange algorithm can be specified instead of allowing it to be automatically chosen.  Additionally, a small length of the fake e value sent to the server can be chosen for a more efficient attack (such as 4).")
    parser.add_argument("--lookup", action="store", dest="lookup", metavar="alg1[,alg2,...]", type=str, default=None, help="looks up an algorithm(s) without connecting to a server.")
    parser.add_argument("--skip-rate-test", action="store_true", dest="skip_rate_test", default=False, help="skip the connection rate test during standard audits (used to safely infer whether the DHEat attack is viable)")
    parser.add_argument("--threads", action="store", dest="threads", metavar="N", type=int, default=32, help="number of threads to use when scanning multiple targets (-T/--targets) (default: %(default)s)")

    # The mandatory target option.  Or rather, mandatory when -L, -T, or --lookup are not used.
    parser.add_argument("host", nargs="?", action="store", type=str, default="", help="target hostname or IPv4/IPv6 address")

    # If no arguments were given, print the help and exit.
    if len(args) < 1:
        parser.print_help()
        sys.exit(exitcodes.UNKNOWN_ERROR)

    oport: Optional[int] = None
    try:
        argument = parser.parse_args(args=args)

        # Set simple flags.
        aconf.client_audit = argument.client_audit
        aconf.ipv4 = argument.ipv4
        aconf.ipv6 = argument.ipv6
        aconf.level = argument.level
        aconf.list_policies = argument.list_policies
        aconf.manual = argument.manual
        aconf.skip_rate_test = argument.skip_rate_test
        oport = argument.oport

        if argument.batch is True:
            aconf.batch = True

        # If one -j was given, turn on JSON output.  If -jj was given, enable indentation.
        aconf.json = argument.json > 0
        if argument.json > 1:
            aconf.json_print_indent = True

        if argument.conn_rate_test is not None:
            aconf.conn_rate_test = argument.conn_rate_test

        if argument.debug is True:
            aconf.debug = True
            out.debug = True

        if argument.dheat is not None:
            aconf.dheat = argument.dheat

        if argument.gex_test is not None:
            dh_gex = argument.gex_test
            permitted_syntax = get_permitted_syntax_for_gex_test()

            if not any(re.search(regex_str, dh_gex) for regex_str in permitted_syntax.values()):
                out.fail('{} is not valid'.format(dh_gex), write_now=True)
                sys.exit(exitcodes.UNKNOWN_ERROR)

            if re.search(permitted_syntax['RANGE'], dh_gex):
                extracted_digits = re.findall(r'\d+', dh_gex)
                bits_left_bound = int(extracted_digits[0])
                bits_right_bound = int(extracted_digits[1])

                bits_step = 1
                if (len(extracted_digits)) == 3:
                    bits_step = int(extracted_digits[2])

                if bits_step <= 0:
                    out.fail('the step field cannot be 0 or less: {}'.format(bits_step), write_now=True)
                    sys.exit(exitcodes.UNKNOWN_ERROR)

                if all(x < 0 for x in (bits_left_bound, bits_right_bound)):
                    out.fail('{} {} {} is not valid'.format(dh_gex, bits_left_bound, bits_right_bound), write_now=True)
                    sys.exit(exitcodes.UNKNOWN_ERROR)

            aconf.gex_test = dh_gex

        if argument.lookup is not None:
            aconf.lookup = argument.lookup

        if argument.make_policy is not None:
            aconf.make_policy = True
            aconf.policy_file = argument.make_policy

        if argument.policy is not None:
            aconf.policy_file = argument.policy

        if argument.targets is not None:
            aconf.target_file = argument.targets

        if argument.threads is not None:
            aconf.threads = argument.threads

        if argument.timeout is not None:
            aconf.timeout = float(argument.timeout)
            aconf.timeout_set = True

        if argument.verbose is True:
            aconf.verbose = True
            out.verbose = True

    except argparse.ArgumentError as err:
        out.fail(str(err), write_now=True)
        parser.print_help()
        sys.exit(exitcodes.UNKNOWN_ERROR)

    if argument.host == "" and argument.client_audit is False and argument.targets is None and argument.list_policies is False and argument.lookup is None and argument.manual is False:
        out.fail("target host must be specified, unless -c, -m, -L, -T, or --lookup are used", write_now=True)
        sys.exit(exitcodes.UNKNOWN_ERROR)

    if aconf.manual:
        return aconf

    if aconf.lookup != "":
        return aconf

    if aconf.list_policies:
        list_policies(out, aconf.verbose)
        sys.exit(exitcodes.GOOD)

    if aconf.client_audit is False and aconf.target_file is None:
        if oport is not None:
            host = argument.host
        else:
            host, port = Utils.parse_host_and_port(argument.host)

        if not host and aconf.target_file is None:
            out.fail("target host is not specified", write_now=True)
            sys.exit(exitcodes.UNKNOWN_ERROR)

    if oport is None and aconf.client_audit:  # The default port to listen on during a client audit is 2222.
        port = 2222

    if oport is not None:
        port = Utils.parse_int(oport)
        if port < 1 or port > 65535:
            out.fail("port must be greater than 0 and less than 65535: {}".format(oport), write_now=True)
            sys.exit(exitcodes.UNKNOWN_ERROR)

    aconf.host = host
    aconf.port = port

    # If a file containing a list of targets was given, read it.
    if aconf.target_file is not None:
        try:
            with open(aconf.target_file, 'r', encoding='utf-8') as f:
                aconf.target_list = f.readlines()
        except PermissionError as e:
            # If installed as a Snap package, print a more useful message with potential work-arounds.
            if SNAP_PACKAGE:
                print(SNAP_PERMISSIONS_ERROR)
            else:
                print("Error: insufficient permissions: %s" % str(e))
            sys.exit(exitcodes.UNKNOWN_ERROR)

        # Strip out whitespace from each line in target file, and skip empty lines.
        aconf.target_list = [target.strip() for target in aconf.target_list if target not in ("", "\n")]

    # If a policy file was provided, validate it.
    if (aconf.policy_file is not None) and (aconf.make_policy is False):

        # First, see if this is a built-in policy name.  If not, assume a file path was provided, and try to load it from disk.
        aconf.policy = Policy.load_builtin_policy(aconf.policy_file, json_output=aconf.json)
        if aconf.policy is None:
            try:
                aconf.policy = Policy(policy_file=aconf.policy_file, json_output=aconf.json)
            except Exception as e:
                out.fail("Error while loading policy file: %s: %s" % (str(e), traceback.format_exc()), write_now=True)
                sys.exit(exitcodes.UNKNOWN_ERROR)

        # If the user wants to do a client audit, but provided a server policy, terminate.
        if aconf.client_audit and aconf.policy.is_server_policy():
            out.fail("Error: client audit selected, but server policy provided.", write_now=True)
            sys.exit(exitcodes.UNKNOWN_ERROR)

        # If the user wants to do a server audit, but provided a client policy, terminate.
        if aconf.client_audit is False and aconf.policy.is_server_policy() is False:
            out.fail("Error: server audit selected, but client policy provided.", write_now=True)
            sys.exit(exitcodes.UNKNOWN_ERROR)

    return aconf


def build_struct(target_host: str, banner: Optional['Banner'], kex: Optional['SSH2_Kex'] = None, client_host: Optional[str] = None, software: Optional[Software] = None, algorithms: Optional[Algorithms] = None, algorithm_recommendation_suppress_list: Optional[List[str]] = None, additional_notes: List[str] = []) -> Any:  # pylint: disable=dangerous-default-value

    def fetch_notes(algorithm: str, alg_type: str) -> Dict[str, List[Optional[str]]]:
        '''Returns a dictionary containing the messages in the "fail", "warn", and "info" levels for this algorithm.'''
        alg_db = SSH2_KexDB.get_db()
        alg_info = {}
        if algorithm in alg_db[alg_type]:
            alg_desc = alg_db[alg_type][algorithm]
            alg_desc_len = len(alg_desc)

            # If a list for the failure notes exists, add it to the return value.  Similarly, add the related lists for the warnings and informational notes.
            if (alg_desc_len >= 2) and (len(alg_desc[1]) > 0):
                alg_info["fail"] = alg_desc[1]
            if (alg_desc_len >= 3) and (len(alg_desc[2]) > 0):
                alg_info["warn"] = alg_desc[2]
            if (alg_desc_len >= 4) and (len(alg_desc[3]) > 0):
                alg_info["info"] = alg_desc[3]

            # Add information about when this algorithm was implemented in OpenSSH/Dropbear.
            since_text = Algorithm.get_since_text(alg_desc[0])
            if (since_text is not None) and (len(since_text) > 0):
                # Add the "info" key with an empty list if the if-block above didn't create it already.
                if "info" not in alg_info:
                    alg_info["info"] = []
                alg_info["info"].append(since_text)
        else:
            alg_info["fail"] = [SSH2_KexDB.FAIL_UNKNOWN]

        return alg_info

    banner_str = ''
    banner_protocol = None
    banner_software = None
    banner_comments = None
    if banner is not None:
        banner_str = str(banner)
        banner_protocol = '.'.join(str(x) for x in banner.protocol)
        banner_software = banner.software
        banner_comments = banner.comments

    res: Any = {
        "banner": {
            "raw": banner_str,
            "protocol": banner_protocol,
            "software": banner_software,
            "comments": banner_comments,
        },
    }

    # If we're scanning a client host, put the client's IP into the results.  Otherwise, include the target host.
    if client_host is not None:
        res['client_ip'] = client_host
    else:
        res['target'] = target_host

    if kex is not None:
        res['compression'] = kex.server.compression

        res['kex'] = []
        dh_alg_sizes = kex.dh_modulus_sizes()
        for algorithm in kex.kex_algorithms:
            alg_notes = fetch_notes(algorithm, 'kex')
            entry: Any = {
                'algorithm': algorithm,
                'notes': alg_notes,
            }
            if algorithm in dh_alg_sizes:
                hostkey_size = dh_alg_sizes[algorithm]
                entry['keysize'] = hostkey_size
            res['kex'].append(entry)
        res['key'] = []
        host_keys = kex.host_keys()
        for algorithm in kex.key_algorithms:
            alg_notes = fetch_notes(algorithm, 'key')
            entry = {
                'algorithm': algorithm,
                'notes': alg_notes,
            }
            if algorithm in host_keys:
                hostkey_info = host_keys[algorithm]
                hostkey_size = cast(int, hostkey_info['hostkey_size'])

                ca_type = ''
                ca_size = 0
                if 'ca_key_type' in hostkey_info:
                    ca_type = cast(str, hostkey_info['ca_key_type'])
                if 'ca_key_size' in hostkey_info:
                    ca_size = cast(int, hostkey_info['ca_key_size'])

                if algorithm in HostKeyTest.RSA_FAMILY or algorithm.startswith('ssh-rsa-cert-v0'):
                    entry['keysize'] = hostkey_size
                if ca_size > 0:
                    entry['ca_algorithm'] = ca_type
                    entry['casize'] = ca_size
            res['key'].append(entry)

        res['enc'] = []
        for algorithm in kex.server.encryption:
            alg_notes = fetch_notes(algorithm, 'enc')
            entry = {
                'algorithm': algorithm,
                'notes': alg_notes,
            }
            res['enc'].append(entry)

        res['mac'] = []
        for algorithm in kex.server.mac:
            alg_notes = fetch_notes(algorithm, 'mac')
            entry = {
                'algorithm': algorithm,
                'notes': alg_notes,
            }
            res['mac'].append(entry)

        res['fingerprints'] = []
        host_keys = kex.host_keys()

        # Normalize all RSA key types to 'ssh-rsa'.  Otherwise, due to Python's order-indifference dictionary types, we would iterate key types in unpredictable orders, which interferes with the docker testing framework (i.e.: tests would fail because elements are reported out of order, even though the output is semantically the same).
        for host_key_type in list(host_keys.keys())[:]:
            if host_key_type in HostKeyTest.RSA_FAMILY:
                val = host_keys[host_key_type]
                del host_keys[host_key_type]
                host_keys['ssh-rsa'] = val

        for host_key_type in sorted(host_keys):
            if host_keys[host_key_type] is None:
                continue

            fp = Fingerprint(cast(bytes, host_keys[host_key_type]['raw_hostkey_bytes']))

            # Skip over certificate host types (or we would return invalid fingerprints).
            if '-cert-' in host_key_type:
                continue

            # Add the SHA256 and MD5 fingerprints.
            res['fingerprints'].append({
                'hostkey': host_key_type,
                'hash_alg': 'SHA256',
                'hash': fp.sha256[7:]
            })
            res['fingerprints'].append({
                'hostkey': host_key_type,
                'hash_alg': 'MD5',
                'hash': fp.md5[4:]
            })

    # Historically, CVE information was returned.  Now we'll just return an empty dictionary so as to not break any legacy clients.
    res['cves'] = []

    # Add in the recommendations.
    res['recommendations'] = get_algorithm_recommendations(algorithms, algorithm_recommendation_suppress_list, software, for_server=True)

    # Add in the additional notes.
    res['additional_notes'] = additional_notes

    return res


# Returns one of the exitcodes.* flags.
def audit(out: OutputBuffer, aconf: AuditConf, print_target: bool = False) -> int:
    program_retval = exitcodes.GOOD
    out.batch = aconf.batch
    out.verbose = aconf.verbose
    out.debug = aconf.debug
    out.level = aconf.level
    out.use_colors = aconf.colors
    s = SSH_Socket(out, aconf.host, aconf.port, aconf.ip_version_preference, aconf.timeout, aconf.timeout_set)

    if aconf.client_audit:
        out.v("Listening for client connection on port %d..." % aconf.port, write_now=True)
        s.listen_and_accept()
    else:
        out.v("Starting audit of %s:%d..." % ('[%s]' % aconf.host if Utils.is_ipv6_address(aconf.host) else aconf.host, aconf.port), write_now=True)
        err = s.connect()

        if err is not None:
            out.fail(err)

            # If we're running against multiple targets, return a connection error to the calling worker thread.  Otherwise, write the error message to the console and exit.
            if len(aconf.target_list) > 0:
                return exitcodes.CONNECTION_ERROR
            else:
                out.write()
                sys.exit(exitcodes.CONNECTION_ERROR)

    err = None
    banner, header, err = s.get_banner()
    if banner is None:
        if err is None:
            err = '[exception] did not receive banner.'
        else:
            err = '[exception] did not receive banner: {}'.format(err)
    if err is None:
        s.send_kexinit()  # Send the algorithms we support (except we don't since this isn't a real SSH connection).

        packet_type, payload = s.read_packet()
        if packet_type < 0:
            try:
                if len(payload) > 0:
                    payload_txt = payload.decode('utf-8')
                else:
                    payload_txt = 'empty'
            except UnicodeDecodeError:
                payload_txt = '"{}"'.format(repr(payload).lstrip('b')[1:-1])
            err = '[exception] error reading packet ({})'.format(payload_txt)
        else:
            err_pair = None
            if packet_type != Protocol.MSG_KEXINIT:
                err_pair = ('MSG_KEXINIT', Protocol.MSG_KEXINIT)
            if err_pair is not None:
                fmt = '[exception] did not receive {0} ({1}), ' + \
                      'instead received unknown message ({2})'
                err = fmt.format(err_pair[0], err_pair[1], packet_type)
    if err is not None:
        output(out, aconf, banner, header)
        out.fail(err)
        return exitcodes.CONNECTION_ERROR

    try:
        kex = SSH2_Kex.parse(out, payload)
        out.d(str(kex))
    except Exception:
        out.fail("Failed to parse server's kex.  Stack trace:\n%s" % str(traceback.format_exc()))
        return exitcodes.CONNECTION_ERROR

    if aconf.dheat is not None:
        DHEat(out, aconf, banner, kex).run()
        return exitcodes.GOOD
    elif aconf.conn_rate_test_enabled:
        DHEat.dh_rate_test(out, aconf, kex, 0, 0, 0)
        return exitcodes.GOOD

    dh_rate_test_notes = ""
    if aconf.client_audit is False:
        HostKeyTest.run(out, s, kex)
        if aconf.gex_test != '':
            return run_gex_granular_modulus_size_test(out, s, kex, aconf)
        else:
            GEXTest.run(out, s, banner, kex)

            # Skip the rate test if the user specified "--skip-rate-test".
            if aconf.skip_rate_test:
                out.d("Skipping rate test due to --skip-rate-test option.")
            else:
                # Try to open many TCP connections against the server if any Diffie-Hellman key exchanges are present; this tests potential vulnerability to the DHEat DOS attack.  Use 3 concurrent sockets over at most 1.5 seconds to open at most 38 connections (stops if 1.5 seconds elapse, or 38 connections are opened--whichever comes first).  If more than 25 connections per second were observed, flag the DH algorithms with a warning about the DHEat DOS vuln.
                dh_rate_test_notes = DHEat.dh_rate_test(out, aconf, kex, 1.5, 38, 3)

    # This is a standard audit scan.
    if (aconf.policy is None) and (aconf.make_policy is False):
        program_retval = output(out, aconf, banner, header, client_host=s.client_host, kex=kex, print_target=print_target, dh_rate_test_notes=dh_rate_test_notes)

    # This is a policy test.
    elif (aconf.policy is not None) and (aconf.make_policy is False):
        program_retval = exitcodes.GOOD if evaluate_policy(out, aconf, banner, s.client_host, kex=kex) else exitcodes.FAILURE

    # A new policy should be made from this scan.
    elif (aconf.policy is None) and (aconf.make_policy is True):
        make_policy(aconf, banner, kex, s.client_host)

    else:
        raise RuntimeError('Internal error while handling output: %r %r' % (aconf.policy is None, aconf.make_policy))

    return program_retval


def algorithm_lookup(out: OutputBuffer, alg_names: str) -> int:
    '''Looks up a comma-separated list of algorithms and outputs their security properties.  Returns an exitcodes.* flag.'''
    retval = exitcodes.GOOD
    alg_types = {
        'kex': 'key exchange algorithms',
        'key': 'host-key algorithms',
        'mac': 'message authentication code algorithms',
        'enc': 'encryption algorithms (ciphers)'
    }

    algorithm_names = alg_names.split(",")
    adb = SSH2_KexDB.get_db()

    # Use nested dictionary comprehension to iterate an outer dictionary where
    # each key is an alg type that consists of a value (which is itself a
    # dictionary) of alg names. Filter the alg names against the user supplied
    # list of names.
    algorithms_dict = {
        outer_k: {
            inner_k
            for (inner_k, inner_v) in outer_v.items()
            if inner_k in algorithm_names
        }
        for (outer_k, outer_v) in adb.items()
    }

    unknown_algorithms: List[str] = []
    padding = len(max(algorithm_names, key=len))

    for alg_type in alg_types:
        if len(algorithms_dict[alg_type]) > 0:
            title = str(alg_types.get(alg_type))
            retval = output_algorithms(out, title, adb, alg_type, list(algorithms_dict[alg_type]), unknown_algorithms, False, retval, padding)

    algorithms_dict_flattened = [
        alg_name
        for val in algorithms_dict.values()
        for alg_name in val
    ]

    algorithms_not_found = [
        alg_name
        for alg_name in algorithm_names
        if alg_name not in algorithms_dict_flattened
    ]

    similar_algorithms = [
        alg_unknown + " --> (" + alg_type + ") " + alg_name
        for alg_unknown in algorithms_not_found
        for alg_type, alg_names in adb.items()
        for alg_name in alg_names
        # Perform a case-insensitive comparison using 'casefold'
        # and match substrings using the 'in' operator.
        if alg_unknown.casefold() in alg_name.casefold()
    ]

    if len(algorithms_not_found) > 0:
        retval = exitcodes.FAILURE
        out.head('# unknown algorithms')
        for algorithm_not_found in algorithms_not_found:
            out.fail(algorithm_not_found)

    out.sep()

    if len(similar_algorithms) > 0:
        retval = exitcodes.FAILURE
        out.head('# suggested similar algorithms')
        for similar_algorithm in similar_algorithms:
            out.warn(similar_algorithm)

    return retval


# Worker thread for scanning multiple targets concurrently.
def target_worker_thread(host: str, port: int, shared_aconf: AuditConf) -> Tuple[int, str]:
    ret = -1
    string_output = ''

    out = OutputBuffer()
    out.verbose = shared_aconf.verbose
    my_aconf = copy.deepcopy(shared_aconf)
    my_aconf.host = host
    my_aconf.port = port

    # If we're outputting JSON, turn off colors and ensure 'info' level messages go through.
    if my_aconf.json:
        out.json = True
        out.use_colors = False

    out.v("Running against: %s:%d..." % (my_aconf.host, my_aconf.port), write_now=True)
    try:
        ret = audit(out, my_aconf, print_target=True)
        string_output = out.get_buffer()
    except Exception:
        ret = -1
        string_output = "An exception occurred while scanning %s:%d:\n%s" % (host, port, str(traceback.format_exc()))

    return ret, string_output


def builtin_manual(out: OutputBuffer) -> int:
    '''Prints the man page (Docker, PyPI, Snap, and Windows builds only).  Returns an exitcodes.* flag.'''


    builtin_man_page = BUILTIN_MAN_PAGE
    if builtin_man_page == "":
        out.fail("The '-m' and '--manual' parameters are reserved for use in Docker, PyPI, Snap,\nand Windows builds only.  Users of other platforms should read the system man\npage.")
        return exitcodes.FAILURE

    # If colors are disabled, strip the ANSI color codes from the man page.
    if not out.use_colors:
        builtin_man_page = re.sub(r'\x1b\[\d+?m', '', builtin_man_page)

    out.info(builtin_man_page)
    return exitcodes.GOOD


def get_permitted_syntax_for_gex_test() -> Dict[str, str]:
    syntax = {
        'RANGE': r'^\d+-\d+(:\d+)?$',
        'LIST_WITHOUT_MIN_PREF_MAX': r'^\d+(,\d+)*$',
        'LIST_WITH_MIN_PREF_MAX': r'^\d+:\d+:\d+(,\d+:\d+:\d+)*$'
    }
    return syntax


def run_gex_granular_modulus_size_test(out: OutputBuffer, s: 'SSH_Socket', kex: 'SSH2_Kex', aconf: AuditConf) -> int:
    '''Extracts the user specified modulus sizes and submits them for testing against the target server.  Returns an exitcodes.* flag.'''

    permitted_syntax = get_permitted_syntax_for_gex_test()

    mod_dict: Dict[str, List[int]] = {}

    # Range syntax.
    if re.search(permitted_syntax['RANGE'], aconf.gex_test):
        extracted_digits = re.findall(r'\d+', aconf.gex_test)
        bits_left_bound = int(extracted_digits[0])
        bits_right_bound = int(extracted_digits[1])

        bits_step = 1
        if (len(extracted_digits)) == 3:
            bits_step = int(extracted_digits[2])

        # If the left value is greater than the right value, then the sequence
        # operates from right to left.
        if bits_left_bound <= bits_right_bound:
            bits_in_range_to_test = range(bits_left_bound, bits_right_bound + 1, bits_step)
        else:
            bits_in_range_to_test = range(bits_left_bound, bits_right_bound - 1, -abs(bits_step))

        out.v("A separate test will be performed against each of the following modulus sizes: " + ", ".join([str(x) for x in bits_in_range_to_test]) + ".", write_now=True)

        for i_bits in bits_in_range_to_test:
            program_retval = GEXTest.granular_modulus_size_test(out, s, kex, i_bits, i_bits, i_bits, mod_dict)
            if program_retval != exitcodes.GOOD:
                return program_retval

    # Two variations of list syntax.
    if re.search(permitted_syntax['LIST_WITHOUT_MIN_PREF_MAX'], aconf.gex_test):
        bits_in_list_to_test = aconf.gex_test.split(',')
        out.v("A separate test will be performed against each of the following modulus sizes: " + ", ".join([str(x) for x in bits_in_list_to_test]) + ".", write_now=True)
        for s_bits in bits_in_list_to_test:
            program_retval = GEXTest.granular_modulus_size_test(out, s, kex, int(s_bits), int(s_bits), int(s_bits), mod_dict)
            if program_retval != exitcodes.GOOD:
                return program_retval

    if re.search(permitted_syntax['LIST_WITH_MIN_PREF_MAX'], aconf.gex_test):
        sets_of_min_pref_max = aconf.gex_test.split(',')
        out.v("A separate test will be performed against each of the following sets of 'min:pref:max' modulus sizes: " + ', '.join(sets_of_min_pref_max), write_now=True)
        for set_of_min_pref_max in sets_of_min_pref_max:
            bits_in_list_to_test = set_of_min_pref_max.split(':')
            program_retval = GEXTest.granular_modulus_size_test(out, s, kex, int(bits_in_list_to_test[0]), int(bits_in_list_to_test[1]), int(bits_in_list_to_test[2]), mod_dict)
            if program_retval != exitcodes.GOOD:
                return program_retval

    if mod_dict:
        if aconf.json:
            json_struct = {'dh-gex-modulus-size': mod_dict}
            out.info(json.dumps(json_struct, indent=4 if aconf.json_print_indent else None, sort_keys=True))
        else:
            out.head('# diffie-hellman group exchange modulus size')
            max_key_len = len(max(mod_dict, key=len))

            for key, value in mod_dict.items():
                padding = (max_key_len - len(key)) + 1
                out.info(key + " " * padding + '--> ' + ', '.join([str(i) for i in value]))

    return program_retval


def main() -> int:
    out = OutputBuffer()
    aconf = process_commandline(out, sys.argv[1:])

    # If we're on Windows, but the colorama module could not be imported, print a warning if we're in verbose mode.
    if (sys.platform == 'win32') and ('colorama' not in sys.modules):
        out.v("WARNING: colorama module not found.  Colorized output will be disabled.", write_now=True)

    # If we're outputting JSON, turn off colors and ensure 'info' level messages go through.
    if aconf.json:
        out.json = True
        out.use_colors = False

    if aconf.manual:
        # If the colorama module was not be imported, turn off colors in order
        # to output a plain text version of the man page.
        if (sys.platform == 'win32') and ('colorama' not in sys.modules):
            out.use_colors = False
        retval = builtin_manual(out)
        out.write()
        sys.exit(retval)

    if aconf.lookup != '':
        retval = algorithm_lookup(out, aconf.lookup)
        out.write()
        sys.exit(retval)

    # If multiple targets were specified...
    if len(aconf.target_list) > 0:
        ret = exitcodes.GOOD

        # If JSON output is desired, each target's results will be reported in its own list entry.
        if aconf.json:
            print('[', end='')

        # Loop through each target in the list.  Entries can specify a port number to use, otherwise the value provided on the command line (--port=N) will be used by default (set to 22 if --port is not used).
        target_servers = []
        for _, target in enumerate(aconf.target_list):
            host, port = Utils.parse_host_and_port(target, default_port=aconf.port)
            target_servers.append((host, port))

        # A ranked list of return codes.  Those with higher indices will take precedence over lower ones.  For example, if three servers are scanned, yielding WARNING, GOOD, and UNKNOWN_ERROR, the overall result will be UNKNOWN_ERROR, since its index is the highest.  Errors have highest priority, followed by failures, then warnings.
        ranked_return_codes = [exitcodes.GOOD, exitcodes.WARNING, exitcodes.FAILURE, exitcodes.CONNECTION_ERROR, exitcodes.UNKNOWN_ERROR]

        # Queue all worker threads.
        num_target_servers = len(target_servers)
        num_processed = 0
        out.v("Scanning %u targets with %s%u threads..." % (num_target_servers, '(at most) ' if aconf.threads > num_target_servers else '',  aconf.threads), write_now=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=aconf.threads) as executor:
            future_to_server = {executor.submit(target_worker_thread, target_server[0], target_server[1], aconf): target_server for target_server in target_servers}
            for future in concurrent.futures.as_completed(future_to_server):
                worker_ret, worker_output = future.result()

                # If this worker's return code is ranked higher that what we've cached so far, update our cache.
                if ranked_return_codes.index(worker_ret) > ranked_return_codes.index(ret):
                    ret = worker_ret

                # print("Worker for %s:%d returned %d: [%s]" % (target_server[0], target_server[1], worker_ret, worker_output))
                print(worker_output, end='' if aconf.json else "\n")

                # Don't print a delimiter after the last target was handled.
                num_processed += 1
                if num_processed < num_target_servers:
                    if aconf.json:
                        print(", ", end='')
                    else:
                        print(("-" * 80) + "\n")

        if aconf.json:
            print(']')

        # Send notification that this thread is exiting.  This deletes the thread's local copy of the algorithm databases.
        SSH2_KexDB.thread_exit()

    else:  # Just a scan against a single target.
        ret = audit(out, aconf)
        out.write()

    return ret


if __name__ == '__main__':  # pragma: nocover
    multiprocessing.freeze_support()  # Needed for PyInstaller (Windows) builds.

    exit_code = exitcodes.GOOD
    try:
        exit_code = main()
    except Exception:
        exit_code = exitcodes.UNKNOWN_ERROR
        print(traceback.format_exc())

    sys.exit(exit_code)

#!/usr/bin/env python3
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
import concurrent.futures
import copy
import getopt
import json
import os
import re
import sys
import traceback

# pylint: disable=unused-import
from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401

from ssh_audit.globals import SNAP_PACKAGE
from ssh_audit.globals import SNAP_PERMISSIONS_ERROR
from ssh_audit.globals import VERSION
from ssh_audit.globals import WINDOWS_MAN_PAGE
from ssh_audit.algorithm import Algorithm
from ssh_audit.algorithms import Algorithms
from ssh_audit.auditconf import AuditConf
from ssh_audit.banner import Banner
from ssh_audit import exitcodes
from ssh_audit.fingerprint import Fingerprint
from ssh_audit.gextest import GEXTest
from ssh_audit.hostkeytest import HostKeyTest
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.policy import Policy
from ssh_audit.product import Product
from ssh_audit.protocol import Protocol
from ssh_audit.software import Software
from ssh_audit.ssh1_kexdb import SSH1_KexDB
from ssh_audit.ssh1_publickeymessage import SSH1_PublicKeyMessage
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexdb import SSH2_KexDB
from ssh_audit.ssh_socket import SSH_Socket
from ssh_audit.utils import Utils
from ssh_audit.versionvulnerabilitydb import VersionVulnerabilityDB

# Only import colorama under Windows.  Other OSes can natively handle terminal colors.
if sys.platform == 'win32':
    try:
        from colorama import init as colorama_init
        colorama_init()
    except ImportError:
        pass


def usage(uout: OutputBuffer, err: Optional[str] = None) -> None:
    retval = exitcodes.GOOD
    p = os.path.basename(sys.argv[0])
    uout.head('# {} {}, https://github.com/jtesta/ssh-audit\n'.format(p, VERSION))
    if err is not None and len(err) > 0:
        uout.fail(err + '\n')
        retval = exitcodes.UNKNOWN_ERROR
    uout.info('usage: {0} [options] <host>\n'.format(p))
    uout.info('   -h,  --help             print this help')
    uout.info('   -1,  --ssh1             force ssh version 1 only')
    uout.info('   -2,  --ssh2             force ssh version 2 only')
    uout.info('   -4,  --ipv4             enable IPv4 (order of precedence)')
    uout.info('   -6,  --ipv6             enable IPv6 (order of precedence)')
    uout.info('   -b,  --batch            batch output')
    uout.info('   -c,  --client-audit     starts a server on port 2222 to audit client\n                               software config (use -p to change port;\n                               use -t to change timeout)')
    uout.info('   -d,  --debug            debug output')
    uout.info('   -g,  --gex-test=<x[,y,...]>  dh gex modulus size test')
    uout.info('                   <min1:pref1:max1[,min2:pref2:max2,...]>')
    uout.info('                   <x-y[:step]>')
    uout.info('   -j,  --json             JSON output (use -jj to enable indents)')
    uout.info('   -l,  --level=<level>    minimum output level (info|warn|fail)')
    uout.info('   -L,  --list-policies    list all the official, built-in policies')
    uout.info('        --lookup=<alg1,alg2,...>    looks up an algorithm(s) without\n                                    connecting to a server')
    uout.info('   -M,  --make-policy=<policy.txt>  creates a policy based on the target server\n                                    (i.e.: the target server has the ideal\n                                    configuration that other servers should\n                                    adhere to)')
    uout.info('   -m,  --manual           print the man page (Windows only)')
    uout.info('   -n,  --no-colors        disable colors')
    uout.info('   -p,  --port=<port>      port to connect')
    uout.info('   -P,  --policy=<policy.txt>  run a policy test using the specified policy')
    uout.info('   -t,  --timeout=<secs>   timeout (in seconds) for connection and reading\n                               (default: 5)')
    uout.info('   -T,  --targets=<hosts.txt>  a file containing a list of target hosts (one\n                                   per line, format HOST[:PORT]).  Use --threads\n                                   to control concurrent scans.')
    uout.info('        --threads=<threads>    number of threads to use when scanning multiple\n                                   targets (-T/--targets) (default: 32)')
    uout.info('   -v,  --verbose          verbose output')
    uout.sep()
    uout.write()
    sys.exit(retval)


def output_algorithms(out: OutputBuffer, title: str, alg_db: Dict[str, Dict[str, List[List[Optional[str]]]]], alg_type: str, algorithms: List[str], unknown_algs: List[str], is_json_output: bool, program_retval: int, maxlen: int = 0, alg_sizes: Optional[Dict[str, Tuple[int, int]]] = None) -> int:  # pylint: disable=too-many-arguments
    with out:
        for algorithm in algorithms:
            program_retval = output_algorithm(out, alg_db, alg_type, algorithm, unknown_algs, program_retval, maxlen, alg_sizes)
    if not out.is_section_empty() and not is_json_output:
        out.head('# ' + title)
        out.flush_section()
        out.sep()

    return program_retval


def output_algorithm(out: OutputBuffer, alg_db: Dict[str, Dict[str, List[List[Optional[str]]]]], alg_type: str, alg_name: str, unknown_algs: List[str], program_retval: int, alg_max_len: int = 0, alg_sizes: Optional[Dict[str, Tuple[int, int]]] = None) -> int:
    prefix = '(' + alg_type + ') '
    if alg_max_len == 0:
        alg_max_len = len(alg_name)
    padding = '' if out.batch else ' ' * (alg_max_len - len(alg_name))

    # If this is an RSA host key or DH GEX, append the size to its name and fix
    # the padding.
    alg_name_with_size = None
    if (alg_sizes is not None) and (alg_name in alg_sizes):
        hostkey_size, ca_size = alg_sizes[alg_name]
        if ca_size > 0:
            alg_name_with_size = '%s (%d-bit cert/%d-bit CA)' % (alg_name, hostkey_size, ca_size)
            padding = padding[0:-15]
        else:
            alg_name_with_size = '%s (%d-bit)' % (alg_name, hostkey_size)
            padding = padding[0:-11]

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

    alg_name = alg_name_with_size if alg_name_with_size is not None else alg_name
    first = True
    for level, text in texts:
        if level == 'fail':
            program_retval = exitcodes.FAILURE
        elif level == 'warn' and program_retval != exitcodes.FAILURE:  # If a failure was found previously, don't downgrade to warning.
            program_retval = exitcodes.WARNING

        f = getattr(out, level)
        comment = (padding + ' -- [' + level + '] ' + text) if text != '' else ''
        if first:
            if first and level == 'info':
                f = out.good
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


def output_security_sub(out: OutputBuffer, sub: str, software: Optional[Software], client_audit: bool, padlen: int) -> dict:
    cveVulns = {
        'critical': [],
        'warning': []
    }
    secdb = VersionVulnerabilityDB.CVE if sub == 'cve' else VersionVulnerabilityDB.TXT
    if software is None or software.product not in secdb:
        return
    for line in secdb[software.product]:
        vfrom: str = ''
        vtill: str = ''
        vfrom, vtill = line[0:2]
        if not software.between_versions(vfrom, vtill):
            continue
        target: int = 0
        name: str = ''
        target, name = line[2:4]
        is_server = target & 1 == 1
        is_client = target & 2 == 2
        # is_local = target & 4 == 4

        # If this security entry applies only to servers, but we're testing a client, then skip it.  Similarly, skip entries that apply only to clients, but we're testing a server.
        if (is_server and not is_client and client_audit) or (is_client and not is_server and not client_audit):
            continue
        p = '' if out.batch else ' ' * (padlen - len(name))
        if sub == 'cve':
            cvss: float = 0.0
            descr: str = ''
            cvss, descr = line[4:6]

            # Critical CVSS scores (>= 8.0) are printed as a fail, otherwise they are printed as a warning.
            out_func = out.warn
            level = 'critical' if cvss >= 8.0 else 'warning'
            if cvss >= 8.0:
                out_func = out.fail
            out_func('(cve) {}{} -- (CVSSv2: {}) {}'.format(name, p, cvss, descr))
            cveVulns[level].append({"cve": name, "CVSSv2": cvss, "description": descr})
        else:
            descr = line[4]
            out.fail('(sec) {}{} -- {}'.format(name, p, descr))
    return cveVulns


def output_security(out: OutputBuffer, banner: Optional[Banner], client_audit: bool, padlen: int, is_json_output: bool) -> dict:
    cveVulns = {}
    with out:
        if banner is not None:
            software = Software.parse(banner)
            cveVulns = output_security_sub(out, 'cve', software, client_audit, padlen)
            _ = output_security_sub(out, 'txt', software, client_audit, padlen)
            if banner.protocol[0] == 1:
                p = '' if out.batch else ' ' * (padlen - 14)
                out.fail('(sec) SSH v1 enabled{} -- SSH v1 can be exploited to recover plaintext passwords'.format(p))
    if not out.is_section_empty() and not is_json_output:
        out.head('# security')
        out.flush_section()
        out.sep()
    return cveVulns



def output_fingerprints(out: OutputBuffer, algs: Algorithms, is_json_output: bool) -> None:
    with out:
        fps = []
        if algs.ssh1kex is not None:
            name = 'ssh-rsa1'
            fp = Fingerprint(algs.ssh1kex.host_key_fingerprint_data)
            # bits = algs.ssh1kex.host_key_bits
            fps.append((name, fp))
        if algs.ssh2kex is not None:
            host_keys = algs.ssh2kex.host_keys()
            for host_key_type in algs.ssh2kex.host_keys():
                if host_keys[host_key_type] is None:
                    continue

                fp = Fingerprint(host_keys[host_key_type])

                # Workaround for Python's order-indifference in dicts.  We might get a random RSA type (ssh-rsa, rsa-sha2-256, or rsa-sha2-512), so running the tool against the same server three times may give three different host key types here.  So if we have any RSA type, we will simply hard-code it to 'ssh-rsa'.
                if host_key_type in HostKeyTest.RSA_FAMILY:
                    host_key_type = 'ssh-rsa'

                # Skip over certificate host types (or we would return invalid fingerprints).
                if '-cert-' not in host_key_type:
                    fps.append((host_key_type, fp))
        # Similarly, the host keys can be processed in random order due to Python's order-indifference in dicts.  So we sort this list before printing; this makes automated testing possible.
        fps = sorted(fps)
        for fpp in fps:
            name, fp = fpp
            out.good('(fin) {}: {}'.format(name, fp.sha256))

            # Output the MD5 hash too if verbose mode is enabled.
            if out.verbose:
                out.info('(fin) {}: {} -- [info] do not rely on MD5 fingerprints for server identification; it is insecure for this use case'.format(name, fp.md5))

    if not out.is_section_empty() and not is_json_output:
        out.head('# fingerprints')
        out.flush_section()
        out.sep()


# Returns True if no warnings or failures encountered in configuration.
def output_recommendations(out: OutputBuffer, algs: Algorithms, software: Optional[Software], is_json_output: bool, padlen: int = 0) -> bool:

    ret = True
    # PuTTY's algorithms cannot be modified, so there's no point in issuing recommendations.
    if (software is not None) and (software.product == Product.PuTTY):
        max_vuln_version = 0.0
        max_cvssv2_severity = 0.0
        # Search the CVE database for the most recent vulnerable version and the max CVSSv2 score.
        for cve_list in VersionVulnerabilityDB.CVE['PuTTY']:
            vuln_version = float(cve_list[1])
            cvssv2_severity = cve_list[4]

            if vuln_version > max_vuln_version:
                max_vuln_version = vuln_version
            if cvssv2_severity > max_cvssv2_severity:
                max_cvssv2_severity = cvssv2_severity

        fn = out.warn
        if max_cvssv2_severity > 8.0:
            fn = out.fail

        # Assuming that PuTTY versions will always increment by 0.01, we can calculate the first safe version by adding 0.01 to the latest vulnerable version.
        current_version = float(software.version)
        upgrade_to_version = max_vuln_version + 0.01
        if current_version < upgrade_to_version:
            out.head('# recommendations')
            fn('(rec) Upgrade to PuTTY v%.2f' % upgrade_to_version)
            out.sep()
            ret = False
        return ret

    for_server = True
    with out:
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
                        p = '' if out.batch else ' ' * (padlen - len(name))
                        chg_additional_info = ''
                        if action == 'del':
                            an, sg, fn = 'remove', '-', out.warn
                            ret = False
                            if alg_rec[sshv][alg_type][action][name] >= 10:
                                fn = out.fail
                        elif action == 'add':
                            an, sg, fn = 'append', '+', out.good
                        elif action == 'chg':
                            an, sg, fn = 'change', '!', out.fail
                            ret = False
                            chg_additional_info = ' (increase modulus size to 3072 bits or larger)'
                        b = '(SSH{})'.format(sshv) if sshv == 1 else ''
                        fm = '(rec) {0}{1}{2}-- {3} algorithm to {4}{5} {6}'
                        fn(fm.format(sg, name, p, alg_type, an, chg_additional_info, b))
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
def output_info(out: OutputBuffer, software: Optional['Software'], client_audit: bool, any_problems: bool, is_json_output: bool) -> None:
    with out:
        # Tell user that PuTTY cannot be hardened at the protocol-level.
        if client_audit and (software is not None) and (software.product == Product.PuTTY):
            out.warn('(nfo) PuTTY does not have the option of restricting any algorithms during the SSH handshake.')

        # If any warnings or failures were given, print a link to the hardening guides.
        if any_problems:
            out.warn('(nfo) For hardening guides on common OSes, please see: <https://www.ssh-audit.com/hardening_guides.html>')

    if not out.is_section_empty() and not is_json_output:
        out.head('# additional info')
        out.flush_section()
        out.sep()


# Returns a exitcodes.* flag to denote if any failures or warnings were encountered.
def output(out: OutputBuffer, aconf: AuditConf, banner: Optional[Banner], header: List[str], client_host: Optional[str] = None, kex: Optional[SSH2_Kex] = None, pkm: Optional[SSH1_PublicKeyMessage] = None, print_target: bool = False) -> int:

    program_retval = exitcodes.GOOD
    client_audit = client_host is not None  # If set, this is a client audit.
    sshv = 1 if pkm is not None else 2
    algs = Algorithms(pkm, kex)
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

            out.good('(gen) target: {}'. format(host))
        if client_audit:
            out.good('(gen) client IP: {}'.format(client_host))
        if len(header) > 0:
            out.info('(gen) header: ' + '\n'.join(header))
        if banner is not None:
            banner_line = '(gen) banner: {}'.format(banner)
            if sshv == 1 or banner.protocol[0] == 1:
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
    cveVulns = output_security(out, banner, client_audit, maxlen, aconf.json)
    # Filled in by output_algorithms() with unidentified algs.
    unknown_algorithms: List[str] = []
    if pkm is not None:
        adb = SSH1_KexDB.ALGORITHMS
        ciphers = pkm.supported_ciphers
        auths = pkm.supported_authentications
        title, atype = 'SSH1 host-key algorithms', 'key'
        program_retval = output_algorithms(out, title, adb, atype, ['ssh-rsa1'], unknown_algorithms, aconf.json, program_retval, maxlen)
        title, atype = 'SSH1 encryption algorithms (ciphers)', 'enc'
        program_retval = output_algorithms(out, title, adb, atype, ciphers, unknown_algorithms, aconf.json, program_retval, maxlen)
        title, atype = 'SSH1 authentication types', 'aut'
        program_retval = output_algorithms(out, title, adb, atype, auths, unknown_algorithms, aconf.json, program_retval, maxlen)
    if kex is not None:
        adb = SSH2_KexDB.ALGORITHMS
        title, atype = 'key exchange algorithms', 'kex'
        program_retval = output_algorithms(out, title, adb, atype, kex.kex_algorithms, unknown_algorithms, aconf.json, program_retval, maxlen, kex.dh_modulus_sizes())
        title, atype = 'host-key algorithms', 'key'
        program_retval = output_algorithms(out, title, adb, atype, kex.key_algorithms, unknown_algorithms, aconf.json, program_retval, maxlen, kex.rsa_key_sizes())
        title, atype = 'encryption algorithms (ciphers)', 'enc'
        program_retval = output_algorithms(out, title, adb, atype, kex.server.encryption, unknown_algorithms, aconf.json, program_retval, maxlen)
        title, atype = 'message authentication code algorithms', 'mac'
        program_retval = output_algorithms(out, title, adb, atype, kex.server.mac, unknown_algorithms, aconf.json, program_retval, maxlen)
    output_fingerprints(out, algs, aconf.json)
    perfect_config = output_recommendations(out, algs, software, aconf.json, maxlen)
    output_info(out, software, client_audit, not perfect_config, aconf.json)

    if aconf.json:
        out.reset()
        # Build & write the JSON struct.
        out.info(
            json.dumps(
                build_struct(
                    aconf.host,
                    aconf.port,
                    banner,
                    kex=kex,
                    client_host=client_host,
                    cves=cveVulns,
                    software=software,
                    algs=algs
                ),
                indent=4 if aconf.json_print_indent else None, 
                sort_keys=True
            )
        )
    elif len(unknown_algorithms) > 0:  # If we encountered any unknown algorithms, ask the user to report them.
        out.warn("\n\n!!! WARNING: unknown algorithm(s) found!: %s.  Please email the full output above to the maintainer (jtesta@positronsecurity.com), or create a Github issue at <https://github.com/jtesta/ssh-audit/issues>.\n" % ','.join(unknown_algorithms))

    return program_retval


def evaluate_policy(out: OutputBuffer, aconf: AuditConf, banner: Optional['Banner'], client_host: Optional[str], kex: Optional['SSH2_Kex'] = None) -> bool:

    if aconf.policy is None:
        raise RuntimeError('Internal error: cannot evaluate against null Policy!')

    passed, error_struct, error_str = aconf.policy.evaluate(banner, kex)
    if aconf.json:
        json_struct = {'host': aconf.host, 'policy': aconf.policy.get_name_and_version(), 'passed': passed, 'errors': error_struct}
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

    return passed


def list_policies(out: OutputBuffer) -> None:
    '''Prints a list of server & client policies.'''

    server_policy_names, client_policy_names = Policy.list_builtin_policies()

    if len(server_policy_names) > 0:
        out.head('\nServer policies:\n')
        out.info("  * \"%s\"" % "\"\n  * \"".join(server_policy_names))

    if len(client_policy_names) > 0:
        out.head('\nClient policies:\n')
        out.info("  * \"%s\"" % "\"\n  * \"".join(client_policy_names))

    out.sep()
    if len(server_policy_names) == 0 and len(client_policy_names) == 0:
        out.fail("Error: no built-in policies found!")
    else:
        out.info("\nHint: Use -P and provide the full name of a policy to run a policy scan with.\n")
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


def process_commandline(out: OutputBuffer, args: List[str], usage_cb: Callable[..., None]) -> 'AuditConf':  # pylint: disable=too-many-statements
    # pylint: disable=too-many-branches
    aconf = AuditConf()

    enable_colors = not any(i in args for i in ['--no-colors', '-n'])
    aconf.colors = enable_colors
    out.use_colors = enable_colors

    try:
        sopts = 'h1246M:p:P:jbcnvl:t:T:Lmdg:'
        lopts = ['help', 'ssh1', 'ssh2', 'ipv4', 'ipv6', 'make-policy=', 'port=', 'policy=', 'json', 'batch', 'client-audit', 'no-colors', 'verbose', 'level=', 'timeout=', 'targets=', 'list-policies', 'lookup=', 'threads=', 'manual', 'debug', 'gex-test=']
        opts, args = getopt.gnu_getopt(args, sopts, lopts)
    except getopt.GetoptError as err:
        usage_cb(out, str(err))
    aconf.ssh1, aconf.ssh2 = False, False
    host: str = ''
    oport: Optional[str] = None
    port: int = 0
    for o, a in opts:
        if o in ('-h', '--help'):
            usage_cb(out)
        elif o in ('-1', '--ssh1'):
            aconf.ssh1 = True
        elif o in ('-2', '--ssh2'):
            aconf.ssh2 = True
        elif o in ('-4', '--ipv4'):
            aconf.ipv4 = True
        elif o in ('-6', '--ipv6'):
            aconf.ipv6 = True
        elif o in ('-p', '--port'):
            oport = a
        elif o in ('-b', '--batch'):
            aconf.batch = True
            aconf.verbose = True
        elif o in ('-c', '--client-audit'):
            aconf.client_audit = True
        elif o in ('-j', '--json'):
            if aconf.json:  # If specified twice, enable indent printing.
                aconf.json_print_indent = True
            else:
                aconf.json = True
        elif o in ('-v', '--verbose'):
            aconf.verbose = True
            out.verbose = True
        elif o in ('-l', '--level'):
            if a not in ('info', 'warn', 'fail'):
                usage_cb(out, 'level {} is not valid'.format(a))
            aconf.level = a
        elif o in ('-t', '--timeout'):
            aconf.timeout = float(a)
            aconf.timeout_set = True
        elif o in ('-M', '--make-policy'):
            aconf.make_policy = True
            aconf.policy_file = a
        elif o in ('-P', '--policy'):
            aconf.policy_file = a
        elif o in ('-T', '--targets'):
            aconf.target_file = a
        elif o == '--threads':
            aconf.threads = int(a)
        elif o in ('-L', '--list-policies'):
            aconf.list_policies = True
        elif o == '--lookup':
            aconf.lookup = a
        elif o in ('-m', '--manual'):
            aconf.manual = True
        elif o in ('-d', '--debug'):
            aconf.debug = True
            out.debug = True
        elif o in ('-g', '--gex-test'):
            permitted_syntax = get_permitted_syntax_for_gex_test()

            if not any(re.search(regex_str, a) for regex_str in permitted_syntax.values()):
                usage_cb(out, '{} {} is not valid'.format(o, a))

            if re.search(permitted_syntax['RANGE'], a):
                extracted_digits = re.findall(r'\d+', a)
                bits_left_bound = int(extracted_digits[0])
                bits_right_bound = int(extracted_digits[1])

                bits_step = 1
                if (len(extracted_digits)) == 3:
                    bits_step = int(extracted_digits[2])

                if bits_step <= 0:
                    usage_cb(out, '{} {} is not valid'.format(o, bits_step))

                if all(x < 0 for x in (bits_left_bound, bits_right_bound)):
                    usage_cb(out, '{} {} {} is not valid'.format(o, bits_left_bound, bits_right_bound))

            aconf.gex_test = a


    if len(args) == 0 and aconf.client_audit is False and aconf.target_file is None and aconf.list_policies is False and aconf.lookup == '' and aconf.manual is False:
        usage_cb(out)

    if aconf.manual:
        return aconf

    if aconf.lookup != '':
        return aconf

    if aconf.list_policies:
        list_policies(out)
        sys.exit(exitcodes.GOOD)

    if aconf.client_audit is False and aconf.target_file is None:
        if oport is not None:
            host = args[0]
        else:
            host, port = Utils.parse_host_and_port(args[0])
        if not host and aconf.target_file is None:
            usage_cb(out, 'host is empty')

    if port == 0 and oport is None:
        if aconf.client_audit:  # The default port to listen on during a client audit is 2222.
            port = 2222
        else:
            port = 22

    if oport is not None:
        port = Utils.parse_int(oport)
        if port <= 0 or port > 65535:
            usage_cb(out, 'port {} is not valid'.format(oport))

    aconf.host = host
    aconf.port = port
    if not (aconf.ssh1 or aconf.ssh2):
        aconf.ssh1, aconf.ssh2 = True, True

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
        aconf.policy = Policy.load_builtin_policy(aconf.policy_file)
        if aconf.policy is None:
            try:
                aconf.policy = Policy(policy_file=aconf.policy_file)
            except Exception as e:
                out.fail("Error while loading policy file: %s: %s" % (str(e), traceback.format_exc()))
                out.write()
                sys.exit(exitcodes.UNKNOWN_ERROR)

        # If the user wants to do a client audit, but provided a server policy, terminate.
        if aconf.client_audit and aconf.policy.is_server_policy():
            out.fail("Error: client audit selected, but server policy provided.")
            out.write()
            sys.exit(exitcodes.UNKNOWN_ERROR)

        # If the user wants to do a server audit, but provided a client policy, terminate.
        if aconf.client_audit is False and aconf.policy.is_server_policy() is False:
            out.fail("Error: server audit selected, but client policy provided.")
            out.write()
            sys.exit(exitcodes.UNKNOWN_ERROR)

    return aconf


def build_struct(
    target_host: str,
    target_port: int,
    banner: Optional['Banner'],
    kex: Optional['SSH2_Kex'] = None,
    pkm: Optional['SSH1_PublicKeyMessage'] = None,
    client_host: Optional[str] = None,
    cves: Optional[dict] = None,
    software: Optional[Software] = None,
    algs: Algorithms = None
    ) -> Any:

    banner_str = ''
    banner_protocol = None
    banner_software = None
    banner_comments = None
    if banner is not None:
        banner_str = str(banner)
        banner_protocol = banner.protocol
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

    res['port'] = str(target_port)

    if kex is not None:
        res['compression'] = kex.server.compression

        res['kex'] = []
        alg_sizes = kex.dh_modulus_sizes()
        for algorithm in kex.kex_algorithms:
            entry: Any = {
                'algorithm': algorithm,
            }
            if algorithm in alg_sizes:
                hostkey_size, ca_size = alg_sizes[algorithm]
                entry['keysize'] = hostkey_size
                if ca_size > 0:
                    entry['casize'] = ca_size
            res['kex'].append(entry)

        res['key'] = []
        alg_sizes = kex.rsa_key_sizes()
        for algorithm in kex.key_algorithms:
            entry = {
                'algorithm': algorithm,
            }
            if algorithm in alg_sizes:
                hostkey_size, ca_size = alg_sizes[algorithm]
                entry['keysize'] = hostkey_size
                if ca_size > 0:
                    entry['casize'] = ca_size
            res['key'].append(entry)

        res['enc'] = kex.server.encryption
        res['mac'] = kex.server.mac
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

            fp = Fingerprint(host_keys[host_key_type])

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
    else:
        pkm_supported_ciphers = None
        pkm_supported_authentications = None
        pkm_fp = None
        if pkm is not None:
            pkm_supported_ciphers = pkm.supported_ciphers
            pkm_supported_authentications = pkm.supported_authentications
            pkm_fp = Fingerprint(pkm.host_key_fingerprint_data).sha256

        res['key'] = ['ssh-rsa1']
        res['enc'] = pkm_supported_ciphers
        res['aut'] = pkm_supported_authentications
        res['fingerprints'] = [{
            'type': 'ssh-rsa1',
            'fp': pkm_fp,
        }]

    if cves is None:
        res['cves'] = {}
        res['cves']['critical'] = []
        res['cves']['warning'] = []
    elif cves['warning'] is None and cves['critical']:
        res['cves'] = {}
        res['cves']['warning'] = []
        res['cves']['critical'] = cves['critical']
    elif cves['critical'] and cves['warning'] is None:
        res['cves'] = {}
        res['cves']['critical'] = []
        res['cves']['warning'] = cves['warning']
    else:
        res['cves'] = cves

    software, alg_rec = algs.get_recommendations(software, True)
    res['recommendations'] = {
        'critical': {},
        'warning': {}
    }

    for alg_type in ['kex', 'key', 'enc', 'mac']:
        if alg_type in alg_rec[2]:
            for action in ['del', 'add', 'chg']:
                if action in alg_rec[2][alg_type]:
                    for n in alg_rec[2][alg_type][action]:
                        level = 'critical' if alg_rec[2][alg_type][action][n] >= 10 else 'warning'

                        if action not in res['recommendations'][level]:
                            res['recommendations'][level][action] = {}

                        if alg_type not in res['recommendations'][level][action]:
                            res['recommendations'][level][action][alg_type] = []

                        res['recommendations'][level][action][alg_type].append(n)
    return res


# Returns one of the exitcodes.* flags.
def audit(out: OutputBuffer, aconf: AuditConf, sshv: Optional[int] = None, print_target: bool = False) -> int:
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

    if sshv is None:
        sshv = 2 if aconf.ssh2 else 1
    err = None
    banner, header, err = s.get_banner(sshv)
    if banner is None:
        if err is None:
            err = '[exception] did not receive banner.'
        else:
            err = '[exception] did not receive banner: {}'.format(err)
    if err is None:
        s.send_kexinit()  # Send the algorithms we support (except we don't since this isn't a real SSH connection).

        packet_type, payload = s.read_packet(sshv)
        if packet_type < 0:
            try:
                if len(payload) > 0:
                    payload_txt = payload.decode('utf-8')
                else:
                    payload_txt = 'empty'
            except UnicodeDecodeError:
                payload_txt = '"{}"'.format(repr(payload).lstrip('b')[1:-1])
            if payload_txt == 'Protocol major versions differ.':
                if sshv == 2 and aconf.ssh1:
                    ret = audit(out, aconf, 1)
                    out.write()
                    return ret
            err = '[exception] error reading packet ({})'.format(payload_txt)
        else:
            err_pair = None
            if sshv == 1 and packet_type != Protocol.SMSG_PUBLIC_KEY:
                err_pair = ('SMSG_PUBLIC_KEY', Protocol.SMSG_PUBLIC_KEY)
            elif sshv == 2 and packet_type != Protocol.MSG_KEXINIT:
                err_pair = ('MSG_KEXINIT', Protocol.MSG_KEXINIT)
            if err_pair is not None:
                fmt = '[exception] did not receive {0} ({1}), ' + \
                      'instead received unknown message ({2})'
                err = fmt.format(err_pair[0], err_pair[1], packet_type)
    if err is not None:
        output(out, aconf, banner, header)
        out.fail(err)
        return exitcodes.CONNECTION_ERROR
    if sshv == 1:
        program_retval = output(out, aconf, banner, header, pkm=SSH1_PublicKeyMessage.parse(payload))
    elif sshv == 2:
        try:
            kex = SSH2_Kex.parse(payload)
        except Exception:
            out.fail("Failed to parse server's kex.  Stack trace:\n%s" % str(traceback.format_exc()))
            return exitcodes.CONNECTION_ERROR

        if aconf.client_audit is False:
            HostKeyTest.run(out, s, kex)
            if aconf.gex_test != '':
                return run_gex_granular_modulus_size_test(out, s, kex, aconf)
            else:
                GEXTest.run(out, s, kex)

        # This is a standard audit scan.
        if (aconf.policy is None) and (aconf.make_policy is False):
            program_retval = output(out, aconf, banner, header, client_host=s.client_host, kex=kex, print_target=print_target)

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
    adb = SSH2_KexDB.ALGORITHMS

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


def windows_manual(out: OutputBuffer) -> int:
    '''Prints the man page on Windows.  Returns an exitcodes.* flag.'''

    retval = exitcodes.GOOD

    if sys.platform != 'win32':
        out.fail("The '-m' and '--manual' parameters are reserved for use on Windows only.\nUsers of other operating systems should read the man page.")
        retval = exitcodes.FAILURE
        return retval

    # If colors are disabled, strip the ANSI color codes from the man page.
    windows_man_page = WINDOWS_MAN_PAGE
    if not out.use_colors:
        windows_man_page = re.sub(r'\x1b\[\d+?m', '', windows_man_page)

    out.info(windows_man_page)
    return retval


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
    aconf = process_commandline(out, sys.argv[1:], usage)

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
        retval = windows_manual(out)
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

        # Loop through each target in the list.
        target_servers = []
        for _, target in enumerate(aconf.target_list):
            host, port = Utils.parse_host_and_port(target, default_port=22)
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

    else:  # Just a scan against a single target.
        ret = audit(out, aconf)
        out.write()

    return ret


if __name__ == '__main__':  # pragma: nocover
    exit_code = exitcodes.GOOD

    try:
        exit_code = main()
    except Exception:
        exit_code = exitcodes.UNKNOWN_ERROR
        print(traceback.format_exc())

    sys.exit(exit_code)

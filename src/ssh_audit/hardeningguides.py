"""
   The MIT License (MIT)

   Copyright (C) 2025 Joe Testa (jtesta@positronsecurity.com)

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
from typing import Any, Dict

from ssh_audit.outputbuffer import OutputBuffer


class Hardening_Guides:

    HARDENING_GUIDES: Dict[str, Any] = {
        "Amazon Linux 2023": [
            {
                "server_guide": True,
                "version": 3,
                "version_date": "2024-10-01",
                "change_log": "Re-ordered host keys to prioritize ED25519 due to efficiency. Re-ordered cipher list to prioritize larger key sizes as a countermeasure to quantum attacks.",
                "notes": "all commands below are to be executed as the root user.",
                "commands": [
                    {
                        "heading": "Re-generate the RSA and ED25519 keys",
                        "comment": "",
                        "command": "rm -f /etc/ssh/ssh_host_*\nssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N \"\"\nssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N \"\""
                    },
                    {
                        "heading": "Enable the ED25519 and RSA keys",
                        "comment": "Enable the ED25519 and RSA HostKey directives in the /etc/ssh/sshd_config file:",
                        "command": "echo -e \"\\nHostKey /etc/ssh/ssh_host_ed25519_key\\nHostKey /etc/ssh/ssh_host_rsa_key\" >> /etc/ssh/sshd_config"
                    },
                    {
                        "heading": "Remove small Diffie-Hellman moduli",
                        "comment": "",
                        "command": "awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe\nmv -f /etc/ssh/moduli.safe /etc/ssh/moduli"
                    },
                    {
                        "heading": "Restrict supported key exchange, cipher, and MAC algorithms",
                        "comment": "",
                        "command": "echo -e \"# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com hardening guide.\\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\n\\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\n\\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n\" > /etc/crypto-policies/back-ends/opensshserver.config"
                    },
                    {
                        "heading": "Restart OpenSSH server",
                        "comment": "",
                        "command": "systemctl restart sshd"
                    },
                    {
                        "heading": "Implement connection rate throttling",
                        "comment": "Connection rate throttling is needed in order to protect against the DHEat denial-of-service attack. A complete and flexible solution is to use iptables to allow up to 10 connections every 10 seconds from any one source address. An alternate solution is to set OpenSSH's PerSourceMaxStartups directive to 1 (note, however, that this can cause incomplete results during ssh-audit scans, as well as other client failures when bursts of connections are made).",
                        "command": "dnf install -y iptables\niptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set\niptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP\nip6tables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set\nip6tables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP\ndnf install -y iptables-services\niptables-save > /etc/sysconfig/iptables\nip6tables-save > /etc/sysconfig/ip6tables\nsystemctl enable iptables\nsystemctl enable ip6tables\nsystemctl start iptables\nsystemctl start ip6tables"
                    },
                ]
            },
            {
                "server_guide": True,
                "version": 2,
                "version_date": "2024-04-22",
                "change_log": "Added connection throttling instructions to counteract the DHEat denial-of-service attack.",
                "notes": "",
                "commands": []  # Commands for this older version are not tracked here.
            },
            {
                "server_guide": True,
                "version": 1,
                "version_date": "2024-03-15",
                "change_log": "Initial revision.",
                "notes": "",
                "commands": []  # Commands for this older version are not tracked here.
            },
            {
                "server_guide": False,
                "version": 3,
                "version_date": "2024-10-01",
                "change_log": "Re-ordered cipher list to prioritize larger key sizes as a countermeasure to quantum attacks.",
                "notes": "",
                "commands": [
                    {
                        "heading": "Run the following in a terminal to harden the SSH client for the local user:",
                        "comment": "",
                        "command": "mkdir -p -m 0700 ~/.ssh; echo -e \"\\nHost *\\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,gss-group16-sha512-,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\n\\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\n\\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\n\" >> ~/.ssh/config"
                    },
                ]
            },
            {
                "server_guide": False,
                "version": 2,
                "version_date": "2024-04-22",
                "change_log": "added connection throttling instructions to counteract the DHEat denial-of-service attack.",
                "notes": "",
                "commands": []  # Commands for this older version are not tracked here.
            },
            {
                "server_guide": False,
                "version": 1,
                "version_date": "2024-03-15",
                "change_log": "Initial revision.",
                "notes": "",
                "commands": []  # Commands for this older version are not tracked here.
            },
        ],

        "Debian 11": [
            {
                "server_guide": True,
                "version": 1,
                "version_date": "2021-09-17",
                "change_log": "Latest version.",
                "notes": "all commands below are to be executed as the root user.",
                "commands": [
                    {
                        "heading": "Re-generate the RSA and ED25519 keys",
                        "comment": "",
                        "command": "rm -f /etc/ssh/ssh_host_*\nssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N \"\"\nssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N \"\""
                    },
                    {
                        "heading": "Enable the RSA and ED25519 keys",
                        "comment": "Enable the RSA and ED25519 HostKey directives in the /etc/ssh/sshd_config file:",
                        "command": "sed -i 's/^\\#HostKey \\/etc\\/ssh\\/ssh_host_\\(rsa\\|ed25519\\)_key$/HostKey \\/etc\\/ssh\\/ssh_host_\\1_key/g' /etc/ssh/sshd_config"
                    },
                    {
                        "heading": "Remove small Diffie-Hellman moduli",
                        "comment": "",
                        "command": "awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe\nmv -f /etc/ssh/moduli.safe /etc/ssh/moduli"
                    },
                    {
                        "heading": "Restrict supported key exchange, cipher, and MAC algorithms",
                        "comment": "",
                        "command": "echo -e \"\\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\\n# hardening guide.\\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com\" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf"
                    },
                    {
                        "heading": "Restart OpenSSH server",
                        "comment": "",
                        "command": "service ssh restart"
                    },
                ]
            },
        ],

        "Debian 12": [
            {
                "server_guide": True,
                "version": 3,
                "version_date": "2025-04-18",
                "change_log": "Added sntrup761x25519-sha512 to KexAlgorithms.",
                "notes": "all commands below are to be executed as the root user.",
                "commands": [
                    {
                        "heading": "Re-generate the RSA and ED25519 keys",
                        "comment": "",
                        "command": "rm /etc/ssh/ssh_host_*\nssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N \"\"\nssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N \"\""
                    },
                    {
                        "heading": "Enable the ED25519 and RSA keys",
                        "comment": "Enable the ED25519 and RSA HostKey directives in the /etc/ssh/sshd_config file:",
                        "command": "echo -e \"\\nHostKey /etc/ssh/ssh_host_ed25519_key\\nHostKey /etc/ssh/ssh_host_rsa_key\" >> /etc/ssh/sshd_config"
                    },
                    {
                        "heading": "Remove small Diffie-Hellman moduli",
                        "comment": "",
                        "command": "awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe\nmv /etc/ssh/moduli.safe /etc/ssh/moduli"
                    },
                    {
                        "heading": "Restrict supported key exchange, cipher, and MAC algorithms",
                        "comment": "",
                        "command": "echo -e \"# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\\n# hardening guide.\\n KexAlgorithms sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\n\\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\n\\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nRequiredRSASize 3072\\n\\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\n\" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf"
                    },
                    {
                        "heading": "Restart OpenSSH server",
                        "comment": "",
                        "command": "service ssh restart"
                    },
                    {
                        "heading": "Implement connection rate throttling",
                        "comment": "Connection rate throttling is needed in order to protect against the DHEat denial-of-service attack. A complete and flexible solution is to use iptables to allow up to 10 connections every 10 seconds from any one source address. An alternate solution is to set OpenSSH's PerSourceMaxStartups directive to 1 (note, however, that this can cause incomplete results during ssh-audit scans, as well as other client failures when bursts of connections are made).",
                        "command": "apt update\nDEBIAN_FRONTEND=noninteractive apt install -q -y iptables netfilter-persistent iptables-persistent\niptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set\niptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP\nip6tables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set\nip6tables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP\nservice netfilter-persistent save"
                    },
                ]
            },
            {
                "server_guide": True,
                "version": 2,
                "version_date": "2024-10-01",
                "change_log": "Re-ordered host keys to prioritize ED25519 due to efficiency. Re-ordered cipher list to prioritize larger key sizes as a countermeasure to quantum attacks.",
                "notes": "",
                "commands": []  # Commands for this older version are not tracked here.
            },
            {
                "server_guide": True,
                "version": 1,
                "version_date": "2024-04-24",
                "change_log": "Added connection throttling instructions to counteract the DHEat denial-of-service attack.",
                "notes": "",
                "commands": []  # Commands for this older version are not tracked here.
            },
            {
                "server_guide": False,
                "version": 2,
                "version_date": "2024-10-01",
                "change_log": "Added RequiredRSASize directive to enforce a minimum of 3072-bit user and host-based authentication keys. Re-ordered cipher list to prioritize larger key sizes as a countermeasure to quantum attacks.",
                "notes": "",
                "commands": [
                    {
                        "heading": "Run the following in a terminal to harden the SSH client for the local user:",
                        "comment": "",
                        "command": "mkdir -p -m 0700 ~/.ssh; echo -e \"\\nHost *\\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,gss-group16-sha512-,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\n\\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\n\\n RequiredRSASize 3072\\n\\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\n\" >> ~/.ssh/config"
                    },
                ]
            },
            {
                "server_guide": False,
                "version": 1,
                "version_date": "2024-03-15",
                "change_log": "Initial revision.",
                "notes": "",
                "commands": []  # Commands for this older version are not tracked here.
            },
        ],

        "Rocky Linux 9": [
            {
                "server_guide": True,
                "version": 2,
                "version_date": "2024-10-01",
                "change_log": "Re-ordered host keys to prioritize ED25519 due to efficiency. Re-ordered cipher list to prioritize larger key sizes as a countermeasure to quantum attacks.",
                "notes": "all commands below are to be executed as the root user.",
                "commands": [
                    {
                        "heading": "Re-generate the RSA and ED25519 keys",
                        "comment": "",
                        "command": "rm -f /etc/ssh/ssh_host_*\nssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N \"\"\nssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N \"\""
                    },
                    {
                        "heading": "Enable the ED25519 and RSA keys",
                        "comment": "Enable the ED25519 and RSA HostKey directives in the /etc/ssh/sshd_config file:",
                        "command": "echo -e \"\\nHostKey /etc/ssh/ssh_host_ed25519_key\\nHostKey /etc/ssh/ssh_host_rsa_key\" >> /etc/ssh/sshd_config"
                    },
                    {
                        "heading": "Remove small Diffie-Hellman moduli",
                        "comment": "",
                        "command": "awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe\nmv -f /etc/ssh/moduli.safe /etc/ssh/moduli"
                    },
                    {
                        "heading": "Restrict supported key exchange, cipher, and MAC algorithms",
                        "comment": "",
                        "command": "echo -e \"# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\\n# hardening guide.\\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\n\\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\n\\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nRequiredRSASize 3072\\n\\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n\" > /etc/crypto-policies/back-ends/opensshserver.config"
                    },
                    {
                        "heading": "Restart OpenSSH server",
                        "comment": "",
                        "command": "systemctl restart sshd"
                    },
                    {
                        "heading": "Implement connection rate throttling",
                        "comment": "Connection rate throttling is needed in order to protect against the DHEat denial-of-service attack. A complete and flexible solution is to use iptables/firewalld to allow up to 10 connections every 10 seconds from any one source address. An alternate solution is to set OpenSSH's PerSourceMaxStartups directive to 1 (note, however, that this can cause incomplete results during ssh-audit scans, as well as other client failures when bursts of connections are made).",
                        "command": "firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -p tcp --dport 22 -m state --state NEW -m recent --set\nfirewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP\nfirewall-cmd --permanent --direct --add-rule ipv6 filter INPUT 0 -p tcp --dport 22 -m state --state NEW -m recent --set\nfirewall-cmd --permanent --direct --add-rule ipv6 filter INPUT 1 -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP\nsystemctl reload firewalld"
                    },
                ]
            },
            {
                "server_guide": True,
                "version": 1,
                "version_date": "2024-04-24",
                "change_log": "Added connection throttling instructions to counteract the DHEat denial-of-service attack.",
                "notes": "",
                "commands": []  # Commands for this older version are not tracked here.
            },
            {
                "server_guide": False,
                "version": 2,
                "version_date": "2024-10-01",
                "change_log": "Added RequiredRSASize directive to enforce a minimum of 3072-bit user and host-based authentication keys. Re-ordered cipher list to prioritize larger key sizes as a countermeasure to quantum attacks.",
                "notes": "",
                "commands": [
                    {
                        "heading": "Run the following in a terminal to harden the SSH client for the local user:",
                        "comment": "",
                        "command": "mkdir -p -m 0700 ~/.ssh; echo -e \"\\nHost *\\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,gss-group16-sha512-,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\n\\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\n\\n RequiredRSASize 3072\\n\\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\n\" >> ~/.ssh/config"
                    },
                ]
            },
            {
                "server_guide": False,
                "version": 1,
                "version_date": "2024-03-15",
                "change_log": "Initial revision.",
                "notes": "",
                "commands": []  # Commands for this older version are not tracked here.
            },
        ],

        "Ubuntu 22.04": [
            {
                "server_guide": True,
                "version": 2,
                "version_date": "2024-10-01",
                "change_log": "Re-ordered host keys to prioritize ED25519 due to efficiency. Re-ordered cipher list to prioritize larger key sizes as a countermeasure to quantum attacks.",
                "notes": "all commands below are to be executed as the root user.",
                "commands": [
                    {
                        "heading": "Re-generate the RSA and ED25519 keys",
                        "comment": "",
                        "command": "rm /etc/ssh/ssh_host_*\nssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N \"\"\nssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N \"\""
                    },
                    {
                        "heading": "Enable the ED25519 and RSA keys",
                        "comment": "Enable the ED25519 and RSA HostKey directives in the /etc/ssh/sshd_config file:",
                        "command": "echo -e \"\\nHostKey /etc/ssh/ssh_host_ed25519_key\\nHostKey /etc/ssh/ssh_host_rsa_key\" >> /etc/ssh/sshd_config"
                    },
                    {
                        "heading": "Remove small Diffie-Hellman moduli",
                        "comment": "",
                        "command": "awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe\nmv /etc/ssh/moduli.safe /etc/ssh/moduli"
                    },
                    {
                        "heading": "Restrict supported key exchange, cipher, and MAC algorithms",
                        "comment": "",
                        "command": "echo -e \"# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\\n# hardening guide.\\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\n\\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\n\\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf"
                    },
                    {
                        "heading": "Implement connection rate throttling",
                        "comment": "Connection rate throttling is needed in order to protect against the DHEat denial-of-service attack. A complete and flexible solution is to use iptables to allow up to 10 connections every 10 seconds from any one source address. An alternate solution is to set OpenSSH's PerSourceMaxStartups directive to 1 (note, however, that this can cause incomplete results during ssh-audit scans, as well as other client failures when bursts of connections are made).",
                        "command": "iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set\niptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP\nip6tables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set\nip6tables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP\nDEBIAN_FRONTEND=noninteractive apt install -q -y netfilter-persistent iptables-persistent\nservice netfilter-persistent save"
                    },
                    {
                        "heading": "Restart OpenSSH server",
                        "comment": "",
                        "command": "service ssh restart"
                    },
                ]
            },
            {
                "server_guide": True,
                "version": 1,
                "version_date": "2024-04-22",
                "change_log": "Added connection throttling instructions to counteract the DHEat denial-of-service attack.",
                "notes": "",
                "commands": []  # Commands for this older version are not tracked here.
            },
            {
                "server_guide": False,
                "version": 1,
                "version_date": "2024-10-01",
                "change_log": "Re-ordered cipher list to prioritize larger key sizes as a countermeasure to quantum attacks.",
                "notes": "",
                "commands": [
                    {
                        "heading": "Run the following in a terminal to harden the SSH client for the local user:",
                        "comment": "",
                        "command": "mkdir -p -m 0700 ~/.ssh; echo -e \"\\nHost *\\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,gss-group16-sha512-,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\n\\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\n\\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\n\" >> ~/.ssh/config"
                    },
                ]
            },
        ],

        "Ubuntu 24.04": [
            {
                "server_guide": True,
                "version": 2,
                "version_date": "2024-10-01",
                "change_log": "Added RequiredRSASize directive to enforce a minimum of 3072-bit user and host-based authentication keys.",
                "notes": "all commands below are to be executed as the root user.",
                "commands": [
                    {
                        "heading": "Re-generate the ED25519 and RSA keys",
                        "comment": "",
                        "command": "rm /etc/ssh/ssh_host_*\nssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N \"\"\nssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N \"\""
                    },
                    {
                        "heading": "Remove small Diffie-Hellman moduli",
                        "comment": "",
                        "command": "awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe\nmv /etc/ssh/moduli.safe /etc/ssh/moduli"
                    },
                    {
                        "heading": "Enable the ED25519 and RSA keys",
                        "comment": "Enable the ED25519 and RSA HostKey directives in the /etc/ssh/sshd_config file:",
                        "command": "echo -e \"\\nHostKey /etc/ssh/ssh_host_ed25519_key\\nHostKey /etc/ssh/ssh_host_rsa_key\" >> /etc/ssh/sshd_config"
                    },
                    {
                        "heading": "Restrict supported key exchange, cipher, and MAC algorithms",
                        "comment": "",
                        "command": "echo -e \"# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\\n# hardening guide.\\nKexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,gss-group16-sha512-,diffie-hellman-group16-sha512\\n\\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\nMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com\\n\\nRequiredRSASize 3072\\n\\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf"
                    },
                    {
                        "heading": "Restart OpenSSH server",
                        "comment": "",
                        "command": "service ssh restart"
                    },
                    {
                        "heading": "Implement connection rate throttling",
                        "comment": "Connection rate throttling is needed in order to protect against the DHEat denial-of-service attack. A complete and flexible solution is to use iptables to allow up to 10 connections every 10 seconds from any one source address. An alternate solution is to set OpenSSH's PerSourceMaxStartups directive to 1 (note, however, that this can cause incomplete results during ssh-audit scans, as well as other client failures when bursts of connections are made).",
                        "command": "iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set\niptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP\nip6tables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set\nip6tables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP\nDEBIAN_FRONTEND=noninteractive apt install -q -y netfilter-persistent iptables-persistent\nservice netfilter-persistent save"
                    },
                ]
            },
            {
                "server_guide": True,
                "version": 1,
                "version_date": "2024-04-29",
                "change_log": "Initial revision. In comparison to Ubuntu 22.04 LTS guide, the following changes were made: 1.) For key exchanges, diffie-hellman-group18-sha512 and diffie-hellman-group-exchange-sha256 were prioritized over diffie-hellman-group16-sha512 due to greater security strength; GSS algorithms were prioritized over their non-GSS equivalents in order to match the client guide, 2.) For ciphers, 256-bit AES ciphers were prioritized over 192 and 128-bit AES ciphers due to their increased resistence against quantum computing attacks (previously, weaker GCM ciphers had priority over CTR ciphers), 3.) The HostbasedAcceptedAlgorithms and PubkeyAcceptedAlgorithms settings are now the same as HostKeyAlgorithms setting, 4.) The hmac-sha2-512-etm@openssh.com MAC was increased in priority due to its increased resistence against quantum computing attacks, and 5.) The ED25519 host keys were given priority over RSA host keys due to their greater efficiency.",
                "notes": "",
                "commands": []  # Commands for this older version are not tracked here.
            },
            {
                "server_guide": False,
                "version": 2,
                "version_date": "2024-10-01",
                "change_log": "Added RequiredRSASize directive to enforce a minimum of 3072-bit user and host-based authentication keys.",
                "notes": "",
                "commands": [
                    {
                        "heading": "Run the following in a terminal to harden the SSH client for the local user:",
                        "comment": "",
                        "command": "mkdir -p -m 0700 ~/.ssh; echo -e \"\\nHost *\\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,gss-group16-sha512-,diffie-hellman-group16-sha512\\n\\n MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com\\n\\n RequiredRSASize 3072\\n\\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n\" >> ~/.ssh/config"
                    },
                ]
            },
            {
                "server_guide": False,
                "version": 1,
                "version_date": "2024-04-29",
                "change_log": "Initial revision. In comparison to Ubuntu 22.04 LTS Client guide, the following changes were made: 1.) For key exchanges, diffie-hellman-group18-sha512 and diffie-hellman-group-exchange-sha256 were prioritized over diffie-hellman-group16-sha512 due to greater security strength, 2.) For ciphers, 256-bit AES ciphers were prioritized over 192 and 128-bit AES ciphers due to their increased resistence against quantum computing attacks (previously, weaker GCM ciphers had priority over CTR ciphers), 3.) The HostbasedAcceptedAlgorithms and PubkeyAcceptedAlgorithms settings are now the same as HostKeyAlgorithms setting, and 4.) The hmac-sha2-512-etm@openssh.com MAC was increased in priority due to its increased resistence against quantum computing attacks.",
                "notes": "",
                "commands": []  # Commands for this older version are not tracked here.
            },
        ],

        "Linux Mint 21": [
            {
                "server_guide": False,
                "version": 1,
                "version_date": "2024-10-01",
                "change_log": "Re-ordered cipher list to prioritize larger key sizes as a countermeasure to quantum attacks.",
                "notes": "",
                "commands": [
                    {
                        "heading": "Run the following in a terminal to harden the SSH client for the local user:",
                        "comment": "",
                        "command": "mkdir -p -m 0700 ~/.ssh; echo -e \"\\nHost *\\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,gss-group16-sha512-,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\n\\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\n\\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\n\" >> ~/.ssh/config"
                    },
                ]
            },
        ],

        "Linux Mint 22": [
            {
                "server_guide": False,
                "version": 2,
                "version_date": "2024-10-01",
                "change_log": "Added RequiredRSASize directive to enforce a minimum of 3072-bit user and host-based authentication keys.",
                "notes": "",
                "commands": [
                    {
                        "heading": "Run the following in a terminal to harden the SSH client for the local user:",
                        "comment": "",
                        "command": "mkdir -p -m 0700 ~/.ssh; echo -e \"\\nHost *\\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,gss-group16-sha512-,diffie-hellman-group16-sha512\\n\\n MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com\\n\\n RequiredRSASize 3072\\n\\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n\" >> ~/.ssh/config"
                    },
                ]
            },
            {
                "server_guide": False,
                "version": 1,
                "version_date": "2024-04-29",
                "change_log": "Initial revision. In comparison to Ubuntu 22.04 LTS Client guide, the following changes were made: 1.) For key exchanges, diffie-hellman-group18-sha512 and diffie-hellman-group-exchange-sha256 were prioritized over diffie-hellman-group16-sha512 due to greater security strength, 2.) For ciphers, 256-bit AES ciphers were prioritized over 192 and 128-bit AES ciphers due to their increased resistence against quantum computing attacks (previously, weaker GCM ciphers had priority over CTR ciphers), 3.) The HostbasedAcceptedAlgorithms and PubkeyAcceptedAlgorithms settings are now the same as HostKeyAlgorithms setting, and 4.) The hmac-sha2-512-etm@openssh.com MAC was increased in priority due to its increased resistence against quantum computing attacks.",
                "notes": "",
                "commands": []  # Commands for this older version are not tracked here.
            },
        ],
    }


    @staticmethod
    def list_guides(out: OutputBuffer, verbose: bool) -> None:
        '''Print all the server and client hardening guides.'''


        server_guide_names = []
        client_guide_names = []

        # Iterate through the guides, and record a list of server guide names, along with a separate list for client guide names.
        for name, guides in Hardening_Guides.HARDENING_GUIDES.items():
            for guide in guides:
                version = guide["version"]
                version_date = guide["version_date"]
                change_log = guide["change_log"]
                if guide["server_guide"]:
                    full_name = f"{name} Server" if not verbose else f"{name} Server (version {version}): {version_date}: {change_log}"
                    if full_name not in server_guide_names:
                        server_guide_names.append(full_name)
                else:
                    full_name = f"{name} Client" if not verbose else f"{name} Client (version {version}): {version_date}: {change_log}"
                    if full_name not in client_guide_names:
                        client_guide_names.append(full_name)

        # Sort the names.
        server_guide_names.sort()
        client_guide_names.sort()

        # Print the lists.
        out.head("\nServer hardening guides:\n")
        out.info("  * %s" % "\n  * ".join(server_guide_names))

        out.head("\nClient hardening guides:\n")
        out.info("  * %s" % "\n  * ".join(client_guide_names))
        out.info("\n")

        if not verbose:
            out.info("Hint: add -v to --list-hardening-guides in order to see change log messages and prior versions.  Prior versions of hardening guides can be retrieved as well with --get-hardening-guide (i.e.: --get-hardening-guide \"Ubuntu 24.04 Server (version 1)\").\n")
        out.write()


    @staticmethod
    def print_hardening_guide(out: OutputBuffer, platform: str) -> None:
        '''Prints a hardening guide for the specified platform.'''


        platform_orig = platform
        invalid_guide_name_error = "Invalid guide name.  Run --list-hardening-guides to see list of valid guide names."

        # If the user provided a version with the platform name, parse the version number they're interested in.
        use_latest_version = True
        use_version = 0
        pos = platform.find(" (version ")
        if pos != -1:
            use_latest_version = False
            end_pos = platform.find(")", pos)
            try:
                use_version = int(platform[pos + 10:end_pos])
            except ValueError:
                out.fail(invalid_guide_name_error, write_now=True)
                return

            platform = platform[0:pos]

        last_space_pos = platform.rfind(" ")
        if last_space_pos == -1:
            out.fail(invalid_guide_name_error, write_now=True)
            return

        # From input such as "Ubuntu 24.04 Server", parse the OS name ("Ubuntu 24.04") and last word ("Server").
        os_name = platform[0:last_space_pos]
        last_word = platform[last_space_pos + 1:]

        # Determine if this is a server or client guide.
        is_server = False
        if last_word == "Server":
            is_server = True
        elif last_word != "Client":
            out.fail(invalid_guide_name_error, write_now=True)
            return

        # Ensure that this OS exists in the database.
        if os_name not in Hardening_Guides.HARDENING_GUIDES:
            out.fail(invalid_guide_name_error, write_now=True)
            return

        # Pull all guides for this OS name.
        guides = Hardening_Guides.HARDENING_GUIDES[os_name]

        # Iterate over guides until we find the type (server/client) we need, as well as the version of the guide we need.
        selected_guide = None
        latest_version = 0
        for guide in guides:
            if guide["server_guide"] == is_server:
                version = guide["version"]
                if use_latest_version and (version > latest_version):
                    selected_guide = guide
                    latest_version = version
                elif use_latest_version is False and use_version == version:
                    selected_guide = guide

        # Ensure we found a guide from above.
        if selected_guide is None:
            out.fail(invalid_guide_name_error, write_now=True)
            return

        # Now print the guide.
        version_header = f"\n#\n# Hardening guide for {platform_orig}\n#\n" if not use_latest_version else f"\n#\n# Hardening guide for {platform_orig} (version {latest_version})\n#\n"
        out.info(version_header)

        commands = selected_guide["commands"]
        for command_dict in commands:
            heading = command_dict["heading"]
            comment = command_dict["comment"]
            command = command_dict["command"]
            if heading != "":
                out.info(f"# {heading}")

            if comment != "":
                out.info(f"# {comment}")

            out.info(f"{command}")
            out.info(s="")

        out.write()

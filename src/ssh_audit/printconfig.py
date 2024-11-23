import sys

from ssh_audit import exitcodes


class PrintConfig:
    def __init__(self, os_type, os_ver, clientserver):
        self.os_type = os_type
        self.os_ver = os_ver
        self.clientserver = clientserver

        self.Get_Config()

    def Get_Config(self):
        os_type = self.os_type
        os_ver = self.os_ver
        clientserver = self.clientserver

        if clientserver not in ["Server", "Client"] or os_type not in ["Amazon", "Debian", "Mint", "Rocky", "Ubuntu"]:
            PrintConfig.unknown_varient(os_type, os_ver, clientserver)
        else:
            print(' ')
            print(f'\033[1mLocating configuration for {os_type} {os_ver} - {clientserver}\033[0m')
            print(' ')

        # Server Configs
        if clientserver in ["Server"]:
            # Amazon Linux
            if os_type in ["Amazon"]:
                if os_ver in ["2023"]:
                    PrintConfig.server_modern_common()
                    PrintConfig.amazon_server_2023()
                else:
                    PrintConfig.unknown_varient(os_type, os_ver, clientserver)
            # Debian
            elif os_type in ["Debian"]:
                if os_ver in ["Bookworm"]:
                    PrintConfig.server_modern_common()
                    PrintConfig.bookworm_server()
                    PrintConfig.debian_ubuntu_rate_throttling()
                elif os_ver in ["Bullseye"]:
                    PrintConfig.server_modern_common()
                    PrintConfig.bullseye_server()
                else:
                    PrintConfig.unknown_varient(os_type, os_ver, clientserver)
            # Rocky Linux
            elif os_type in ["Rocky"]:
                if os_ver in ["9"]:
                    PrintConfig.server_modern_common()
                    PrintConfig.rocky_9_server()
                else:
                    PrintConfig.unknown_varient(os_type, os_ver, clientserver)
            # Ubuntu
            elif os_type in ["Ubuntu"]:
                if os_ver in ["2404"]:
                    PrintConfig.server_modern_common()
                    PrintConfig.ubuntu_server_2404()
                    PrintConfig.debian_ubuntu_rate_throttling()
                elif os_ver in ["2204"]:
                    PrintConfig.server_modern_common()
                    PrintConfig.ubuntu_server_2204()
                    PrintConfig.debian_ubuntu_rate_throttling()
                elif os_ver in ["2004"]:
                    PrintConfig.server_modern_common()
                    PrintConfig.ubuntu_server_2004()
                    PrintConfig.debian_ubuntu_rate_throttling()
                elif os_ver in ["1804"]:
                    PrintConfig.server_legacy_common()
                    PrintConfig.ubuntu_server_1804()
                else:
                    PrintConfig.unknown_varient(os_type, os_ver, clientserver)

            else:
                PrintConfig.unknown_varient(os_type, os_ver, clientserver)
        
        if clientserver in ["Client"]:
            if os_type in ["Amazon"]:
                if os_ver in ["2023"]:
                    PrintConfig.amazon_2023_client()
            elif os_type in ["Debian"]:
                if os_ver in ["Bookworm"]:
                    PrintConfig.debian_bookworm_client()
            elif os_type in ["Mint"]:
                if os_ver in ["22"]:
                    PrintConfig.ubuntu_2404_mint_22_client()
                elif os_ver in ["21"]:
                    PrintConfig.ubuntu_2204_mint_21_client()
                elif os_ver in ["20"]:
                    PrintConfig.ubuntu_2004_mint_20_client()
            elif os_type in ["Rocky"]:
                if os_ver in ["9"]:
                    PrintConfig.rocky_9_client()
            elif os_type in ["Ubuntu"]:
                if os_ver in ["2404"]:
                    PrintConfig.ubuntu_2404_mint_22_client()
                elif os_ver in ["2204"]:
                    PrintConfig.ubuntu_2204_mint_21_client()
                elif os_ver in ["2004"]:
                    PrintConfig.ubuntu_2004_mint_20_client()



    def unknown_varient(os_type, os_ver, clientserver):
                retval = exitcodes.GOOD
                print(' ')
                print(f'\033[1mError unknown varient : {os_type} {os_ver} {clientserver} \033[0m')
                print(' ')
                print(f'For current, community developed and legacy guides')
                print(f'check the website : https://www.ssh-audit.com/hardening_guides.html ')
                print(' ')
                print('Ensure your configuration is \"quote encapsulated\"')
                print(' ')
                print(f'\033[1mSupported Server Configurations : \033[0m')
                print('\"Amazon 2023 Server\"')
                print('\"Debian Bookworm Server\"')
                print('\"Debian Bullseye Server\"')
                print('\"Rocky 9 Server\"')
                print('\"Ubuntu 2404 Server\"')
                print('\"Ubuntu 2204 Server\"')
                print('\"Ubuntu 2004 Server\"')
                print(' ')
                print(f'\033[1mSupported Client Configurations : \033[0m')
                print('\"Amazon 2023 Client\"')
                print('\"Debian Bookworm Client\"')
                print('\"Mint 22 Client\"')
                print('\"Mint 21 Client\"')
                print('\"Mint 20 Client\"')
                print('\"Rocky 9 Client\"')
                print('\"Ubuntu 2404 Client\"')
                print('\"Ubuntu 2204 Client\"')
                print('\"Ubuntu 2004 Client\"')


                sys.exit(retval)
        

    # Client Configurations
    def amazon_2023_client():
        retval = exitcodes.GOOD
        print(' ')
        print(f'\033[1mRun the following in a terminal to harden the SSH client for the local user:\033[0m')
        print(' ')
        print('mkdir -p -m 0700 ~/.ssh; echo -e "\\nHost *\\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,gss-group16-sha512-,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\n\\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\n\\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\n" >> ~/.ssh/config')
        sys.exit(retval)

    def debian_bookworm_client():
        retval = exitcodes.GOOD
        print(' ')
        print(f'\033[1mRun the following in a terminal to harden the SSH client for the local user:\033[0m')
        print(' ')
        print('mkdir -p -m 0700 ~/.ssh; echo -e "\\nHost *\\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,gss-group16-sha512-,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\n\\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\n\\n RequiredRSASize 3072\\n\\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\n" >> ~/.ssh/config')
        sys.exit(retval)

    def rocky_9_client():
        retval = exitcodes.GOOD
        print(f'\033[1mRun the following in a terminal to harden the SSH client for the local user:\033[0m')
        print(' ')
        print('mkdir -p -m 0700 ~/.ssh; echo -e "\\nHost *\\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,gss-group16-sha512-,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\n\\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\n\\n RequiredRSASize 3072\\n\\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\n" >> ~/.ssh/config')
        sys.exit(retval)

    def ubuntu_2404_mint_22_client():
        retval = exitcodes.GOOD
        print(f'\033[1mRun the following in a terminal to harden the SSH client for the local user:\033[0m')
        print(' ')
        print('mkdir -p -m 0700 ~/.ssh; echo -e "\\nHost *\\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,gss-group16-sha512-,diffie-hellman-group16-sha512\\n\\n MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com\\n\\n RequiredRSASize 3072\\n\\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n" >> ~/.ssh/config')
        sys.exit(retval)

    def ubuntu_2204_mint_21_client():
        retval = exitcodes.GOOD
        print(f'\033[1mRun the following in a terminal to harden the SSH client for the local user:\033[0m')
        print(' ')
        print('mkdir -p -m 0700 ~/.ssh; echo -e "\\nHost *\\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,gss-group16-sha512-,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\n\\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\n\\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\n" >> ~/.ssh/config')
        sys.exit(retval)

    def ubuntu_2004_mint_20_client():
        retval = exitcodes.GOOD
        print(f'\033[1mRun the following in a terminal to harden the SSH client for the local user:\033[0m')
        print(' ')
        print('mkdir -p -m 0700 ~/.ssh; echo -e "\\nHost *\\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\\n KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\n HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com\\n" >> ~/.ssh/config')
        sys.exit(retval)


    # Server Configurations
    def server_modern_common():
        print(f'\033[1mRe-generate the ED25519 and RSA keys\033[0m')
        print(' ')
        print('rm /etc/ssh/ssh_host_*')
        print('ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N \"\"')
        print('ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N \"\"')
        print(' ')
        print(f'\033[1mRemove small Diffie-Hellman moduli\033[0m')
        print(' ')
        print('awk \'\$5 >= 3071\' /etc/ssh/moduli > /etc/ssh/moduli.safe')
        print('mv /etc/ssh/moduli.safe /etc/ssh/moduli')
        print(' ')
        print(f'\033[1mEnable the ED25519 and RSA keys\033[0m')
        print(' ')
        print('Enable the ED25519 and RSA HostKey directives in the /etc/ssh/sshd_config file:')
        print(' ')
        print('echo -e "\\nHostKey /etc/ssh/ssh_host_ed25519_key\\nHostKey /etc/ssh/ssh_host_rsa_key" >> /etc/ssh/sshd_config')
        print(' ')
    
    def server_legacy_common():
        print('Re-generate the ED25519 and RSA keys', ['bold'])
        print(' ')
        print('rm /etc/ssh/ssh_host_*')
        print('ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N \"\"')
        print('ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N \"\"')
        print(' ')
        print('Remove small Diffie-Hellman moduli')
        print(' ')
        print('awk \'\$5 >= 3071\' /etc/ssh/moduli > /etc/ssh/moduli.safe')
        print('mv /etc/ssh/moduli.safe /etc/ssh/moduli')
        print(' ')
        print('Disable the DSA and ECDSA host keys')
        print(' ')
        print('Comment out the DSA and ECDSA HostKey directives in the /etc/ssh/sshd_config file:')
        print(' ')
        print('sed -i \'s/^HostKey \/etc\/ssh\/ssh_host_\(dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g\' /etc/ssh/sshd_config')
        print(' ')

    def debian_ubuntu_rate_throttling():
        retval = exitcodes.GOOD
        print(f'\033[1mImplement connection rate throttling\033[0m')
        print(' ')
        print('iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set')
        print('iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP')
        print('ip6tables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set')
        print('ip6tables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP')
        print(' ')
        print(f'\033[1mEnable persistence of the iptables rules across server reboots: \033[0m')
        print(' ')
        print('DEBIAN_FRONTEND=noninteractive apt install -q -y netfilter-persistent iptables-persistent service netfilter-persistent save')
        print(' ')
        print(f'\033[1mRestart OpenSSH server\033[0m')
        print(' ')
        print('service ssh restart')
        sys.exit(retval)

    def ubuntu_server_2404():
        print(f'\033[1mRestrict supported key exchange, cipher, and MAC algorithms\033[0m')
        print(' ')
        print('echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\\n# hardening guide.\\nKexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,gss-group16-sha512-,diffie-hellman-group16-sha512\\n\\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\nMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com\\n\\nRequiredRSASize 3072\\n\\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf')
        print(' ')
        print(f'\033[1mRestart OpenSSH server\033[0m')
        print(' ')
        print('service ssh restart')
        print(' ')

    def ubuntu_server_2204():
        print(f'\033[1mRestrict supported key exchange, cipher, and MAC algorithms\033[0m')
        print(' ')
        print('echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\\n# hardening guide.\\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\n\\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\n\\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf')
        print(' ')
        print(f'\033[1mRestart OpenSSH server\033[0m')
        print(' ')
        print('service ssh restart')
        print(' ')

    def ubuntu_server_2004():
        print(f'\033[1mRestrict supported key exchange, cipher, and MAC algorithms\033[0m')
        print(' ')
        print('echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\\n# hardening guide.\\nKexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,gss-group16-sha512-,diffie-hellman-group16-sha512\\n\\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\nMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com\\n\\nRequiredRSASize 3072\\n\\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf')
        print(' ')
        print(f'\033[1mRestart OpenSSH server\033[0m')
        print(' ')
        print('service ssh restart')
        print(' ')

    def ubuntu_server_1804():
        retval = exitcodes.GOOD

        print(f'\033[1mRestrict supported key exchange, cipher, and MAC algorithms\033[0m')
        print(' ')
        print('echo -e "\\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\\n# hardening guide.\\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com" >> /etc/ssh/sshd_config')
        print(' ')
        print(f'\033[1mRestart OpenSSH server\033[0m')
        print(' ')
        print('service ssh restart')
        print(' ')
        sys.exit(retval)

    def bookworm_server():
        retval = exitcodes.GOOD

        print(f'\033[1mRestrict supported key exchange, cipher, and MAC algorithms\033[0m')
        print(' ')
        print('echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\\n# hardening guide.\\nKexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,gss-group16-sha512-,diffie-hellman-group16-sha512\\n\\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\nMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com\\n\\nRequiredRSASize 3072\\n\\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf')
        print(' ')
        print(f'\033[1mRestart OpenSSH server\033[0m')
        print(' ')
        print('service ssh restart')
        print(' ')
        sys.exit(retval)

    def bullseye_server():
        retval = exitcodes.GOOD

        print('Restrict supported key exchange, cipher, and MAC algorithms')
        print(' ')
        print('echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\\n# hardening guide.\\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\n\\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\n\\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf')
        print(' ')
        print('Restart OpenSSH server')
        print(' ')
        print('service ssh restart')
        print(' ')
        sys.exit(retval)
    
    def buster_server():
        retval = exitcodes.GOOD

        print('Restrict supported key exchange, cipher, and MAC algorithms')
        print(' ')
        print('echo -e "\\n# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\\n# hardening guide.\\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com" >> /etc/ssh/sshd_config')
        print(' ')
        print('Restart OpenSSH server')
        print(' ')
        print('service ssh restart')
        print(' ')
        sys.exit(retval)
    
    def rocky_9_server():
        retval = exitcodes.GOOD

        print(f'\033[1mRestrict supported key exchange, cipher, and MAC algorithms\033[0m')
        print(' ')
        print('echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\\n# hardening guide.\\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\n\\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\n\\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nRequiredRSASize 3072\\n\\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n" > /etc/crypto-policies/back-ends/opensshserver.config')
        print(' ')
        print(f'\033[1mRestart OpenSSH server\033[0m')
        print(' ')
        print('systemctl restart sshd')
        print(' ')
        print(f'\033[1mImplement connection rate throttling\033[0m')
        print(' ')
        print('firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -p tcp --dport 22 -m state --state NEW -m recent --set')
        print('firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP')
        print('firewall-cmd --permanent --direct --add-rule ipv6 filter INPUT 0 -p tcp --dport 22 -m state --state NEW -m recent --set')
        print('firewall-cmd --permanent --direct --add-rule ipv6 filter INPUT 1 -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP')
        print(' ')
        print(f'\033[1mReload firewalld to enable new rules:\033[0m')
        print(' ')
        print('systemctl reload firewalld')
        print(' ')
        sys.exit(retval)

    def amazon_server_2023():
        retval = exitcodes.GOOD

        print(f'\033[1mRestrict supported key exchange, cipher, and MAC algorithms\033[0m')
        print(' ')
        print('echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\\n# hardening guide.\\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\\n\\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\\n\\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\\n\\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\\n\\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\\n\\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\\n\\n" > /etc/crypto-policies/back-ends/opensshserver.config')
        print(' ')
        print(f'\033[1mRestart OpenSSH server\033[0m')
        print(' ')
        print('systemctl restart sshd')
        print(' ')
        print(f'\033[1mImplement connection rate throttling\033[0m')
        print(' ')
        print('dnf install -y iptables')
        print('iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set')
        print('iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP')
        print('ip6tables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set')
        print('ip6tables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP')
        print(' ')
        print(f'\033[1mEnable persistence of the iptables rules across server reboots:\033[0m')
        print(' ')
        print('dnf install -y iptables-services')
        print('iptables-save > /etc/sysconfig/iptables')
        print('ip6tables-save > /etc/sysconfig/ip6tables')
        print('systemctl enable iptables')
        print('systemctl enable ip6tables')
        print('systemctl start iptables')
        print('systemctl start ip6tables')
        print(' ')
        sys.exit(retval)











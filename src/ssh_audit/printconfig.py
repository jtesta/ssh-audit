import sys

from ssh_audit import exitcodes
from ssh_audit.globals import VERSION
from ssh_audit.globals import GUIDES_UPDATED


class PrintConfig:
    def __init__(self, os_type: str, os_ver: str, clientserver: str) -> None:
        self.os_type = os_type
        self.os_ver = os_ver
        self.clientserver = clientserver

        self.Get_Config()

    def Get_Config(self) -> None:
        retval = exitcodes.GOOD

        os_type = self.os_type
        os_ver = self.os_ver
        clientserver = self.clientserver

        supported_os = ["Amazon", "Debian", "Mint", "Rocky", "Ubuntu"]
        supported_edition = ["2404", "2204", "2004", "1804", "2023", "22", "21", "20", "9", "Bookworm", "Bullseye"]
        if clientserver not in ["Server", "Client"] or os_type not in supported_os and os_ver not in supported_edition:
            PrintConfig.unknown_varient(os_type, os_ver, clientserver)
            sys.exit(retval)
        else:
            print(" ")
            print(f"\033[1mSSH-Audit Version : {VERSION}\033[0m")
            print(" ")
            print(f"\033[1mBGuides Last modified : {GUIDES_UPDATED}\033[0m")
            print(" ")
            print(f"\033[1mLocating configuration for {os_type} {os_ver} - {clientserver}\033[0m")
            print(" ")


        # Server Configs
        if clientserver in ["Server"]:
            # Amazon Linux
            if os_type in ["Amazon"] and os_ver in ["2023"]:
                PrintConfig.server_modern_common()
                PrintConfig.amazon_server_2023()
                sys.exit(retval)
            # Debian
            elif os_type in ["Debian"] and os_ver in ["Bookworm"]:
                PrintConfig.server_modern_common()
                PrintConfig.bookworm_server()
                PrintConfig.debian_ubuntu_rate_throttling()
                sys.exit(retval)
            elif os_type in ["Debian"] and os_ver in ["Bullseye"]:
                PrintConfig.server_modern_common()
                PrintConfig.bullseye_server()
                sys.exit(retval)
            # Rocky Linux
            elif os_type in ["Rocky"] and os_ver in ["9"]:
                PrintConfig.server_modern_common()
                PrintConfig.rocky_9_server()
                sys.exit(retval)
            # Ubuntu
            elif os_type in ["Ubuntu"] and os_ver in ["2404"]:
                PrintConfig.server_modern_common()
                PrintConfig.ubuntu_server_2404()
                PrintConfig.debian_ubuntu_rate_throttling()
                sys.exit(retval)
            elif os_type in ["Ubuntu"] and os_ver in ["2204"]:
                PrintConfig.server_modern_common()
                PrintConfig.ubuntu_server_2204()
                PrintConfig.debian_ubuntu_rate_throttling()
                sys.exit(retval)
            elif os_type in ["Ubuntu"] and os_ver in ["2004"]:
                PrintConfig.server_modern_common()
                PrintConfig.ubuntu_server_2004()
                PrintConfig.debian_ubuntu_rate_throttling()
                sys.exit(retval)
            elif os_type in ["Ubuntu"] and os_ver in ["1804"]:
                PrintConfig.server_legacy_common()
                PrintConfig.ubuntu_server_1804()
                sys.exit(retval)
            else:
                PrintConfig.unknown_varient(os_type, os_ver, clientserver)
                sys.exit(retval)


        # Client Configs
        if clientserver in ["Client"]:
            # Amazon
            if os_type in ["Amazon"] and os_ver in ["2023"]:
                PrintConfig.amazon_2023_client()
                sys.exit(retval)
            # Debian
            elif os_type in ["Debian"] and os_ver in ["Bookworm"]:
                PrintConfig.debian_bookworm_client()
                sys.exit(retval)
            # Mint
            elif os_type in ["Mint"] and os_ver in ["22"]:
                PrintConfig.ubuntu_2404_mint_22_client()
                sys.exit(retval)
            elif os_type in ["Mint"] and os_ver in ["21"]:
                PrintConfig.ubuntu_2204_mint_21_client()
                sys.exit(retval)
            elif os_type in ["Mint"] and os_ver in ["20"]:
                PrintConfig.ubuntu_2004_mint_20_client()
                sys.exit(retval)
            # Rocky
            elif os_type in ["Rocky"] and os_ver in ["9"]:
                PrintConfig.rocky_9_client()
                sys.exit(retval)
            # Ubuntu
            elif os_type in ["Ubuntu"] and os_ver in ["2404"]:
                PrintConfig.ubuntu_2404_mint_22_client()
                sys.exit(retval)
            elif os_type in ["Ubuntu"] and os_ver in ["2204"]:
                PrintConfig.ubuntu_2204_mint_21_client()
                sys.exit(retval)
            elif os_type in ["Ubuntu"] and os_ver in ["2004"]:
                PrintConfig.ubuntu_2004_mint_20_client()
                sys.exit(retval)
            else:
                PrintConfig.unknown_varient(os_type, os_ver, clientserver)
                sys.exit(retval)



    @staticmethod
    def unknown_varient(os_type: str, os_ver: str, clientserver: str) -> None:
        print(" ")
        print(f"\033[1mSSH-Audit Version : {VERSION}\033[0m")
        print(" ")
        print(f"\033[1mGuides Last modified : {GUIDES_UPDATED}\033[0m")
        print(" ")
        print(f"\033[1mError unknown varient : {os_type} {os_ver} {clientserver} \033[0m")
        print(" ")
        print("For current, community developed and legacy guides")
        print("check the website : https://www.ssh-audit.com/hardening_guides.html")
        print(" ")
        print("\033[1mSupported Server Configurations : \033[0m")
        print(r"Amazon 2023 Server")
        print(r"Debian Bookworm Server")
        print(r"Debian Bullseye Server")
        print(r"Rocky 9 Server")
        print(r"Ubuntu 2404 Server")
        print(r"Ubuntu 2204 Server")
        print(r"Ubuntu 2004 Server")
        print(" ")
        print("\033[1mSupported Client Configurations : \033[0m")
        print(r"Amazon 2023 Client")
        print(r"Debian Bookworm Client")
        print(r"Mint 22 Client")
        print(r"Mint 21 Client")
        print(r"Mint 20 Client")
        print(r"Rocky 9 Client")
        print(r"Ubuntu 2404 Client")
        print(r"Ubuntu 2204 Client")
        print(r"Ubuntu 2004 Client")


    # Client Configurations


    @staticmethod
    def amazon_2023_client() -> None:
        print(" ")
        print("\033[1mRun the following in a terminal to harden the SSH client for the local user:\033[0m")
        print(" ")
        print(r'mkdir -p -m 0700 ~/.ssh; echo -e "\nHost *\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\n\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,gss-group16-sha512-,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n" >> ~/.ssh/config')

    @staticmethod
    def debian_bookworm_client() -> None:
        print(" ")
        print("\033[1mRun the following in a terminal to harden the SSH client for the local user:\033[0m")
        print(" ")
        print(r'mkdir -p -m 0700 ~/.ssh; echo -e "\nHost *\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\n\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,gss-group16-sha512-,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\n RequiredRSASize 3072\n\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n" >> ~/.ssh/config')

    @staticmethod
    def rocky_9_client() -> None:
        print("\033[1mRun the following in a terminal to harden the SSH client for the local user:\033[0m")
        print(" ")
        print(r'mkdir -p -m 0700 ~/.ssh; echo -e "\nHost *\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\n\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,gss-group16-sha512-,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\n RequiredRSASize 3072\n\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n" >> ~/.ssh/config')

    @staticmethod
    def ubuntu_2404_mint_22_client() -> None:
        print("\033[1mRun the following in a terminal to harden the SSH client for the local user:\033[0m")
        print(" ")
        print(r'mkdir -p -m 0700 ~/.ssh; echo -e "\nHost *\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\n\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,gss-group16-sha512-,diffie-hellman-group16-sha512\n\n MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com\n\n RequiredRSASize 3072\n\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n" >> ~/.ssh/config')

    @staticmethod
    def ubuntu_2204_mint_21_client() -> None:
        print("\033[1mRun the following in a terminal to harden the SSH client for the local user:\033[0m")
        print(" ")
        print(r'mkdir -p -m 0700 ~/.ssh; echo -e "\nHost *\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\n\n KexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,gss-group16-sha512-,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\n HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n GSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\n HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\n" >> ~/.ssh/config')

    @staticmethod
    def ubuntu_2004_mint_20_client() -> None:
        print("\033[1mRun the following in a terminal to harden the SSH client for the local user:\033[0m")
        print(" ")
        print(r'mkdir -p -m 0700 ~/.ssh; echo -e "\nHost *\n Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com\n" >> ~/.ssh/config')


    # Server Configurations


    @staticmethod
    def server_modern_common() -> None:
        print("\033[1mRe-generate the ED25519 and RSA keys\033[0m")
        print(" ")
        print("rm /etc/ssh/ssh_host_*")
        print(r'ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""')
        print(r'ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""')
        print(" ")
        print("\033[1mRemove small Diffie-Hellman moduli\033[0m")
        print(" ")
        print(r"awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe")
        print("mv /etc/ssh/moduli.safe /etc/ssh/moduli")
        print(" ")
        print("\033[1mEnable the ED25519 and RSA keys\033[0m")
        print(" ")
        print("Enable the ED25519 and RSA HostKey directives in the /etc/ssh/sshd_config file:")
        print(" ")
        print(r'echo -e "\nHostKey /etc/ssh/ssh_host_ed25519_key\nHostKey /etc/ssh/ssh_host_rsa_key" >> /etc/ssh/sshd_config')
        print(" ")

    @staticmethod
    def server_legacy_common() -> None:
        print("\033[1mRe-generate the ED25519 and RSA keys\033[0m")
        print(" ")
        print(r"rm /etc/ssh/ssh_host_*")
        print(r'ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""')
        print(r'ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""')
        print(" ")
        print("\033[1mRemove small Diffie-Hellman moduli\033[0m")
        print(" ")
        print(r"awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe")
        print("mv /etc/ssh/moduli.safe /etc/ssh/moduli")
        print(" ")
        print("\033[1mDisable the DSA and ECDSA host keys\033[0m")
        print(" ")
        print("Comment out the DSA and ECDSA HostKey directives in the /etc/ssh/sshd_config file:")
        print(" ")
        print(r"sed -i 's/^HostKey \/etc\/ssh\/ssh_host_\(dsa\|ecdsa\)_key$/\#HostKey \/etc\/ssh\/ssh_host_\1_key/g' /etc/ssh/sshd_config")
        print(" ")

    @staticmethod
    def debian_ubuntu_rate_throttling() -> None:
        print("\033[1mImplement connection rate throttling\033[0m")
        print(" ")
        print("iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set")
        print("iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP")
        print("ip6tables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set")
        print("ip6tables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP")
        print(" ")
        print("\033[1mEnable persistence of the iptables rules across server reboots: \033[0m")
        print(" ")
        print("DEBIAN_FRONTEND=noninteractive apt install -q -y netfilter-persistent iptables-persistent service netfilter-persistent save")
        print(" ")
        print("\033[1mRestart OpenSSH server\033[0m")
        print(" ")
        print("service ssh restart")

    @staticmethod
    def ubuntu_server_2404() -> None:
        print("\033[1mRestrict supported key exchange, cipher, and MAC algorithms\033[0m")
        print(" ")
        print(r'echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,gss-group16-sha512-,diffie-hellman-group16-sha512\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\n\nMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com\n\nRequiredRSASize 3072\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf')
        print(" ")
        print("\033[1mRestart OpenSSH server\033[0m")
        print(" ")
        print("service ssh restart")
        print(" ")

    @staticmethod
    def ubuntu_server_2204() -> None:
        print("\033[1mRestrict supported key exchange, cipher, and MAC algorithms\033[0m")
        print(" ")
        print(r'echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\n\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf')
        print(" ")
        print("\033[1mRestart OpenSSH server\033[0m")
        print(" ")
        print("service ssh restart")
        print(" ")

    @staticmethod
    def ubuntu_server_2004() -> None:
        print("\033[1mRestrict supported key exchange, cipher, and MAC algorithms\033[0m")
        print(" ")
        print(r'echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,gss-group16-sha512-,diffie-hellman-group16-sha512\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\n\nMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com\n\nRequiredRSASize 3072\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf')
        print(" ")
        print("\033[1mRestart OpenSSH server\033[0m")
        print(" ")
        print("service ssh restart")
        print(" ")

    @staticmethod
    def ubuntu_server_1804() -> None:
        print("\033[1mRestrict supported key exchange, cipher, and MAC algorithms\033[0m")
        print(" ")
        print(r'echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\nHostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com" >> /etc/ssh/sshd_config')
        print(" ")
        print("\033[1mRestart OpenSSH server\033[0m")
        print(" ")
        print("service ssh restart")
        print(" ")

    @staticmethod
    def bookworm_server() -> None:
        print("\033[1mRestrict supported key exchange, cipher, and MAC algorithms\033[0m")
        print(" ")
        print(r'echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms sntrup761x25519-sha512@openssh.com,gss-curve25519-sha256-,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,gss-group16-sha512-,diffie-hellman-group16-sha512\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\n\nMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com\n\nRequiredRSASize 3072\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf')
        print(" ")
        print("\033[1mRestart OpenSSH server\033[0m")
        print(" ")
        print("service ssh restart")
        print(" ")

    @staticmethod
    def bullseye_server() -> None:
        print("\033[1mRestrict supported key exchange, cipher, and MAC algorithms\033[0m")
        print(" ")
        print(r'echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\n\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256" > /etc/ssh/sshd_config.d/ssh-audit_hardening.conf')
        print(" ")
        print("\033[1mRestart OpenSSH server\033[0m")
        print(" ")
        print("service ssh restart")
        print(" ")

    @staticmethod
    def rocky_9_server() -> None:
        print("\033[1mRestrict supported key exchange, cipher, and MAC algorithms\033[0m")
        print(" ")
        print(r'echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\n\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nRequiredRSASize 3072\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n" > /etc/crypto-policies/back-ends/opensshserver.config')
        print(" ")
        print("\033[1mRestart OpenSSH server\033[0m")
        print(" ")
        print("systemctl restart sshd")
        print(" ")
        print("\033[1mImplement connection rate throttling\033[0m")
        print(" ")
        print("firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -p tcp --dport 22 -m state --state NEW -m recent --set")
        print("firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 1 -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP")
        print("firewall-cmd --permanent --direct --add-rule ipv6 filter INPUT 0 -p tcp --dport 22 -m state --state NEW -m recent --set")
        print("firewall-cmd --permanent --direct --add-rule ipv6 filter INPUT 1 -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP")
        print(" ")
        print("\033[1mReload firewalld to enable new rules:\033[0m")
        print(" ")
        print("systemctl reload firewalld")
        print(" ")

    @staticmethod
    def amazon_server_2023() -> None:
        print("\033[1mRestrict supported key exchange, cipher, and MAC algorithms\033[0m")
        print(" ")
        print(r'echo -e "# Restrict key exchange, cipher, and MAC algorithms, as per sshaudit.com\n# hardening guide.\nKexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,gss-curve25519-sha256-,diffie-hellman-group16-sha512,gss-group16-sha512-,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256\n\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr\n\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n\nHostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nCASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\nGSSAPIKexAlgorithms gss-curve25519-sha256-,gss-group16-sha512-\n\nHostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256\n\nPubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n\n" > /etc/crypto-policies/back-ends/opensshserver.config')
        print(" ")
        print("\033[1mRestart OpenSSH server\033[0m")
        print(" ")
        print("systemctl restart sshd")
        print(" ")
        print("\033[1mImplement connection rate throttling\033[0m")
        print(" ")
        print("dnf install -y iptables")
        print("iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set")
        print("iptables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP")
        print("ip6tables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --set")
        print("ip6tables -I INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 10 --hitcount 10 -j DROP")
        print(" ")
        print("\033[1mEnable persistence of the iptables rules across server reboots:\033[0m")
        print(" ")
        print("dnf install -y iptables-services")
        print("iptables-save > /etc/sysconfig/iptables")
        print("ip6tables-save > /etc/sysconfig/ip6tables")
        print("systemctl enable iptables")
        print("systemctl enable ip6tables")
        print("systemctl start iptables")
        print("systemctl start ip6tables")
        print(" ")
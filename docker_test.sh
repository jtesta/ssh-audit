#!/bin/bash

#
# This script will set up a docker image with multiple versions of OpenSSH, then
# use it to run tests.
#
# For debugging purposes, here is a cheat sheet for manually running the docker image:
#
# docker run -p 2222:22 -it ssh-audit-test:X /bin/bash
# docker run -p 2222:22 --security-opt seccomp:unconfined -it ssh-audit-test /debug.sh
# docker run -d -p 2222:22 ssh-audit-test:X /openssh/sshd-5.6p1 -D -f /etc/ssh/sshd_config-5.6p1_test1
# docker run -d -p 2222:22 ssh-audit-test:X /openssh/sshd-8.0p1 -D -f /etc/ssh/sshd_config-8.0p1_test1
#


# This is the docker tag for the image.  If this tag doesn't exist, then we assume the
# image is out of date, and generate a new one with this tag.
IMAGE_VERSION=2

# This is the name of our docker image.
IMAGE_NAME=ssh-audit-test


# Terminal colors.
CLR="\033[0m"
RED="\033[0;31m"
GREEN="\033[0;32m"
REDB="\033[1;31m"   # Red + bold
GREENB="\033[1;32m" # Green + bold


# Returns 0 if current docker image exists.
function check_if_docker_image_exists {
    images=`docker image ls | egrep "$IMAGE_NAME[[:space:]]+$IMAGE_VERSION"`
}


# Uncompresses and compiles the specified version of Dropbear.
function compile_dropbear {
    version=$1
    compile 'Dropbear' $version
}


# Uncompresses and compiles the specified version of OpenSSH.
function compile_openssh {
    version=$1
    compile 'OpenSSH' $version
}

function compile {
    project=$1
    version=$2

    tarball=
    uncompress_options=
    source_dir=
    server_executable=
    if [[ $project == 'OpenSSH' ]]; then
	tarball="openssh-${version}.tar.gz"
	uncompress_options="xzf"
	source_dir="openssh-${version}"
	server_executable=sshd
    elif [[ $project == 'Dropbear' ]]; then
	tarball="dropbear-${version}.tar.bz2"
	uncompress_options="xjf"
	source_dir="dropbear-${version}"
	server_executable=dropbear
    fi

    echo "Uncompressing ${project} ${version}..."
    tar $uncompress_options $tarball

    echo "Compiling ${project} ${version}..."
    pushd $source_dir > /dev/null
    ./configure && make -j 10

    if [[ ! -f $server_executable ]]; then
	echo -e "${REDB}Error: ${server_executable} not built!${CLR}"
	exit 1
    fi

    echo -e "\n${GREEN}Successfully built ${project} ${version}${CLR}\n"
    popd > /dev/null
}


# Creates a new docker image.
function create_docker_image {
    # Create a new temporary directory.
    TMP_DIR=`mktemp -d /tmp/sshaudit-docker-XXXXXXXXXX`

    # Copy the Dockerfile to our new temp directory.
    cp test/docker/* $TMP_DIR

    # Make the temp directory our working directory for the duration of the build
    # process.
    pushd $TMP_DIR > /dev/null

    # Get the release key for OpenSSH.
    get_openssh_release_key
    get_dropbear_release_key

    # Aside from checking the GPG signatures, we also compare against this known-good
    # SHA-256 hash just in case.
    get_openssh '4.0p1' '5adb9b2c2002650e15216bf94ed9db9541d9a17c96fcd876784861a8890bc92b'
    get_openssh '5.6p1' '538af53b2b8162c21a293bb004ae2bdb141abd250f61b4cea55244749f3c6c2b'
    get_openssh '8.0p1' 'bd943879e69498e8031eb6b7f44d08cdc37d59a7ab689aa0b437320c3481fd68'
    get_dropbear '2019.78' '525965971272270995364a0eb01f35180d793182e63dd0b0c3eb0292291644a4'

    # Compile the versions of OpenSSH.
    compile_openssh '4.0p1'
    compile_openssh '5.6p1'
    compile_openssh '8.0p1'

    # Compile the versions of Dropbear.
    compile_dropbear '2019.78'


    # Rename the default config files so we know they are our originals.
    mv openssh-4.0p1/sshd_config sshd_config-4.0p1_orig
    mv openssh-5.6p1/sshd_config sshd_config-5.6p1_orig
    mv openssh-8.0p1/sshd_config sshd_config-8.0p1_orig


    # Create the configurations for each test.


    #
    # OpenSSH v4.0p1
    #

    # Test 1: Basic test.
    create_openssh_config '4.0p1' 'test1' "HostKey /etc/ssh/ssh1_host_key\nHostKey /etc/ssh/ssh_host_rsa_key_1024\nHostKey /etc/ssh/ssh_host_dsa_key"


    #
    # OpenSSH v5.6p1
    #

    # Test 1: Basic test.
    create_openssh_config '5.6p1' 'test1' "HostKey /etc/ssh/ssh_host_rsa_key_1024\nHostKey /etc/ssh/ssh_host_dsa_key"

    # Test 2: RSA 1024 host key with RSA 1024 certificate.
    create_openssh_config '5.6p1' 'test2' "HostKey /etc/ssh/ssh_host_rsa_key_1024\nHostCertificate /etc/ssh/ssh_host_rsa_key_1024-cert_1024.pub"
    
    # Test 3: RSA 1024 host key with RSA 3072 certificate.
    create_openssh_config '5.6p1' 'test3' "HostKey /etc/ssh/ssh_host_rsa_key_1024\nHostCertificate /etc/ssh/ssh_host_rsa_key_1024-cert_3072.pub"

    # Test 4: RSA 3072 host key with RSA 1024 certificate.
    create_openssh_config '5.6p1' 'test4' "HostKey /etc/ssh/ssh_host_rsa_key_3072\nHostCertificate /etc/ssh/ssh_host_rsa_key_3072-cert_1024.pub"

    # Test 5: RSA 3072 host key with RSA 3072 certificate.
    create_openssh_config '5.6p1' 'test5' "HostKey /etc/ssh/ssh_host_rsa_key_3072\nHostCertificate /etc/ssh/ssh_host_rsa_key_3072-cert_3072.pub"


    #
    # OpenSSH v8.0p1
    #

    # Test 1: Basic test.
    create_openssh_config '8.0p1' 'test1' "HostKey /etc/ssh/ssh_host_rsa_key_3072\nHostKey /etc/ssh/ssh_host_ecdsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key"

    # Test 2: ED25519 certificate test.
    create_openssh_config '8.0p1' 'test2' "HostKey /etc/ssh/ssh_host_ed25519_key\nHostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub"

    # Test 3: Hardened installation test.
    create_openssh_config '8.0p1' 'test3' "HostKey /etc/ssh/ssh_host_ed25519_key\nKexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com"


    # Now build the docker image!
    docker build --tag $IMAGE_NAME:$IMAGE_VERSION .

    popd > /dev/null
    rm -rf $TMP_DIR
}


# Creates an OpenSSH configuration file for a specific test.
function create_openssh_config {
    openssh_version=$1
    test_number=$2
    config_text=$3

    cp sshd_config-${openssh_version}_orig sshd_config-${openssh_version}_${test_number}
    echo -e "${config_text}" >> sshd_config-${openssh_version}_${test_number}
}


# Downloads the Dropbear release key and adds it to the local keyring.
function get_dropbear_release_key {
    get_release_key 'Dropbear' 'https://matt.ucc.asn.au/dropbear/releases/dropbear-key-2015.asc' 'F29C6773' 'F734 7EF2 EE2E 07A2 6762  8CA9 4493 1494 F29C 6773'
}


# Downloads the OpenSSH release key and adds it to the local keyring.
function get_openssh_release_key {
    get_release_key 'OpenSSH' 'https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/RELEASE_KEY.asc' '6D920D30' '59C2 118E D206 D927 E667  EBE3 D3E5 F56B 6D92 0D30'
}


function get_release_key {
    project=$1
    key_url=$2
    key_id=$3
    release_key_fingerprint_expected=$4

    echo -e "\nGetting ${project} release key...\n"
    wget -O key.asc $2

    echo -e "\nImporting ${project} release key...\n"
    gpg --import key.asc

    rm key.asc

    local release_key_fingerprint_actual=`gpg --fingerprint ${key_id}`
    if [[ $release_key_fingerprint_actual != *"$release_key_fingerprint_expected"* ]]; then
        echo -e "\n${REDB}Error: ${project} release key fingerprint does not match expected value!\n\tExpected: $release_key_fingerprint_expected\n\tActual: $release_key_fingerprint_actual\n\nTerminating.${CLR}"
        exit -1
    fi
    echo -e "\n\n${GREEN}${project} release key matches expected value.${CLR}\n"
}


# Downloads the specified version of Dropbear.
function get_dropbear {
    version=$1
    tarball_checksum_expected=$2
    get_source 'Dropbear' $version $tarball_checksum_expected
}


# Downloads the specified version of OpenSSH.
function get_openssh {
    version=$1
    tarball_checksum_expected=$2
    get_source 'OpenSSH' $version $tarball_checksum_expected
}


function get_source {
    project=$1
    version=$2
    tarball_checksum_expected=$3

    base_url=
    tarball=
    sig=
    signer=
    if [[ $project == 'OpenSSH' ]]; then
	base_url='https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/'
	tarball="openssh-${version}.tar.gz"
	sig="${tarball}.asc"
	signer="Damien Miller "
    elif [[ $project == 'Dropbear' ]]; then
	base_url='https://matt.ucc.asn.au/dropbear/releases/'
	tarball="dropbear-${version}.tar.bz2"
	sig="${tarball}.asc"
	signer="Dropbear SSH Release Signing <matt@ucc.asn.au>"
    fi

    echo -e "\nGetting ${project} ${version} sources...\n"
    wget "${base_url}${tarball}"

    echo -e "\nGetting ${project} ${version} signature...\n"
    wget "${base_url}${sig}"


    # Older OpenSSH releases were .sigs.
    if [[ ($project == 'OpenSSH') && (! -f $sig) ]]; then
	wget ${base_url}openssh-${version}.tar.gz.sig
	sig=openssh-${version}.tar.gz.sig
    fi

    local gpg_verify=`gpg --verify ${sig} ${tarball} 2>&1`
    if [[ $gpg_verify != *"Good signature from \"${signer}"* ]]; then
        echo -e "\n\n${REDB}Error: ${project} signature invalid!\n$gpg_verify\n\nTerminating.${CLR}"
        exit -1
    fi

    # Check GPG's return value.  0 denotes a valid signature, and 1 is returned
    # on invalid signatures.
    if [[ $? != 0 ]]; then
        echo -e "\n\n${REDB}Error: ${project} signature invalid!  Verification returned code: $?\n\nTerminating.${CLR}"
        exit -1
    fi

    echo -e "${GREEN}Signature on ${project} sources verified.${CLR}\n"

    local checksum_actual=`sha256sum ${tarball} | cut -f1 -d" "`
    if [[ $checksum_actual != $tarball_checksum_expected ]]; then
        echo -e "${REDB}Error: ${project} checksum is invalid!\n  Expected: ${tarball_checksum_expected}\n  Actual:   ${checksum_actual}\n\n  Terminating.${CLR}"
        exit -1
    fi
}


# Runs a Dropbear test.  Upon failure, a diff between the expected and actual results
# is shown, then the script immediately terminates.
function run_dropbear_test {
    dropbear_version=$1
    test_number=$2
    options=$3

    run_test 'Dropbear' $dropbear_version $test_number "$options"
}


# Runs an OpenSSH test.  Upon failure, a diff between the expected and actual results
# is shown, then the script immediately terminates.
function run_openssh_test {
    openssh_version=$1
    test_number=$2

    run_test 'OpenSSH' $openssh_version $test_number ''
}


function run_test {
    server_type=$1
    version=$2
    test_number=$3
    options=$4

    server_exec=
    test_result=
    expected_result=
    test_name=
    if [[ $server_type == 'OpenSSH' ]]; then
	server_exec="/openssh/sshd-${version} -D -f /etc/ssh/sshd_config-${version}_${test_number}"
	test_result="${TEST_RESULT_DIR}/openssh_${version}_${test_number}.txt"
	expected_result="test/docker/expected_results/openssh_${version}_${test_number}.txt"
	test_name="OpenSSH ${version} ${test_number}"
	options=
    elif [[ $server_type == 'Dropbear' ]]; then
	server_exec="/dropbear/dropbear-${version} -F ${options}"
	test_result="${TEST_RESULT_DIR}/dropbear_${version}_${test_number}.txt"
	expected_result="test/docker/expected_results/dropbear_${version}_${test_number}.txt"
	test_name="Dropbear ${version} ${test_number}"
    fi

    cid=`docker run -d -p 2222:22 ${IMAGE_NAME}:${IMAGE_VERSION} ${server_exec}`
    if [[ $? != 0 ]]; then
	echo -e "${REDB}Failed to run docker image! (exit code: $?)${CLR}"
	exit 1
    fi

    ./ssh-audit.py localhost:2222 > $test_result
    if [[ $? != 0 ]]; then
	echo -e "${REDB}Failed to run ssh-audit.py! (exit code: $?)${CLR}"
	docker container stop $cid > /dev/null
	exit 1
    fi

    docker container stop $cid > /dev/null
    if [[ $? != 0 ]]; then
       echo -e "${REDB}Failed to stop docker container ${cid}! (exit code: $?)${CLR}"
       exit 1
    fi

    diff=`diff -u ${expected_result} ${test_result}`
    if [[ $? == 0 ]]; then
	echo -e "${test_name} ${GREEN}passed${CLR}."
    else
	echo -e "${test_name} ${REDB}FAILED${CLR}.\n\n${diff}\n"
	exit 1
    fi
}



# First check if docker is functional.
docker version > /dev/null
if [[ $? != 0 ]]; then
    echo -e "${REDB}Error: 'docker version' command failed (error code: $?).  Is docker installed and functioning?${CLR}"
    exit 1
fi

# Check if the docker image is the most up-to-date version.  If not, create it.
check_if_docker_image_exists
if [[ $? == 0 ]]; then
    echo -e "\n${GREEN}Docker image $IMAGE_NAME:$IMAGE_VERSION already exists.${CLR}"
else
    echo -e "\nCreating docker image $IMAGE_NAME:$IMAGE_VERSION..."
    create_docker_image
    echo -e "\n${GREEN}Done creating docker image!${CLR}"
fi

# Create a temporary directory to write test results to.
TEST_RESULT_DIR=`mktemp -d /tmp/ssh-audit_test-results_XXXXXXXXXX`

# Now run all the tests.
echo -e "\nRunning tests..."
run_openssh_test '4.0p1' 'test1'
echo
run_openssh_test '5.6p1' 'test1'
run_openssh_test '5.6p1' 'test2'
run_openssh_test '5.6p1' 'test3'
run_openssh_test '5.6p1' 'test4'
run_openssh_test '5.6p1' 'test5'
echo
run_openssh_test '8.0p1' 'test1'
run_openssh_test '8.0p1' 'test2'
run_openssh_test '8.0p1' 'test3'
echo
run_dropbear_test '2019.78' 'test1' '-r /etc/dropbear/dropbear_rsa_host_key_1024 -r /etc/dropbear/dropbear_dss_host_key -r /etc/dropbear/dropbear_ecdsa_host_key'

# The test functions above will terminate the script on failure, so if we reached here,
# all tests are successful.
echo -e "\n${GREENB}ALL TESTS PASS!${CLR}\n"

rm -rf $TEST_RESULT_DIR
exit 0

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
IMAGE_VERSION=3

# This is the name of our docker image.
IMAGE_NAME=positronsecurity/ssh-audit-test-framework


# Terminal colors.
CLR="\033[0m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
GREEN="\033[0;32m"
REDB="\033[1;31m"   # Red + bold
GREENB="\033[1;32m" # Green + bold

# Program return values.
PROGRAM_RETVAL_FAILURE=3
PROGRAM_RETVAL_WARNING=2
PROGRAM_RETVAL_CONNECTION_ERROR=1
PROGRAM_RETVAL_GOOD=0


# Counts the number of test failures.
num_failures=0


# Returns 0 if current docker image exists.
check_if_docker_image_exists() {
    images=$(docker image ls | grep -E "$IMAGE_NAME[[:space:]]+$IMAGE_VERSION")
}


# Uncompresses and compiles the specified version of Dropbear.
compile_dropbear() {
    version=$1
    compile 'Dropbear' "$version"
}


# Uncompresses and compiles the specified version of OpenSSH.
compile_openssh() {
    version=$1
    compile 'OpenSSH' "$version"
}


# Uncompresses and compiles the specified version of TinySSH.
compile_tinyssh() {
    version=$1
    compile 'TinySSH' "$version"
}


compile() {
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
    elif [[ $project == 'TinySSH' ]]; then
        tarball="${version}.tar.gz"
        uncompress_options="xzf"
        source_dir="tinyssh-${version}"
        server_executable='build/bin/tinysshd'
    fi

    echo "Uncompressing ${project} ${version}..."
    tar $uncompress_options "$tarball"

    echo "Compiling ${project} ${version}..."
    pushd "$source_dir" > /dev/null

    # TinySSH has no configure script... only a Makefile.
    if [[ $project == 'TinySSH' ]]; then
        make -j 10
    else
        ./configure && make -j 10
    fi

    if [[ ! -f $server_executable ]]; then
        echo -e "${REDB}Error: ${server_executable} not built!${CLR}"
        exit 1
    fi

    echo -e "\n${GREEN}Successfully built ${project} ${version}${CLR}\n"
    popd > /dev/null
}


# Creates a new docker image.
create_docker_image() {
    # Create a new temporary directory.
    TMP_DIR=$(mktemp -d /tmp/sshaudit-docker-XXXXXXXXXX)

    # Copy the Dockerfile and all files in the test/docker/ dir to our new temp directory.
    find test/docker/ -maxdepth 1 -type f -exec cp -t "$TMP_DIR" '{}' +

    # Make the temp directory our working directory for the duration of the build
    # process.
    pushd "$TMP_DIR" > /dev/null

    # Get the release keys.
    get_dropbear_release_key
    get_openssh_release_key
    get_tinyssh_release_key

    # Aside from checking the GPG signatures, we also compare against this known-good
    # SHA-256 hash just in case.
    get_openssh '4.0p1' '5adb9b2c2002650e15216bf94ed9db9541d9a17c96fcd876784861a8890bc92b'
    get_openssh '5.6p1' '538af53b2b8162c21a293bb004ae2bdb141abd250f61b4cea55244749f3c6c2b'
    get_openssh '8.0p1' 'bd943879e69498e8031eb6b7f44d08cdc37d59a7ab689aa0b437320c3481fd68'
    get_dropbear '2019.78' '525965971272270995364a0eb01f35180d793182e63dd0b0c3eb0292291644a4'
    get_tinyssh '20190101' '554a9a94e53b370f0cd0c5fbbd322c34d1f695cbcea6a6a32dcb8c9f595b3fea'

    # Compile the versions of OpenSSH.
    compile_openssh '4.0p1'
    compile_openssh '5.6p1'
    compile_openssh '8.0p1'

    # Compile the versions of Dropbear.
    compile_dropbear '2019.78'

    # Compile the versions of TinySSH.
    compile_tinyssh '20190101'


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
    docker build --tag "$IMAGE_NAME:$IMAGE_VERSION" .

    popd > /dev/null
    rm -rf -- "$TMP_DIR"
}


# Creates an OpenSSH configuration file for a specific test.
create_openssh_config() {
    openssh_version=$1
    test_number=$2
    config_text=$3

    cp "sshd_config-${openssh_version}_orig" "sshd_config-${openssh_version}_${test_number}"
    echo -e "${config_text}" >> "sshd_config-${openssh_version}_${test_number}"
}


# Downloads the Dropbear release key and adds it to the local keyring.
get_dropbear_release_key() {
    get_release_key 'Dropbear' 'https://matt.ucc.asn.au/dropbear/releases/dropbear-key-2015.asc' 'F29C6773' 'F734 7EF2 EE2E 07A2 6762  8CA9 4493 1494 F29C 6773'
}


# Downloads the OpenSSH release key and adds it to the local keyring.
get_openssh_release_key() {
    get_release_key 'OpenSSH' 'https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/RELEASE_KEY.asc' '6D920D30' '59C2 118E D206 D927 E667  EBE3 D3E5 F56B 6D92 0D30'
}


# Downloads the TinySSH release key and adds it to the local keyring.
get_tinyssh_release_key() {
    get_release_key 'TinySSH' '' '96939FF9' 'AADF 2EDF 5529 F170 2772  C8A2 DEC4 D246 931E F49B'
}


get_release_key() {
    project=$1
    key_url=$2
    key_id=$3
    release_key_fingerprint_expected=$4

    # The TinySSH release key isn't on any website, apparently.
    if [[ $project == 'TinySSH' ]]; then
        gpg --keyserver keys.gnupg.net --recv-key "$key_id"
    else
        echo -e "\nGetting ${project} release key...\n"
        wget -O key.asc "$2"

        echo -e "\nImporting ${project} release key...\n"
        gpg --import key.asc

        rm key.asc
    fi

    local release_key_fingerprint_actual=$(gpg --fingerprint "$key_id")
    if [[ $release_key_fingerprint_actual != *"$release_key_fingerprint_expected"* ]]; then
        echo -e "\n${REDB}Error: ${project} release key fingerprint does not match expected value!\n\tExpected: $release_key_fingerprint_expected\n\tActual: $release_key_fingerprint_actual\n\nTerminating.${CLR}"
        exit 1
    fi
    echo -e "\n\n${GREEN}${project} release key matches expected value.${CLR}\n"
}


# Downloads the specified version of Dropbear.
get_dropbear() {
    version=$1
    tarball_checksum_expected=$2
    get_source 'Dropbear' "$version" "$tarball_checksum_expected"
}


# Downloads the specified version of OpenSSH.
get_openssh() {
    version=$1
    tarball_checksum_expected=$2
    get_source 'OpenSSH' "$version" "$tarball_checksum_expected"
}


# Downloads the specified version of TinySSH.
get_tinyssh() {
    version=$1
    tarball_checksum_expected=$2
    get_source 'TinySSH' "$version" "$tarball_checksum_expected"
}


get_source() {
    project=$1
    version=$2
    tarball_checksum_expected=$3

    base_url_source=
    base_url_sig=
    tarball=
    sig=
    signer=
    if [[ $project == 'OpenSSH' ]]; then
        base_url_source='https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/'
        base_url_sig=$base_url_source
        tarball="openssh-${version}.tar.gz"
        sig="${tarball}.asc"
        signer="Damien Miller "
    elif [[ $project == 'Dropbear' ]]; then
        base_url_source='https://matt.ucc.asn.au/dropbear/releases/'
        base_url_sig=$base_url_source
        tarball="dropbear-${version}.tar.bz2"
        sig="${tarball}.asc"
        signer="Dropbear SSH Release Signing <matt@ucc.asn.au>"
    elif [[ $project == 'TinySSH' ]]; then
        base_url_source='https://github.com/janmojzis/tinyssh/archive/'
        base_url_sig="https://github.com/janmojzis/tinyssh/releases/download/${version}/"
        tarball="${version}.tar.gz"
        sig="${tarball}.asc"
        signer="Jan Mojžíš <jan.mojzis@gmail.com>"
    fi

    echo -e "\nGetting ${project} ${version} sources...\n"
    wget "${base_url_source}${tarball}"

    echo -e "\nGetting ${project} ${version} signature...\n"
    wget "${base_url_sig}${sig}"


    # Older OpenSSH releases were .sigs.
    if [[ ($project == 'OpenSSH') && (! -f $sig) ]]; then
        wget "${base_url_sig}openssh-${version}.tar.gz.sig"
        sig=openssh-${version}.tar.gz.sig
    fi

    local gpg_verify=$(gpg --verify "${sig}" "${tarball}" 2>&1)
    if [[ $gpg_verify != *"Good signature from \"${signer}"* ]]; then
        echo -e "\n\n${REDB}Error: ${project} signature invalid!\n$gpg_verify\n\nTerminating.${CLR}"
        exit 1
    fi

    # Check GPG's return value.  0 denotes a valid signature, and 1 is returned
    # on invalid signatures.
    if [[ $? != 0 ]]; then
        echo -e "\n\n${REDB}Error: ${project} signature invalid!  Verification returned code: $?\n\nTerminating.${CLR}"
        exit 1
    fi

    echo -e "${GREEN}Signature on ${project} sources verified.${CLR}\n"

    local checksum_actual=$(sha256sum "${tarball}" | cut -f1 -d" ")
    if [[ $checksum_actual != "$tarball_checksum_expected" ]]; then
        echo -e "${REDB}Error: ${project} checksum is invalid!\n  Expected: ${tarball_checksum_expected}\n  Actual:   ${checksum_actual}\n\n  Terminating.${CLR}"
        exit 1
    fi
}


# Pulls the defined image from Dockerhub.
pull_docker_image() {
    docker pull "$IMAGE_NAME:$IMAGE_VERSION"
    if [[ $? == 0 ]]; then
        echo -e "${GREEN}Successfully downloaded image $IMAGE_NAME:$IMAGE_VERSION from Dockerhub.${CLR}\n"
    else
        echo -e "${REDB}Failed to pull image $IMAGE_NAME:$IMAGE_VERSION from Dockerhub!  Error code: $?${CLR}\n"
        exit 1
    fi
}


# Runs a Dropbear test.  Upon failure, a diff between the expected and actual results
# is shown, then the script immediately terminates.
run_dropbear_test() {
    dropbear_version=$1
    test_number=$2
    options=$3
    expected_retval=$4

    run_test 'Dropbear' $dropbear_version $test_number "$options" $expected_retval
}


# Runs an OpenSSH test.  Upon failure, a diff between the expected and actual results
# is shown, then the script immediately terminates.
run_openssh_test() {
    openssh_version=$1
    test_number=$2
    expected_retval=$3

    run_test 'OpenSSH' $openssh_version $test_number '' $expected_retval
}


# Runs a TinySSH test.  Upon failure, a diff between the expected and actual results
# is shown, then the script immediately terminates.
run_tinyssh_test() {
    tinyssh_version=$1
    test_number=$2
    expected_retval=$3

    run_test 'TinySSH' $tinyssh_version $test_number '' $expected_retval
}


run_test() {
    server_type=$1
    version=$2
    test_number=$3
    options=$4
    expected_retval=$5

    failed=0  # Set to 1 if this test fails.
    server_exec=
    test_result_stdout=
    test_result_json=
    expected_result_stdout=
    expected_result_json=
    test_name=
    if [[ $server_type == 'OpenSSH' ]]; then
        server_exec="/openssh/sshd-${version} -D -f /etc/ssh/sshd_config-${version}_${test_number}"
        test_result_stdout="${TEST_RESULT_DIR}/openssh_${version}_${test_number}.txt"
        test_result_json="${TEST_RESULT_DIR}/openssh_${version}_${test_number}.json"
        expected_result_stdout="test/docker/expected_results/openssh_${version}_${test_number}.txt"
        expected_result_json="test/docker/expected_results/openssh_${version}_${test_number}.json"
        test_name="OpenSSH ${version} ${test_number}"
        options=
    elif [[ $server_type == 'Dropbear' ]]; then
        server_exec="/dropbear/dropbear-${version} -F ${options}"
        test_result_stdout="${TEST_RESULT_DIR}/dropbear_${version}_${test_number}.txt"
        test_result_json="${TEST_RESULT_DIR}/dropbear_${version}_${test_number}.json"
        expected_result_stdout="test/docker/expected_results/dropbear_${version}_${test_number}.txt"
        expected_result_json="test/docker/expected_results/dropbear_${version}_${test_number}.json"
        test_name="Dropbear ${version} ${test_number}"
    elif [[ $server_type == 'TinySSH' ]]; then
        server_exec="/usr/bin/tcpserver -HRDl0 0.0.0.0 22 /tinysshd/tinyssh-20190101 -v /etc/tinyssh/"
        test_result_stdout="${TEST_RESULT_DIR}/tinyssh_${version}_${test_number}.txt"
        test_result_json="${TEST_RESULT_DIR}/tinyssh_${version}_${test_number}.json"
        expected_result_stdout="test/docker/expected_results/tinyssh_${version}_${test_number}.txt"
        expected_result_json="test/docker/expected_results/tinyssh_${version}_${test_number}.json"
        test_name="TinySSH ${version} ${test_number}"
    fi

    cid=$(docker run -d -p 2222:22 "$IMAGE_NAME:$IMAGE_VERSION" ${server_exec})
    #echo "Running: docker run -d -p 2222:22 $IMAGE_NAME:$IMAGE_VERSION ${server_exec}"
    if [[ $? != 0 ]]; then
        echo -e "${REDB}Failed to run docker image! (exit code: $?)${CLR}"
        exit 1
    fi

    ./ssh-audit.py localhost:2222 > "$test_result_stdout"
    actual_retval=$?
    if [[ $actual_retval != "$expected_retval" ]]; then
        echo -e "${REDB}Unexpected return value.  Expected: ${expected_retval}; Actual: ${actual_retval}${CLR}"
        docker container stop -t 0 $cid > /dev/null
        exit 1
    fi

    ./ssh-audit.py -j localhost:2222 > "$test_result_json"
    actual_retval=$?
    if [[ $actual_retval != "$expected_retval" ]]; then
        echo -e "${REDB}Unexpected return value.  Expected: ${expected_retval}; Actual: ${actual_retval}${CLR}"
        docker container stop -t 0 $cid > /dev/null
        exit 1
    fi

    docker container stop -t 0 $cid > /dev/null
    if [[ $? != 0 ]]; then
       echo -e "${REDB}Failed to stop docker container ${cid}! (exit code: $?)${CLR}"
       exit 1
    fi

    # TinySSH outputs a random string in each banner, which breaks our test.  So
    # we need to filter out the banner part of the output so we get stable, repeatable
    # results.
    if [[ $server_type == 'TinySSH' ]]; then
        grep -v "(gen) banner: " "${test_result_stdout}" > "${test_result_stdout}.tmp"
        mv "${test_result_stdout}.tmp" "${test_result_stdout}"
        cat "${test_result_json}" | perl -pe 's/"comments": ".*?"/"comments": ""/' | perl -pe 's/"raw": ".+?"/"raw": ""/' > "${test_result_json}.tmp"
        mv "${test_result_json}.tmp" "${test_result_json}"
    fi

    diff=$(diff -u "${expected_result_stdout}" "${test_result_stdout}")
    if [[ $? != 0 ]]; then
        echo -e "${test_name} ${REDB}FAILED${CLR}.\n\n${diff}\n"
        failed=1
        num_failures=$((num_failures+1))
    fi

    diff=$(diff -u "${expected_result_json}" "${test_result_json}")
    if [[ $? != 0 ]]; then
        echo -e "${test_name} ${REDB}FAILED${CLR}.\n\n${diff}\n"
        failed=1
        num_failures=$((num_failures+1))
    fi

    if [[ $failed == 0 ]]; then
        echo -e "${test_name} ${GREEN}passed${CLR}."
    fi
}

run_builtin_policy_test() {
    policy_name=$1         # The built-in policy name to use.
    version=$2             # Version of OpenSSH to test with.
    test_number=$3         # The test number to run.
    server_options=$4      # The options to start the server with (i.e.: "-o option1,options2,...")
    expected_exit_code=$5  # The expected exit code of ssh-audit.py.

    server_exec="/openssh/sshd-${version} -D -f /etc/ssh/sshd_config-8.0p1_test1 ${server_options}"
    test_result_stdout="${TEST_RESULT_DIR}/openssh_${version}_builtin_policy_${test_number}.txt"
    test_result_json="${TEST_RESULT_DIR}/openssh_${version}_builtin_policy_${test_number}.json"
    expected_result_stdout="test/docker/expected_results/openssh_${version}_builtin_policy_${test_number}.txt"
    expected_result_json="test/docker/expected_results/openssh_${version}_builtin_policy_${test_number}.json"
    test_name="OpenSSH ${version} built-in policy ${test_number}"

    run_policy_test "${test_name}" "${server_exec}" "${policy_name}" "${test_result_stdout}" "${test_result_json}" "${expected_exit_code}"
}


run_custom_policy_test() {
    config_number=$1  # The configuration number to use.
    test_number=$2    # The policy test number to run.
    expected_exit_code=$3  # The expected exit code of ssh-audit.py.

    version=
    config=
    if [[ ${config_number} == 'config1' ]]; then
        version='5.6p1'
        config='sshd_config-5.6p1_test1'
    elif [[ ${config_number} == 'config2' ]]; then
        version='8.0p1'
        config='sshd_config-8.0p1_test1'
    elif [[ ${config_number} == 'config3' ]]; then
        version='5.6p1'
        config='sshd_config-5.6p1_test4'
    fi

    server_exec="/openssh/sshd-${version} -D -f /etc/ssh/${config}"
    policy_path="test/docker/policies/policy_${test_number}.txt"
    test_result_stdout="${TEST_RESULT_DIR}/openssh_${version}_custom_policy_${test_number}.txt"
    test_result_json="${TEST_RESULT_DIR}/openssh_${version}_custom_policy_${test_number}.json"
    expected_result_stdout="test/docker/expected_results/openssh_${version}_custom_policy_${test_number}.txt"
    expected_result_json="test/docker/expected_results/openssh_${version}_custom_policy_${test_number}.json"
    test_name="OpenSSH ${version} custom policy ${test_number}"

    run_policy_test "${test_name}" "${server_exec}" "${policy_path}" "${test_result_stdout}" "${test_result_json}" "${expected_exit_code}"
}


run_policy_test() {
    test_name=$1
    server_exec=$2
    policy_path=$3
    test_result_stdout=$4
    test_result_json=$5
    expected_exit_code=$6


    #echo "Running: docker run -d -p 2222:22 $IMAGE_NAME:$IMAGE_VERSION ${server_exec}"
    cid=$(docker run -d -p 2222:22 "$IMAGE_NAME:$IMAGE_VERSION" ${server_exec})
    if [[ $? != 0 ]]; then
        echo -e "${REDB}Failed to run docker image! (exit code: $?)${CLR}"
        exit 1
    fi

    #echo "Running: ./ssh-audit.py -P \"${policy_path}\" localhost:2222 > ${test_result_stdout}"
    ./ssh-audit.py -P "${policy_path}" localhost:2222 > "${test_result_stdout}"
    actual_exit_code=$?
    if [[ ${actual_exit_code} != "${expected_exit_code}" ]]; then
        echo -e "${test_name} ${REDB}FAILED${CLR} (expected exit code: ${expected_exit_code}; actual exit code: ${actual_exit_code}\n"
        cat "${test_result_stdout}"
        docker container stop -t 0 $cid > /dev/null
        exit 1
    fi

    #echo "Running: ./ssh-audit.py -P \"${policy_path}\" -j localhost:2222 > ${test_result_json}"
    ./ssh-audit.py -P "${policy_path}" -j localhost:2222 > "${test_result_json}"
    actual_exit_code=$?
    if [[ ${actual_exit_code} != "${expected_exit_code}" ]]; then
        echo -e "${test_name} ${REDB}FAILED${CLR} (expected exit code: ${expected_exit_code}; actual exit code: ${actual_exit_code}\n"
        cat "${test_result_json}"
        docker container stop -t 0 $cid > /dev/null
        exit 1
    fi

    docker container stop -t 0 $cid > /dev/null
    if [[ $? != 0 ]]; then
       echo -e "${REDB}Failed to stop docker container ${cid}! (exit code: $?)${CLR}"
       exit 1
    fi

    diff=$(diff -u "${expected_result_stdout}" "${test_result_stdout}")
    if [[ $? != 0 ]]; then
        echo -e "${test_name} ${REDB}FAILED${CLR}.\n\n${diff}\n"
        exit 1
    fi

    diff=$(diff -u "${expected_result_json}" "${test_result_json}")
    if [[ $? != 0 ]]; then
        echo -e "${test_name} ${REDB}FAILED${CLR}.\n\n${diff}\n"
        exit 1
    fi

    echo -e "${test_name} ${GREEN}passed${CLR}."
}


# First check if docker is functional.
docker version > /dev/null
if [[ $? != 0 ]]; then
    echo -e "${REDB}Error: 'docker version' command failed (error code: $?).  Is docker installed and functioning?${CLR}"
    exit 1
fi


# Check if the docker image is the most up-to-date version.
docker_image_exists=0
check_if_docker_image_exists
if [[ $? == 0 ]]; then
    docker_image_exists=1
fi


# Check if the user specified --create to build a new image.
if [[ ($# == 1) && ($1 == "--create") ]]; then
    # Ensure that the image name doesn't already exist before building.
    if [[ $docker_image_exists == 1 ]]; then
        echo -e "${REDB}Error: --create specified, but $IMAGE_NAME:$IMAGE_VERSION already exists!${CLR}"
        exit 1
    else
        echo -e "\nCreating docker image $IMAGE_NAME:$IMAGE_VERSION..."
        create_docker_image
        echo -e "\n${GREEN}Done creating docker image!${CLR}"
        exit 0
    fi
fi


# If we weren't explicitly told to create a new image, and it doesn't exist, then pull it from Dockerhub.
if [[ $docker_image_exists == 0 ]]; then
    echo -e "\nPulling docker image $IMAGE_NAME:$IMAGE_VERSION..."
    pull_docker_image
fi


echo -e "\n${GREEN}Starting tests...${CLR}"

# Create a temporary directory to write test results to.
TEST_RESULT_DIR=$(mktemp -d /tmp/ssh-audit_test-results_XXXXXXXXXX)

# Now run all the tests.
echo -e "\nRunning tests..."
run_openssh_test '4.0p1' 'test1' $PROGRAM_RETVAL_FAILURE
echo
run_openssh_test '5.6p1' 'test1' $PROGRAM_RETVAL_FAILURE
run_openssh_test '5.6p1' 'test2' $PROGRAM_RETVAL_FAILURE
run_openssh_test '5.6p1' 'test3' $PROGRAM_RETVAL_FAILURE
run_openssh_test '5.6p1' 'test4' $PROGRAM_RETVAL_FAILURE
run_openssh_test '5.6p1' 'test5' $PROGRAM_RETVAL_FAILURE
echo
run_openssh_test '8.0p1' 'test1' $PROGRAM_RETVAL_FAILURE
run_openssh_test '8.0p1' 'test2' $PROGRAM_RETVAL_FAILURE
run_openssh_test '8.0p1' 'test3' $PROGRAM_RETVAL_WARNING
echo
run_dropbear_test '2019.78' 'test1' '-r /etc/dropbear/dropbear_rsa_host_key_1024 -r /etc/dropbear/dropbear_dss_host_key -r /etc/dropbear/dropbear_ecdsa_host_key' 3
echo
run_tinyssh_test '20190101' 'test1' $PROGRAM_RETVAL_WARNING
echo
echo
run_custom_policy_test 'config1' 'test1' $PROGRAM_RETVAL_GOOD
run_custom_policy_test 'config1' 'test2' $PROGRAM_RETVAL_FAILURE
run_custom_policy_test 'config1' 'test3' $PROGRAM_RETVAL_FAILURE
run_custom_policy_test 'config1' 'test4' $PROGRAM_RETVAL_FAILURE
run_custom_policy_test 'config1' 'test5' $PROGRAM_RETVAL_FAILURE
run_custom_policy_test 'config2' 'test6' $PROGRAM_RETVAL_GOOD

# Passing test with host key certificate and CA key certificates.
run_custom_policy_test 'config3' 'test7' $PROGRAM_RETVAL_GOOD

# Failing test with host key certificate and non-compliant CA key length.
run_custom_policy_test 'config3' 'test8' $PROGRAM_RETVAL_FAILURE

# Failing test with non-compliant host key certificate and CA key certificate.
run_custom_policy_test 'config3' 'test9' $PROGRAM_RETVAL_FAILURE

# Failing test with non-compliant host key certificate and non-compliant CA key certificate.
run_custom_policy_test 'config3' 'test10' $PROGRAM_RETVAL_FAILURE

# Passing test with host key size check.
run_custom_policy_test 'config2' 'test11' $PROGRAM_RETVAL_GOOD

# Failing test with non-compliant host key size check.
run_custom_policy_test 'config2' 'test12' $PROGRAM_RETVAL_FAILURE

# Passing test with DH modulus test.
run_custom_policy_test 'config2' 'test13' $PROGRAM_RETVAL_GOOD

# Failing test with DH modulus test.
run_custom_policy_test 'config2' 'test14' $PROGRAM_RETVAL_FAILURE

# Passing test for built-in OpenSSH 8.0p1 server policy.
run_builtin_policy_test "Hardened OpenSSH Server v8.0 (version 1)" "8.0p1" "test1" "-o HostKeyAlgorithms=rsa-sha2-512,rsa-sha2-256,ssh-ed25519 -o KexAlgorithms=curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256 -o Ciphers=chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr -o MACs=hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" $PROGRAM_RETVAL_GOOD

# Failing test for built-in OpenSSH 8.0p1 server policy (MACs not hardened).
run_builtin_policy_test "Hardened OpenSSH Server v8.0 (version 1)" "8.0p1" "test2" "-o HostKeyAlgorithms=rsa-sha2-512,rsa-sha2-256,ssh-ed25519 -o KexAlgorithms=curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256 -o Ciphers=chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" $PROGRAM_RETVAL_FAILURE


if [[ $num_failures == 0 ]]; then
    echo -e "\n${GREENB}ALL TESTS PASS!${CLR}\n"
    rm -rf -- "$TEST_RESULT_DIR"
else
    echo -e "\n${REDB}${num_failures} TESTS FAILED!${CLR}\n"
fi

exit 0

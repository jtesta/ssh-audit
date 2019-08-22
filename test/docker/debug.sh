#!/bin/bash

# This script is run on in docker container.  It will enable logging for sshd in
# /var/log/auth.log.

/etc/init.d/rsyslog start
sleep 1
/openssh/sshd-5.6p1 -o LogLevel=DEBUG3 -f /etc/ssh/sshd_config-5.6p1_test1
/bin/bash

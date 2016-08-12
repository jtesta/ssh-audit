# ssh-audit
**ssh-audit** is a tool for ssh server auditing.  

## Features
- grab banner, detect ssh1 protocol and zlib compression;
- gather key-exchange, host-key, encryption and message authentication code algorithms;
- output algorithm information (available since, removed/disabled, unsafe/weak/legacy, etc);
- analyze SSH version compatibility based on algorithm information;
- historical information from OpenSSH and Dropbear SSH;
- no dependencies, compatible with python2 and python3;

## Usage
```
usage: ssh-audit.py [-nv] host[:port]

   -v  verbose
   -n  disable colors
```
Verbose flag will fill each row, i.e, not leave blanks, for easier usage with _batch_ scripts or with manual grepping.

### example
![screenshot](https://cloud.githubusercontent.com/assets/7356025/17623665/da5281c8-60a9-11e6-9582-13f9971c22e0.png)  

## ChangeLog
### v1.0.20160812
 - implement SSH version compatibility feature
 - fix wrong mac algorithm warning
 - fix Dropbear SSH version typo
 - parse pre-banner header
 - better errors handling

### v1.0.20160803
 - use OpenSSH 7.3 banner
 - add new key-exchange algorithms

### v1.0.20160207
 - use OpenSSH 7.2 banner
 - additional warnings for OpenSSH 7.2 
 - fix OpenSSH 7.0 failure messages
 - add rijndael-cbc failure message from OpenSSH 6.7

### v1.0.20160105
 - multiple additional warnings
 - support for none algorithm
 - better compression handling  
 - ensure reading enough data (fixes few Linux SSH)  

### v1.0.20151230
 - Dropbear SSH support  

### v1.0.20151223
 - initial version  

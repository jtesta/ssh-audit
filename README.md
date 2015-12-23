# ssh-audit
**ssh-audit** is a tool for ssh server auditing.  

## Features
- grab banner, detect ssh1 protocol and zlib compression;
- gather key-exchange, host-key, encryption and message authentication code algorithms;
- output algorithm information (available since, removed/disabled, unsafe/weak/legacy, etc);

## Usage
```
usage: ssh-audit.py [-nv] host[:port]

   -v  verbose
   -n  disable colors
```
Verbose flag will fill each row, i.e, not leave blanks, for easier usage with _batch_ scripts or with manual grepping.

### example
![screenshot](https://cloud.githubusercontent.com/assets/7356025/11970583/38f46984-a936-11e5-9489-7283dfca8d79.png)  

## ChangeLog
### v1.0.20151223
 - initial version  

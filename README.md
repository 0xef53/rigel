Rigel
-------------
[![Build Status](https://drone.io/github.com/0xef53/rigel/status.png)](https://drone.io/github.com/0xef53/rigel/latest)

Rigel is a small anti-malware tool for PHP sites.

### Getting binary

Latest version is available [here](https://drone.io/github.com/0xef53/rigel/files/rigel)

### Installing from source

    go build rigel.go

### How to use

    MANUL_DB='https://raw.githubusercontent.com/antimalware/manul/master/src/scanner/static/signatures/malware_db.xml'
    ./rigel --database $MANUL_DB -n 8 --rootdir mysite.com/www/ --filter 'php,inc,js,xml' --skip-soft


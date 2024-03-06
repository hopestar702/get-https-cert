# About
This is a simple C code to get the public certificate from an https endpoint using OpenSSL functions.
## Command to build and test in Linux
```
gcc ssltest.c -Wall -O0 -g3 -std=c99 -lcrypto -lssl -o get-https-cert
./get-https-cert
```
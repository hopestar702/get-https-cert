# About
This is a simple C code to get the public certificate from an https endpoint using OpenSSL functions.
## Command to build and test in Linux
```
gcc ssltest.c -Wall -O0 -g3 -std=c99 -lcrypto -lssl -o get-https-cert
./get-https-cert hostname port
```

## Command to get the cert using OpenSSL
```
echo | openssl s_client -servername www.example.com -connect www.example.com:443 2>/dev/null | openssl x509 > cert.pem
```
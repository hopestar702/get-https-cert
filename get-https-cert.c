#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s hostname port\n", argv[0]);
        return 1;
    }

    const char* hostname = argv[1];
    const char* port = argv[2];
    BIO *bio;
    SSL *ssl;
    SSL_CTX *ctx;

    // Initialize the OpenSSL library
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    // Create a new SSL context
    ctx = SSL_CTX_new(SSLv23_client_method());

    // Create a new SSL connection
    bio = BIO_new_ssl_connect(ctx);

    // Set the SSL connection to connect to the server
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, hostname);
    BIO_set_conn_port(bio, port);

    // Set the SNI extension
    SSL_set_tlsext_host_name(ssl, hostname);

    // Perform the SSL handshake
    if(BIO_do_connect(bio) <= 0) {
        printf("Failed connection\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    // Get the server's certificate
    X509* cert = SSL_get_peer_certificate(ssl);
    if(cert) {
        FILE* fp = fopen("cert.pem", "w");
        if(fp) {
            PEM_write_X509(fp, cert);
            fclose(fp);
        }
        X509_free(cert);
    } else {
        printf("No certificate.\n");
    }

    // Clean up
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return 0;
}
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

int main() {
    const char* hostname = "www.google.com:443";
    BIO* bio;
    SSL* ssl;
    SSL_CTX* ctx;

    // Initialize the OpenSSL library
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    // Set up the SSL context
    ctx = SSL_CTX_new(SSLv23_client_method());

    // Create a new SSL BIO
    bio = BIO_new_ssl_connect(ctx);

    // Set the SSL_MODE_AUTO_RETRY flag
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    // Create a connection
    BIO_set_conn_hostname(bio, hostname);

    if(BIO_do_connect(bio) <= 0) {
        // Handle failed connection
        printf("Failed connection\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Get the peer's certificate
    X509* cert = SSL_get_peer_certificate(ssl);
    if(cert) {
        X509_NAME* subject = X509_get_subject_name(cert);
        if(subject) {
            printf("Subject: ");
            X509_NAME_print_ex_fp(stdout, subject, 0, XN_FLAG_MULTILINE);
            printf("\n");
        }

        X509_NAME* issuer = X509_get_issuer_name(cert);
        if(issuer) {
            printf("Issuer: ");
            X509_NAME_print_ex_fp(stdout, issuer, 0, XN_FLAG_MULTILINE);
            printf("\n");
        }

        // Convert the certificate to a string
        BIO* cert_bio = BIO_new(BIO_s_mem());
        PEM_write_bio_X509(cert_bio, cert);
        BUF_MEM* cert_buf;
        BIO_get_mem_ptr(cert_bio, &cert_buf);
        char* cert_str = cert_buf->data;

        // Print the certificate string
        printf("Certificate:\n%s\n", cert_str);

        // Clean up
        BIO_free(cert_bio);
        X509_free(cert);
    }

    // Clean up
    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    return 0;
}
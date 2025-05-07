#include <openssl/ssl.h>
#include <openssl/err.h>

void unsafe_connection(SSL *ssl) {
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL) {
        // no cert, abort
        return;
    }

    // *** MISSING: SSL_get_verify_result() check ***

    // Directly reading/writing data without verifying certificate
    char buffer[1024];
    SSL_read(ssl, buffer, sizeof(buffer));
    SSL_write(ssl, "Hello", 5);

    X509_free(cert);
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
 
// Function to check if EC certificate has named or explicit parameters
int check_ec_named_group_or_explicit_params(X509 *cert) {
    if (!cert) {
        fprintf(stderr, "Error: Null certificate provided.\n");
        return -1;
    }
 
    // Retrieve the public key from the certificate
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (!pkey) {
        fprintf(stderr, "Error: Could not retrieve public key from certificate.\n");
        return -1;
    }
 
    // Check if the public key is an EC key
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        EVP_PKEY_free(pkey);
        return 0; // Not an EC key
    }
 
    // Extract EC_KEY from EVP_PKEY (this is available in OpenSSL 1.0.2)
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec_key) {
        fprintf(stderr, "Error: Could not retrieve EC_KEY from EVP_PKEY.\n");
        EVP_PKEY_free(pkey);
        return -1;
    }
 
    // Get the EC_GROUP from the EC_KEY object
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    if (!group) {
        fprintf(stderr, "Error: Could not retrieve EC_GROUP from EC_KEY.\n");
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        return -1;
    }
 
    // Check if the group uses a named curve
    int curve_nid = EC_GROUP_get_curve_name(group);
    if (curve_nid != NID_undef) {
        // Named curve detected
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        return 1;
    }
 
    // If no named curve, check if the EC parameters are explicit
    unsigned char *asn1_buf = NULL;
    int asn1_len = i2d_ECParameters(ec_key, &asn1_buf);
    if (asn1_len > 0 && asn1_buf != NULL) {
        // Explicit curve parameters are defined
        OPENSSL_free(asn1_buf);
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        return -2; // Explicit parameters detected
    }
 
    // Clean up if we encounter an error during serialization
    if (asn1_buf) {
        OPENSSL_free(asn1_buf);
    }
 
    EC_KEY_free(ec_key);
    EVP_PKEY_free(pkey);
    fprintf(stderr, "Error: Could not determine EC parameter encoding.\n");
    return -1;
}
 
 
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <certificate_file>\n", argv[0]);
        return 1;
    }
 
    const char *cert_file = argv[1];
    FILE *fp = NULL;
    X509 *cert = NULL;
 
    // Initialize OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
 
    // Open the certificate file
    fp = fopen(cert_file, "r");
    if (!fp) {
        perror("Error opening certificate file");
        goto cleanup;
    }
 
    // Read the X509 certificate
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!cert) {
        fprintf(stderr, "Error reading X509 certificate.\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
 
    // Check named EC group or explicit parameters
    int result = check_ec_named_group_or_explicit_params(cert);
    if (result == 1) {
        printf("Certificate has EC key with a named group.\n");
    } else if (result == -2) {
        printf("Certificate has EC key with explicit parameters.\n");
    } else if (result == 0) {
        printf("Certificate does not have an EC public key.\n");
    } else if (result == -1) {
        printf("Error occurred while checking the certificate.\n");
    }
 
cleanup:
    if (cert) X509_free(cert);
    if (fp) fclose(fp);
 
    EVP_cleanup();
    ERR_free_strings();
 
    return 0;
}

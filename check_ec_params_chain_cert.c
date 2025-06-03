#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
 
// Function to check whether EC uses named curves or explicit EC parameters
int check_ec_named_group_or_explicit_params(X509 *cert) {
    if (!cert) {
        fprintf(stderr, "Error: Null certificate provided.\n");
        return -1;
    }
 
    // Retrieve public key from the certificate
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (!pkey) {
        fprintf(stderr, "Error: Could not retrieve public key from certificate.\n");
        return -1;
    }
 
    // Check if the public key is of EC type
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        EVP_PKEY_free(pkey);
        return 0; // Not an EC key
    }
 
    // Extract EC_KEY from EVP_PKEY
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
        // Explicit parameters detected
        OPENSSL_free(asn1_buf);
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        return -2;
    }
 
    // Cleanup and handle errors
    if (asn1_buf) {
        OPENSSL_free(asn1_buf);
    }
 
    EC_KEY_free(ec_key);
    EVP_PKEY_free(pkey);
    fprintf(stderr, "Error: Could not determine EC parameter encoding.\n");
    return -1;
}
 
// Function to process a PEM file with a certificate chain
void process_certificate_chain(const char *cert_file) {
    FILE *fp = fopen(cert_file, "r");
    if (!fp) {
        perror("Error opening certificate file");
        return;
    }
 
    X509 *cert = NULL;
    int i = 0;
 
    printf("Processing certificate chain from file: %s\n", cert_file);
 
    // Loop to process all certificates in the chain
    while ((cert = PEM_read_X509(fp, NULL, NULL, NULL))) {
        i++;
        printf("\nCertificate #%d:\n", i);
 
        // Attempt to determine if the certificate uses named curves or explicit params
        int result = check_ec_named_group_or_explicit_params(cert);
        if (result == 1) {
            printf("  -> EC key uses a named group.\n");
        } else if (result == -2) {
            printf("  -> EC key uses explicit elliptic curve parameters.\n");
        } else if (result == 0) {
            printf("  -> This certificate does not have an EC public key.\n");
        } else {
            printf("  -> An error occurred while checking this certificate.\n");
        }
 
        X509_free(cert); // Free the current cert before moving to the next
    }
 
    fclose(fp);
    if (i == 0) {
        printf("No certificates found in the provided file.\n");
    }
}
 
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <certificate_chain.pem>\n", argv[0]);
        return 1;
    }
 
    // Initialize OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
 
    // Process the provided certificate chain
    process_certificate_chain(argv[1]);
 
    // Cleanup OpenSSL
    EVP_cleanup();
    ERR_free_strings();
 
    return 0;
}

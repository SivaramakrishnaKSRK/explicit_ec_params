#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <openssl/ssl.h> // For SSL_library_init and BIO_s_file
#include <openssl/bio.h> // Required for BIO functions
#include <openssl/crypto.h> // For CRYPTO_cleanup_all_ex_data
#include <openssl/x509_vfy.h> // Required for X509_STORE, X509_STORE_CTX
 
// Function to check whether EC uses named curves or explicit EC parameters
// Returns:
//   1  : EC key uses a named group
//   -2 : EC key uses explicit elliptic curve parameters
//   0  : Not an EC key
//   -1 : An error occurred during processing
int check_ec_params_type(X509 *cert) {
    if (!cert) {
        fprintf(stderr, "Error: Null certificate provided to check_ec_params_type.\n");
        return -1;
    }
 
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (!pkey) {
        fprintf(stderr, "Error: Could not retrieve public key from certificate for type check.\n");
        ERR_print_errors_fp(stderr); // Print OpenSSL errors
        return -1;
    }
 
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        EVP_PKEY_free(pkey);
        return 0; // Not an EC key
    }
 
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec_key) {
        fprintf(stderr, "Error: Could not retrieve EC_KEY from EVP_PKEY for type check.\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        return -1;
    }
 
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    if (!group) {
        fprintf(stderr, "Error: Could not retrieve EC_GROUP from EC_KEY for type check.\n");
        ERR_print_errors_fp(stderr);
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        return -1;
    }
 
    int curve_nid = EC_GROUP_get_curve_name(group);
 
    EC_KEY_free(ec_key);
    EVP_PKEY_free(pkey);
 
    if (curve_nid != NID_undef) {
        return 1; // Named curve
    } else {
        return -2; // Explicit parameters
    }
}
 
// Function to check a single certificate and report its EC parameter type
int check_and_report_cert(X509 *cert, BIO *bio_out, int *overall_invalid_flag) {
    if (!cert) return 0; // Nothing to check
 
    BIO_printf(bio_out, "  Subject: ");
    X509_NAME_print_ex(bio_out, X509_get_subject_name(cert), 0, XN_FLAG_RFC2253);
    BIO_printf(bio_out, "\n");
 
    int cert_ec_type = check_ec_params_type(cert);
 
    if (cert_ec_type == 1) {
        BIO_printf(bio_out, "    -> EC key uses a named group.\n");
    } else if (cert_ec_type == -2) {
        BIO_printf(bio_out, "    -> EC key uses explicit elliptic curve parameters. (FLAGGED AS INVALID)\n");
        *overall_invalid_flag = 1; // Mark as invalid
    } else if (cert_ec_type == 0) {
        BIO_printf(bio_out, "    -> This certificate does not have an EC public key.\n");
    } else { // cert_ec_type == -1 (error)
        BIO_printf(bio_out, "    -> An error occurred while checking this certificate's EC parameters.\n");
        *overall_invalid_flag = 1; // Mark as invalid
    }
    return *overall_invalid_flag;
}
 
 
// Function to process a single certificate (end-entity) and verify its chain
// against a trusted CA store, then check all certs in the built chain.
void process_single_cert_with_ca_trust(const char *cert_file, const char *ca_file) {
    FILE *fp = NULL;
    X509 *cert = NULL;
    X509_STORE *cert_store = NULL;
    X509_STORE_CTX *ctx = NULL;
    STACK_OF(X509) *chain = NULL;
    BIO *bio_stdout = NULL;
    int overall_invalid_due_to_explicit_params = 0;
    int ret = 1; // Assume failure until success
 
    // 1. Load the end-entity certificate
    fp = fopen(cert_file, "r");
    if (!fp) {
        perror("Error opening end-entity certificate file");
        goto end;
    }
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    fp = NULL; // Reset fp
    if (!cert) {
        fprintf(stderr, "Error: Could not read end-entity certificate from %s.\n", cert_file);
        ERR_print_errors_fp(stderr);
        goto end;
    }
 
    // 2. Create and configure the X509_STORE
    cert_store = X509_STORE_new();
    if (!cert_store) {
        fprintf(stderr, "Error: Could not create X509_STORE.\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
 
    // Load the trusted CA certificate(s) into the store
    if (!X509_STORE_load_locations(cert_store, ca_file, NULL)) {
        fprintf(stderr, "Error: Could not load CA certificate(s) from %s.\n", ca_file);
        ERR_print_errors_fp(stderr);
        goto end;
    }
    printf("Loaded CA certificate(s) from: %s\n", ca_file);
 
    // 3. Create a verification context
    ctx = X509_STORE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Could not create X509_STORE_CTX.\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
 
    // Initialize the context with the certificate to verify, the store, and any untrusted intermediates
    // In this scenario, we assume the input `cert_file` contains only the end-entity cert.
    // If you had intermediates in a separate file, you'd load them into a STACK and pass to ctx.
    if (!X509_STORE_CTX_init(ctx, cert_store, cert, NULL)) {
        fprintf(stderr, "Error: Could not initialize X509_STORE_CTX.\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
 
    // Create BIO for output
    bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (!bio_stdout) {
        fprintf(stderr, "Error: Could not create BIO for stdout.\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
 
    printf("\nAttempting to verify and process certificate chain for: %s\n", cert_file);
    printf("-------------------------------------------------------------------\n");
 
    // 4. Perform verification
    // This will build the chain if successful.
    int verify_result = X509_verify_cert(ctx);
 
    if (verify_result == 1) {
        printf("Certificate verification successful.\n");
    } else {
        fprintf(stderr, "Certificate verification failed: %s (%d)\n",
                X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)),
                X509_STORE_CTX_get_error(ctx));
        // Even if verification fails, we might still have a partial chain to check
    }
 
    // 5. Retrieve the constructed chain (verified or partial)
    chain = X509_STORE_CTX_get_chain(ctx);
    if (!chain) {
        fprintf(stderr, "Warning: No certificate chain could be built or retrieved.\n");
        // We might still want to check the original cert if no chain was built.
        BIO_printf(bio_stdout, "\nChecking original certificate (if chain not built):\n");
        check_and_report_cert(cert, bio_stdout, &overall_invalid_due_to_explicit_params);
        if (overall_invalid_due_to_explicit_params) ret = 1; else ret = 0;
        goto end;
    }
 
    printf("\nProcessing certificates in the built chain:\n");
    int i;
    for (i = 0; i < sk_X509_num(chain); i++) {
        X509 *current_cert_in_chain = sk_X509_value(chain, i);
        BIO_printf(bio_stdout, "Certificate in chain #%d (Level %d):\n", i + 1, sk_X509_num(chain) - 1 - i); // Level 0 is end-entity
        check_and_report_cert(current_cert_in_chain, bio_stdout, &overall_invalid_due_to_explicit_params);
    }
    printf("-------------------------------------------------------------------\n");
 
 
    // Final result
    if (overall_invalid_due_to_explicit_params) {
        printf("\nOverall result: **INVALID** - At least one EC certificate in the constructed chain uses explicitly defined parameters.\n");
        ret = 1; // Indicate failure
    } else {
        printf("\nOverall result: **VALID** - All EC certificates in the constructed chain use named groups.\n");
        ret = 0; // Indicate success
    }
 
end:
    // Cleanup
    if (cert) X509_free(cert);
    if (ctx) X509_STORE_CTX_free(ctx);
    if (cert_store) X509_STORE_free(cert_store);
    // chain is freed by X509_STORE_CTX_free, no need to free explicitly
    if (bio_stdout) BIO_free(bio_stdout);
 
    // Exit with the appropriate status
    exit(ret);
}
 
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <end_entity_certificate.pem> <trusted_ca_certificates.pem>\n", argv[0]);
        return 1;
    }
 
    // Initialize OpenSSL libraries for 1.0.2
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
 
    // Process the provided certificate chain
    process_single_cert_with_ca_trust(argv[1], argv[2]);
 
    // Cleanup OpenSSL resources for 1.0.2
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
 
    return 0; // Should not be reached if exit() is called
}

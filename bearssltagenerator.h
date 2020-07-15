#pragma once

#include <bearssl.h>

typedef struct {
	int key_type;  /* BR_KEYTYPE_RSA or BR_KEYTYPE_EC */
	union {
		br_rsa_private_key rsa;
		br_ec_private_key ec;
	} key;
} private_key;

typedef struct {
	char *name;
	unsigned char *data;
	size_t data_len;
} pem_object;

/**
 * @brief Generates trust anchors for BearSSL from the contents of \p ca_file and stores them
 * in the \p anchOut array (based on code in BearSSL tools)
 * 
 * @returns The number of trust anchors generated
 */ 
size_t get_trusted_anchors(const char *cert_file, br_x509_trust_anchor *anchOut[]);

/**
 * @brief Converts a private key in a PEM file to BearSSL format
 * 
 * @param key_file[in] The name of the file containing the private key
 * @param priv_key[out] BearSSL format private key
 * 
 * @return zero for success
 */
int read_private_key(const char *key_file, private_key **priv_key);

/**
 * @brief Converts an X.509 certificate(s) in PEM format used to authenticate the client 
 * into BearSSL format.
 * 
 * @param certs_filename[in] The name of the file containing the certficates
 * @param certs[out] The converted certficates
 * 
 * @return zero for success
 */
int read_certificates_string(const char *certs_filename, br_x509_certificate **certs);



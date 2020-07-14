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

int read_private_key(const char *key_file, private_key **priv_key);

int read_certificates_string(const char *certs_filename, br_x509_certificate **certs);



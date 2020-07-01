#pragma once

#include <bearssl.h>

/**
 * @brief Generates trust anchors for BearSSL from the contents of \p ca_file and stores them
 * in the \p anchOut array (based on code in BearSSL tools)
 * 
 * @returns The number of trust anchors generated
 */ 
size_t get_trusted_anchors(const char *ca_file, br_x509_trust_anchor **anchOut);

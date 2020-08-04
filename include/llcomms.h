#pragma once

#include <mqtt_pal.h>

/**
 * @brief Initialize the BearSSL library
 * 
 * @param ctx[in] Control block
 * @param bearssl_iotbuf[in] Buffer for BearSSL
 * @param bearssl_iobuf_len Length of buffer
 */
int initialize_TLS(bearssl_context *ctx, br_x509_certificate *x509cert, int x509cert_count, private_key *x509pk, uint8_t *bearssl_iobuf, size_t bearssl_iobuf_len);

/**
 * @brief Open a nonblocking socket to the MQTT broker
 * 
 * @param ctx[in] Control block
 * @param hostname[in] Host name
 * @param port[in] Port
 * 
 * @returns 0 = success, -1 = retry, -2 = unrecoverable error
 */
int open_nb_socket(bearssl_context *ctx, const char *hostname, const char *port);
                    
/**
 * @brief Close the socket
 * 
 * @param ctx[in] Control block
 * 
 * @returns Return code from close
 */
int close_socket(bearssl_context *ctx);

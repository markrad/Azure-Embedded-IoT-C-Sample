#pragma once

#include <mqtt_pal.h>

void initialize_TLS(bearssl_context *ctx, uint8_t *bearssl_iobuf, size_t bearssl_iobuf_len);

int open_nb_socket(bearssl_context *ctx, const char *hostname, const char *port);
                    
int close_socket(bearssl_context *ctx);

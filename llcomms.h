#pragma once

#include <mqtt_pal.h>

int open_nb_socket(bearssl_context *ctx,
                    const char *hostname,
                    const char *port,
                    unsigned char *bearssl_iobuf,
                    size_t bearssl_iobuf_len);
int close_socket(bearssl_context *ctx);

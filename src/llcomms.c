#ifndef __BEARSSL_SOCKET_TEMPLATE_H__
#define __BEARSSL_SOCKET_TEMPLATE_H__

#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <mqtt_pal.h>

#include <bearssl.h>

#include "bearssltagenerator.h"

//#include "mqtt_pal.h"

/*
 * Low-level data read callback for the simplified SSL I/O API.
 */
static int sock_read(void *ctx, unsigned char *buf, size_t len) {
	ssize_t rlen;

	for (;;) {
		rlen = read(*(int *)ctx, buf, len);

        if (rlen < 0) {
            if (errno == EINTR) {
                continue;
            }
            else if (errno == EWOULDBLOCK || errno == EAGAIN) {
                rlen = 0;
                break;
            }
            else {
                break;
            }
        }
        else {
            break;
        }
	}
    
    return (int)rlen;
}

/*
 * Low-level data write callback for the simplified SSL I/O API.
 */
static int sock_write(void *ctx, const unsigned char *buf, size_t len) {
    ssize_t wlen;
    
    for (;;) {

		wlen = write(*(int *)ctx, buf, len);
		if (wlen <= 0 && errno == EINTR) {
            continue;
        }
		return (int)wlen;
	}
}

static int host_connect(const char *host, const char *port) {
    struct hostent *he;
    struct in_addr **addr_list;

    if (NULL == (he = gethostbyname(host)))
    {
        fprintf(stderr, "Failed to resolve host name\n");
        return -2;
    }

    addr_list = (struct in_addr **) he->h_addr_list;

    int sockfd = -1;
    int rv;
    int i;

    if (-1 == (sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)))
        return -2;

    struct sockaddr_in server;

    server.sin_family = AF_INET;
    server.sin_port = htons(atoi(port));

    /* open the first possible socket */
    for (i = 0; addr_list[i] != NULL; i++)
    {
        memcpy(&server.sin_addr.s_addr, he->h_addr_list[0], he->h_length);

        if (0 > (rv = connect(sockfd, (struct sockaddr *)&server , sizeof(server)))) {
            continue;
        }
        else {
            int flags = fcntl(sockfd, F_GETFL, 0);
            flags |= O_NONBLOCK;
            fcntl(sockfd, F_SETFL, flags);
            break;
        }
    }

    if (addr_list[i] == NULL)
        sockfd = -1;

    /* return the new socket fd */
    return sockfd;
}

static int get_cert_signer_algo(br_x509_certificate *xc)
{
	br_x509_decoder_context dc;
	int result;

	br_x509_decoder_init(&dc, 0, 0);
	br_x509_decoder_push(&dc, xc->data, xc->data_len);
	result = br_x509_decoder_last_error(&dc);

	if (result != 0) 
    {
		printf("Failed to get signer algorithm %d\n", result);
        result = 0;
	}
    else
    {
    	result = br_x509_decoder_get_signer_key_type(&dc);
    }

    return result;
}

int initialize_TLS(bearssl_context *ctx, br_x509_certificate *x509cert, int x509cert_count, private_key *x509pk, uint8_t *bearssl_iobuf, size_t bearssl_iobuf_len)
{
    unsigned int cert_signer_algo;
    int result = 0;

    br_ssl_client_init_full(&ctx->sc, &ctx->xc, ctx->anchOut, ctx->ta_count);
	br_ssl_engine_set_buffer(&ctx->sc.eng, bearssl_iobuf, bearssl_iobuf_len, 1);

    if (x509pk != NULL)
    {
        switch (x509pk->key_type)
        {
        case BR_KEYTYPE_RSA:
            br_ssl_client_set_single_rsa(
                &ctx->sc, 
                x509cert, 
                x509cert_count, 
                &x509pk->key.rsa, 
                br_rsa_pkcs1_sign_get_default());
            break;
        case BR_KEYTYPE_EC:
            cert_signer_algo = get_cert_signer_algo(x509cert);

            if (cert_signer_algo == 0)
            {
                result = -1;
            }
            else
            {
                br_ssl_client_set_single_ec(
                    &ctx->sc,
                    x509cert,
                    x509cert_count,
                    &x509pk->key.ec,
                    BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN, 
                    cert_signer_algo,
                    br_ec_get_default(),
                    br_ecdsa_sign_asn1_get_default());
            }
            break;
        default:
            printf("Unrecognized private key type\n");
            result = -1;
        }
    }

    ctx->low_read = sock_read;
    ctx->low_write = sock_write;

    return result;
}

int open_nb_socket(bearssl_context *ctx,
                    const char *hostname,
                    const char *port,
                    unsigned char *bearssl_iobuf,
                    size_t bearssl_iobuf_len) {

    if (0 >= (ctx->fd = host_connect(hostname, port)))
        return ctx->fd;

    /* reset the BearSSL engine */
	br_ssl_client_reset(&ctx->sc, hostname, 0);

    return 0;
}

int close_socket(bearssl_context *ctx) {
    int rc;

    br_ssl_engine_close(&ctx->sc.eng);

    if (ctx->fd != 0) {
        shutdown(ctx->fd, SHUT_RDWR);
        rc = close(ctx->fd);
        ctx->fd = 0;
    }

    return rc;
}

#endif
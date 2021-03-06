#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <bearssl.h>

#include "heap.h"
#include "azheap.h"
#include "bearssltagenerator.h"
#include "vector_heap.h"

extern HEAPHANDLE hHeap;

typedef struct {
    bool error;
    uint16_t data_length;
    uint16_t buffer_length;
    uint8_t *buffer;
} buffer_head;

/**
 * @brief Callback function to accumulate data in a buffer
 */ 
static void vblob_append(void *cc, const void *data, size_t len);

/**
 * @brief Cleans up allocations made creating trusted anchors
 */
static void free_ta_contents(br_x509_trust_anchor *ta);

/**
 * @brief Free array of trusted anchors
 */
static void free_all_ta_contents(br_x509_trust_anchor *ta, int count);

/**
 * @brief Converts certificate \p xc to a trust anchor in \ta (based on code in BearSSL tools)
 */
static int certificate_to_trust_anchor(br_x509_certificate *xc, br_x509_trust_anchor *ta);

static void vblob_append(void *cc, const void *data, size_t len)
{
    buffer_head *bv = (buffer_head *)cc;

    if (bv->error == false)
    {
        if (bv->data_length + len > bv->buffer_length)
        {
            uint8_t *save = bv->buffer;
            bv->buffer_length += 1024;                                          // Probably the most that will be allocated

            if (NULL == (bv->buffer = heap_realloc(hHeap, bv->buffer, bv->buffer_length)))
            {
                heap_free(hHeap, save);
                bv->error = true;
                return;
            }
        }

        memcpy(bv->buffer + bv->data_length, data, len);
        bv->data_length += len;
    }
}

VECTORHANDLE decode_pem(const char *filename)
{
    VECTORHANDLE pem_list;
	br_pem_decoder_context pc;
	pem_object po;
    buffer_head bv;
	int inobj;
    size_t i;
    FILE *f;
    char input[1];
    bool error = false;

    pem_list = vector_create(hHeap, sizeof(pem_object));

	if (pem_list == NULL)
	{
		printf("Unable to allocate vector to decode PEM\n");
	}
    else if (NULL == (f = fopen(filename, "rb")))
    {
        printf("Unable to open PEM file\n");
        error = true;
    }
	else
	{
		br_pem_decoder_init(&pc);
		inobj = 0;
		po.name = NULL;
		po.data = NULL;
		po.data_len = 0;

		while (!error) 
        {
            if (feof(f))
            {
                // If the PEM file was missing the last newline this will push it to the decoder
                if (input[0] != '\n')
                    input[0] = '\n';
                else
                {
                    fclose(f);
                    break;
                }
            }
            else
            {
                fread(input, 1, 1, f);
            }
			
            if (0 == br_pem_decoder_push(&pc, input, 1))
            {
                switch (br_pem_decoder_event(&pc)) 
                {
                case BR_PEM_BEGIN_OBJ:
                    inobj = 1;

                    if (NULL == (po.name = heap_malloc(hHeap, strlen(br_pem_decoder_name(&pc)) + 1)))
                    {
                        printf("Unable to allocate memory for certificate name\n");
                        break;
                    }

                    strcpy(po.name, br_pem_decoder_name(&pc));
                    bv.buffer = NULL;
                    bv.buffer_length = 0;
                    bv.data_length = 0;
                    bv.error = false;
                    br_pem_decoder_setdest(&pc, vblob_append, &bv);
                    break;

                case BR_PEM_END_OBJ:
                    if (inobj)
                    {
                        if (bv.error == true)
                        {
                            printf("Out of memory decoding pem data\n");
                            break;
                        }

                        po.data = bv.buffer;
                        po.data_len = bv.data_length;
                        vector_append(pem_list, &po);
                        po.name = NULL;
                        po.data = NULL;
                        po.data_len = 0;
                        inobj = 0;
                    }
                    break;

                case BR_PEM_ERROR:
                    printf("ERROR: invalid PEM encoding\n");
                    inobj = 1;
                    error = true;
                    break;
                }

                br_pem_decoder_push(&pc, input, 1);
            }
		}

		if (inobj || error)
		{
			printf("Unable to decode pem\n");

			for (i = 0; i < vector_get_count(pem_list); i++)
			{
				heap_free(hHeap, ((pem_object *)vector_get(pem_list, i))->name);
				heap_free(hHeap, ((pem_object *)vector_get(pem_list, i))->data);
			}

			vector_destroy(pem_list, false);
			heap_free(hHeap, po.name);
			pem_list = NULL;
		}
	}

	return pem_list;
}

int read_certificates_string(const char *certs_filename, br_x509_certificate **certs)
{
	VECTORHANDLE cert_list; 
    VECTORHANDLE pem_list;
	size_t u;
    int result = 0;
    static const char CERTIFICATE[] = "CERTIFICATE";
    static const char X509_CERTIFICATE[] = "X509 CERTIFICATE";
    static const int CERTIFICATE_LEN = sizeof(CERTIFICATE) - 1;
    static const int X509_CERTIFICATE_LEN = sizeof(X509_CERTIFICATE) - 1;

    cert_list = vector_create(hHeap, sizeof(br_x509_certificate));

    if (cert_list == NULL)
    {
        printf("Unable to allocate memory to decode pem strings\n");
        result = -1;
    }
    else
    {
        pem_list = decode_pem(certs_filename);
        
        if (pem_list == NULL) 
        {
            printf("Failed to decode pem\n");
            vector_destroy(cert_list, false);
            result = -1;
        }
        else
        {
            for (u = 0; u < vector_get_count(pem_list); u++) 
            {
                if (0 == memcmp(CERTIFICATE, ((pem_object *)vector_get(pem_list, u))->name, CERTIFICATE_LEN) ||
                    0 == memcmp(X509_CERTIFICATE, ((pem_object *)vector_get(pem_list, u))->name, X509_CERTIFICATE_LEN))
                {
                    br_x509_certificate xc;

                    xc.data = ((pem_object *)vector_get(pem_list, u))->data;
                    xc.data_len = ((pem_object *)vector_get(pem_list, u))->data_len;
                    ((pem_object *)vector_get(pem_list, u))->data = NULL;
                    ((pem_object *)vector_get(pem_list, u))->data_len = 0;
                    heap_free(hHeap, ((pem_object *)vector_get(pem_list, u))->name);
                    ((pem_object *)vector_get(pem_list, u))->name = NULL;

                    result = vector_append(cert_list, &xc);

                    if (result != 0)
                    {
                        printf("Failed to add certificate to vector\n");
                        break;
                    }
                }
                else
                {
                    printf("Unable to determine the certificate type\n");
                }
            }

            // If we enter this loop something failed
            for (; u < vector_get_count(pem_list); u++)
            {
                heap_free(hHeap, ((pem_object *)vector_get(pem_list, u))->name);
                heap_free(hHeap, ((pem_object *)vector_get(pem_list, u))->data);
            }

            vector_destroy(pem_list, false);

            if (0 == vector_get_count(cert_list))
            {
                printf("No certificate in string\n");
                result = -1;
            }

            if (result != 0)
            {
                for (u = 0; u < vector_get_count(cert_list); u++)
                {
                    heap_free(hHeap, ((br_x509_certificate*)vector_get(cert_list, u))->data);
                }

                vector_destroy(cert_list, false);
                result = -1;
            }
        }
    }

    if (result >= 0)
    {
        result = vector_get_count(cert_list);
        *certs = (br_x509_certificate *)vector_get_buffer(cert_list);
        vector_destroy(cert_list, true);
    }

	return result;
}

static void free_private_key(private_key *privkey)
{
    switch (privkey->key_type)
    {
    case BR_KEYTYPE_RSA:
        heap_free(hHeap, privkey->key.rsa.iq);
        heap_free(hHeap, privkey->key.rsa.dq);
        heap_free(hHeap, privkey->key.rsa.dp);
        heap_free(hHeap, privkey->key.rsa.q);
        heap_free(hHeap, privkey->key.rsa.p);
        break;
    case BR_KEYTYPE_EC:
        heap_free(hHeap, privkey->key.ec.x);
        break;
    default:
        printf("Unknown private key type %d\n", privkey->key_type);
    }
}

static private_key *decode_key(const unsigned char *buf, size_t len)
{
	br_skey_decoder_context dc;
	int result;
	private_key *sk;
    int curve;
    uint32_t supp;

	br_skey_decoder_init(&dc);
	br_skey_decoder_push(&dc, buf, len);
	result = br_skey_decoder_last_error(&dc);

	if (result != 0) 
    {
		printf("Error decoding private key: %d\n", result);
        sk = NULL;
	}
    else
    {
        switch (br_skey_decoder_key_type(&dc)) 
        {
            const br_rsa_private_key *rk;
            const br_ec_private_key *ek;

        case BR_KEYTYPE_RSA:
            rk = br_skey_decoder_get_rsa(&dc);
            if (NULL == (sk = (private_key *)heap_malloc(hHeap, sizeof *sk)))
            {
                printf("Failed to allocate memory for RSA key structure\n");
            }
            else  
            {
                memset(sk, 0, sizeof(private_key));

                if (
                    NULL == (sk->key.rsa.p = (unsigned char *)heap_malloc(hHeap, rk->plen)) ||
                    NULL == (sk->key.rsa.q = (unsigned char *)heap_malloc(hHeap, rk->plen)) ||
                    NULL == (sk->key.rsa.dp = (unsigned char *)heap_malloc(hHeap, rk->plen)) ||
                    NULL == (sk->key.rsa.dq = (unsigned char *)heap_malloc(hHeap, rk->plen)) ||
                    NULL == (sk->key.rsa.iq = (unsigned char *)heap_malloc(hHeap, rk->plen))
                    )
                {
                    printf("Failed to allocate memory for RSA key structure\n");
                    free_private_key(sk);
                    sk = NULL;
                }
                else
                {
                    sk->key_type = BR_KEYTYPE_RSA;
                    sk->key.rsa.n_bitlen = rk->n_bitlen;
                    sk->key.rsa.plen = rk->plen;
                    sk->key.rsa.qlen = rk->qlen;
                    sk->key.rsa.dplen = rk->dplen;
                    sk->key.rsa.dqlen = rk->dqlen;
                    sk->key.rsa.iqlen = rk->iqlen;
                    memcpy(sk->key.rsa.p, rk->p, rk->plen);
                    memcpy(sk->key.rsa.q, rk->q, rk->qlen);
                    memcpy(sk->key.rsa.dp, rk->dp, rk->dplen);
                    memcpy(sk->key.rsa.dq, rk->dq, rk->dqlen);
                    memcpy(sk->key.rsa.iq, rk->iq, rk->iqlen);
                }
            }
            break;

        case BR_KEYTYPE_EC:
            ek = br_skey_decoder_get_ec(&dc);
            if (NULL == (sk = (private_key *)heap_malloc(hHeap, sizeof *sk)))
            {
                printf("Failed to allocate memory for EC key structure\n");
            }
            else  
            {
                memset(sk, 0, sizeof(private_key));

                if (NULL == (sk->key.ec.x = (unsigned char *)heap_malloc(hHeap, ek->xlen)))
                {
                    printf("Failed to allocate memory for EC key structure\n");
                    heap_free(hHeap, sk);
                    sk = NULL;
                }
                else
                {
                    sk->key_type = BR_KEYTYPE_EC;
                    sk->key.ec.curve = ek->curve;
                    memcpy(sk->key.ec.x, ek->x, ek->xlen);
                    sk->key.ec.xlen = ek->xlen;
                    curve = sk->key.ec.curve;
                    supp = br_ec_get_default()->supported_curves;

                    if (curve > 31 || !((supp >> curve) & 1)) 
                    {
                        printf("Private key curve (%d) is not supported\n", curve);
                        free_private_key(sk);
                        heap_free(hHeap, sk);
                        sk = NULL;
                    }
                }
            }
            break;

        default:
            printf("Unknown key type: %d\n", br_skey_decoder_key_type(&dc));
            sk = NULL;
            break;
        }
    }

	return sk;
}

int read_private_key(const char *key_file, private_key **priv_key)
{
    static const char RSA_PRIVATE_KEY[] = "RSA PRIVATE KEY";
    static const char EC_PRIVATE_KEY[] = "EC PRIVATE KEY";
    static const char PRIVATE_KEY[] = "PRIVATE KEY";
    static const int RSA_PRIVATE_KEY_LENGTH = sizeof(RSA_PRIVATE_KEY) - 1;
    static const int EC_PRIVATE_KEY_LENGTH = sizeof(EC_PRIVATE_KEY) - 1;
    static const int PRIVATE_KEY_LENGTH = sizeof(PRIVATE_KEY) - 1;

    VECTORHANDLE pos;  // vector of pem_object
	pem_object *work;
    size_t u;

	pos = decode_pem(key_file);
		
    if (pos != NULL) 
    {

        for (u = 0; u < vector_get_count(pos); u++) 
        {
            work = (pem_object *)vector_get(pos, u);

            if (0 == memcmp(work->name, RSA_PRIVATE_KEY, RSA_PRIVATE_KEY_LENGTH) ||
                0 == memcmp(work->name, EC_PRIVATE_KEY, EC_PRIVATE_KEY_LENGTH) ||
                0 == memcmp(work->name, RSA_PRIVATE_KEY, RSA_PRIVATE_KEY_LENGTH))
            {
                *priv_key = decode_key(work->data, work->data_len);
                break;
            }
        }

        if (u >= vector_get_count(pos))
        {
            printf("No private key found in X.509 private key option\n");
            return -1;
        }

        for (u = 0; u < vector_get_count(pos); u++)
        {
            heap_free(hHeap, ((pem_object *)vector_get(pos, u))->name);
            heap_free(hHeap, ((pem_object *)vector_get(pos, u))->data);
        }

        vector_destroy(pos, false);
    }
    else
    {
        return -1;
    }

	return 0;
}

static int certificate_to_trust_anchor(br_x509_certificate *xc, br_x509_trust_anchor *ta) {

    // TODO: Review return value
	br_x509_decoder_context dc;
	br_x509_pkey *pk;
    buffer_head vdn;
    int result = 0;

    vdn.buffer = NULL;
    vdn.buffer_length = 0;
    vdn.data_length = 0;
    vdn.error = false;

    memset(ta, 0, sizeof(br_x509_trust_anchor));
    br_x509_decoder_init(&dc, vblob_append, &vdn);
    br_x509_decoder_push(&dc, xc->data, xc->data_len);
    pk = br_x509_decoder_get_pkey(&dc);

    if (vdn.error != false)
    {
        printf("ERROR: Unable to allocate memory to decode certificate\n");
        return -1;
    }

    if (pk == NULL) 
    {
        printf("ERROR: CA decoding failed with error %d", br_x509_decoder_last_error(&dc));
        return -1;
    }

    vdn.buffer = heap_realloc(hHeap, vdn.buffer, vdn.data_length);
    ta->dn.data = vdn.buffer;
    ta->dn.len = vdn.data_length;
    ta->flags = 0;

    if (br_x509_decoder_isCA(&dc)) 
    {
        ta->flags |= BR_X509_TA_CA;
    }

    switch (pk->key_type) 
    {
    case BR_KEYTYPE_RSA:
        ta->pkey.key_type = BR_KEYTYPE_RSA;
        ta->pkey.key.rsa.nlen = pk->key.rsa.nlen;
        ta->pkey.key.rsa.elen = pk->key.rsa.elen;

        if (NULL == (ta->pkey.key.rsa.n = (unsigned char *)heap_malloc(hHeap, ta->pkey.key.rsa.nlen)) ||
            NULL == ( ta->pkey.key.rsa.e = (unsigned char *)heap_malloc(hHeap, ta->pkey.key.rsa.elen)))
        {
            free_ta_contents(ta);
            return 0;
        }
        else
        {
            memcpy(ta->pkey.key.rsa.n, pk->key.rsa.n, ta->pkey.key.rsa.nlen);
            memcpy(ta->pkey.key.rsa.e, pk->key.rsa.e, ta->pkey.key.rsa.elen);
            result = 0;
        }
        break;
    case BR_KEYTYPE_EC:
        ta->pkey.key_type = BR_KEYTYPE_EC;
        ta->pkey.key.ec.curve = pk->key.ec.curve;
        ta->pkey.key.ec.qlen = pk->key.ec.qlen;

        if (NULL == (ta->pkey.key.ec.q = (unsigned char *)heap_malloc(hHeap, ta->pkey.key.ec.qlen)))
        {
            free_ta_contents(ta);
            return 0;
        }
        else
        {
            memcpy(ta->pkey.key.ec.q, pk->key.ec.q, ta->pkey.key.ec.qlen);
            result = 0;
        }
        break;
    default:
        // ERROR: unsupported public key type in CA
        free_ta_contents(ta);
        return 0;
    }

    return result;
}

static void free_certificates(br_x509_certificate *certs, size_t num)
{
	size_t u;

	for (u = 0; u < num; u ++) {
		heap_free(hHeap, certs[u].data);
	}
}

size_t get_trusted_anchors(const char *cert_file, br_x509_trust_anchor *anchOut[])
{
    // Converts a PEM certificate in a string into the format required by BearSSL
    VECTORHANDLE xcs;
    br_x509_certificate *xcs_span;
    br_x509_trust_anchor work;
	br_x509_trust_anchor *anchArray;
    size_t u;
    size_t v;
    int num;
    int result;

    num = read_certificates_string(cert_file, &xcs_span);
    xcs = vector_wrap(hHeap, xcs_span, sizeof(br_x509_certificate), num);
    //xcs = read_certificates_string(az_span_ptr(content), az_span_size(content));
    //num = vector_get_count(xcs);

    if (num <= 0)
    {
        printf("No certificates found in string\n");
    }
    else
    {
        anchArray = (br_x509_trust_anchor *)heap_malloc(hHeap, sizeof(br_x509_trust_anchor) * num);

        if (anchArray == NULL)
        {
            printf("Memory allocation for trust anchors failed\n");
        }
        else
        {
            *anchOut = anchArray;

            for (u = 0; u < num; u++)
            {
                result = certificate_to_trust_anchor((br_x509_certificate *)vector_get(xcs, u), &work);

                if (result != 0)
                {
                    for (v = 0; v < u; v++)
                    {
                        free_ta_contents((anchOut[u]));
                    }

                    heap_free(hHeap, anchArray);
                    *anchOut = NULL;
                    num = 0;
                    break;
                }

                anchArray[u] = work;
            }
        }
    }

    free_certificates((br_x509_certificate *)vector_get_buffer(xcs), vector_get_count(xcs));
    vector_destroy(xcs, false);
    
	return num;
}

static void free_all_ta_contents(br_x509_trust_anchor *anch, int count)
{
    for (int i = 0; i < count; i++)
    {
        free_ta_contents(anch + i);
    }
}

static void free_ta_contents(br_x509_trust_anchor *ta)
{
	heap_free(hHeap, ta->dn.data);
	switch (ta->pkey.key_type) 
    {
	case BR_KEYTYPE_RSA:
		heap_free(hHeap, ta->pkey.key.rsa.n);
		heap_free(hHeap, ta->pkey.key.rsa.e);
		break;
	case BR_KEYTYPE_EC:
		heap_free(hHeap, ta->pkey.key.ec.q);
		break;
	}

    heap_free(hHeap, ta);
}


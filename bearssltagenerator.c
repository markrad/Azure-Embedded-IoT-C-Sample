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
 * @brief Reads the entire file into a heap allocated buffer. The caller is
 * responsilbe for freeing this buffer.
 * 
 * @param file_name[in] The file to read
 * 
 * @returns az_span containing file contents or NULL if failed
 */
static az_span read_file(const char *file_name)
{
    FILE *f = fopen(file_name, "rb");

    if (f == NULL)
        return AZ_SPAN_NULL;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    az_span content = az_heap_alloc(hHeap, fsize);

    if (az_span_ptr(content) == NULL)
        return AZ_SPAN_NULL;

    long read = fread(az_span_ptr(content), 1, fsize, f);
    
    fclose(f);

    if (read != fsize) {
        az_heap_free(hHeap, content);
        return AZ_SPAN_NULL;
    }

    return content;
}

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

            if (NULL == (bv->buffer = heapRealloc(hHeap, bv->buffer, bv->buffer_length)))
            {
                heapFree(hHeap, save);
                bv->error = true;
                return;
            }
        }

        memcpy(bv->buffer + bv->data_length, data, len);
        bv->data_length += len;
    }
}

VECTORHANDLE decode_pem(const void *src, size_t len)
{
    VECTORHANDLE pem_list;
	br_pem_decoder_context pc;
	pem_object po;
    //pem_object *pos;
	const unsigned char *buf;
    buffer_head bv;
	int inobj;
	int extra_nl;
    size_t i;

    pem_list = vector_create(hHeap, sizeof(pem_object));

	if (pem_list == NULL)
	{
		printf("Unable to allocate vectore to decode PEM\n");
	}
	else
	{
		br_pem_decoder_init(&pc);
		buf = src;
		inobj = 0;
		po.name = NULL;
		po.data = NULL;
		po.data_len = 0;
		extra_nl = 1;

		while (len > 0) {
			size_t tlen;

			tlen = br_pem_decoder_push(&pc, buf, len);
			buf += tlen;
			len -= tlen;
			switch (br_pem_decoder_event(&pc)) {

			case BR_PEM_BEGIN_OBJ:
				inobj = 1;

                if (NULL == (po.name = heapMalloc(hHeap, strlen(br_pem_decoder_name(&pc)) + 1)))
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
					po.data = bv.buffer;;
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
				break;
			}

			/*
			 * We add an extra newline at the end, in order to
			 * support PEM files that lack the newline on their last
			 * line (this is somewhat invalid, but PEM format is not
			 * standardised and such files do exist in the wild, so
			 * we'd better accept them).
			 */
			if (len == 0 && extra_nl) {
				extra_nl = 0;
				buf = (const unsigned char *)"\n";
				len = 1;
			}
		}

		if (inobj)
		{
			printf("Unable to decode pem\n");

			for (i = 0; i < vector_get_count(pem_list); i++)
			{
				heapFree(hHeap, ((pem_object *)vector_get(pem_list, i))->name);
				heapFree(hHeap, ((pem_object *)vector_get(pem_list, i))->data);
			}

			vector_destroy(pem_list, false);
			heapFree(hHeap, po.name);
			pem_list = NULL;
		}
	}

	return pem_list;
}

int read_certificates_string(const char *certs_filename, az_span *certs) //const char *buf, size_t len)
{
	VECTORHANDLE cert_list; 
    VECTORHANDLE pem_list;
	size_t u;
    int result = 0;
    static const char CERTIFICATE[] = "CERTIFICATE";
    static const char X509_CERTIFICATE[] = "X509 CERTIFICATE";
    static const int CERTIFICATE_LEN = sizeof(CERTIFICATE) - 1;
    static const int X509_CERTIFICATE_LEN = sizeof(X509_CERTIFICATE) - 1;

    az_span content = read_file(certs_filename);

    if (az_span_ptr(content) == NULL)
    {
        printf("Failed to read X.509 certificate\n");
        return -1;
    }

    cert_list = vector_create(hHeap, sizeof(br_x509_certificate));

    if (cert_list == NULL)
    {
        printf("Unable to allocate memory to decode pem strings\n");
        result = -1;
    }
    else
    {
        pem_list = decode_pem(az_span_ptr(content), az_span_size(content));
        
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
                    heapFree(hHeap, ((pem_object *)vector_get(pem_list, u))->name);
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
                heapFree(hHeap, ((pem_object *)vector_get(pem_list, u))->name);
                heapFree(hHeap, ((pem_object *)vector_get(pem_list, u))->data);
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
                    heapFree(hHeap, ((br_x509_certificate*)vector_get(cert_list, u))->data);
                }

                vector_destroy(cert_list, false);
                result = -1;
            }
        }
    }

    if (result >= 0)
    {
        result = vector_get_count(cert_list);
        *certs = az_span_init(vector_get_buffer(cert_list), sizeof(br_x509_certificate) * result);
        vector_destroy(cert_list, true);
    }

	return result;
}

static void free_private_key(private_key *privkey)
{
    switch (privkey->key_type)
    {
    case BR_KEYTYPE_RSA:
        heapFree(hHeap, privkey->key.rsa.iq);
        heapFree(hHeap, privkey->key.rsa.dq);
        heapFree(hHeap, privkey->key.rsa.dp);
        heapFree(hHeap, privkey->key.rsa.q);
        heapFree(hHeap, privkey->key.rsa.p);
        break;
    case BR_KEYTYPE_EC:
        heapFree(hHeap, privkey->key.ec.x);
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
            if (NULL == (sk = (private_key *)heapMalloc(hHeap, sizeof *sk)))
            {
                printf("Failed to allocate memory for RSA key structure\n");
            }
            else  
            {
                memset(sk, 0, sizeof(private_key));

                if (
                    NULL == (sk->key.rsa.p = (unsigned char *)heapMalloc(hHeap, rk->plen)) ||
                    NULL == (sk->key.rsa.q = (unsigned char *)heapMalloc(hHeap, rk->plen)) ||
                    NULL == (sk->key.rsa.dp = (unsigned char *)heapMalloc(hHeap, rk->plen)) ||
                    NULL == (sk->key.rsa.dq = (unsigned char *)heapMalloc(hHeap, rk->plen)) ||
                    NULL == (sk->key.rsa.iq = (unsigned char *)heapMalloc(hHeap, rk->plen))
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
            if (NULL == (sk = (private_key *)heapMalloc(hHeap, sizeof *sk)))
            {
                printf("Failed to allocate memory for EC key structure\n");
            }
            else  
            {
                memset(sk, 0, sizeof(private_key));

                if (NULL == (sk->key.ec.x = (unsigned char *)heapMalloc(hHeap, ek->xlen)))
                {
                    printf("Failed to allocate memory for EC key structure\n");
                    heapFree(hHeap, sk);
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
                        heapFree(hHeap, sk);
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

int read_private_key(const char *key_file, private_key *priv_key)
{
    static const char RSA_PRIVATE_KEY[] = "RSA PRIVATE KEY";
    static const char EC_PRIVATE_KEY[] = "EC PRIVATE KEY";
    static const char PRIVATE_KEY[] = "PRIVATE KEY";
    static const int RSA_PRIVATE_KEY_LENGTH = sizeof(RSA_PRIVATE_KEY) - 1;
    static const int EC_PRIVATE_KEY_LENGTH = sizeof(EC_PRIVATE_KEY) - 1;
    static const int PRIVATE_KEY_LENGTH = sizeof(PRIVATE_KEY) - 1;

    az_span buf = read_file(key_file);

    if (az_span_ptr(buf) == NULL)
    {
        printf("Out of heap space\n");
        return -1;
    }

    VECTORHANDLE pos;  // vector of pem_object
	pem_object *work;
    size_t u;

	pos = decode_pem(az_span_ptr(buf), az_span_size(buf));
		
    if (pos != NULL) 
    {

        for (u = 0; u < vector_get_count(pos); u++) 
        {
            work = (pem_object *)vector_get(pos, u);

            if (0 == memcmp(work->name, RSA_PRIVATE_KEY, RSA_PRIVATE_KEY_LENGTH) ||
                0 == memcmp(work->name, EC_PRIVATE_KEY, EC_PRIVATE_KEY_LENGTH) ||
                0 == memcmp(work->name, RSA_PRIVATE_KEY, RSA_PRIVATE_KEY_LENGTH))
            {
                priv_key = decode_key(work->data, work->data_len);
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
            heapFree(hHeap, ((pem_object *)vector_get(pos, u))->name);
            heapFree(hHeap, ((pem_object *)vector_get(pos, u))->data);
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

    vdn.buffer = heapRealloc(hHeap, vdn.buffer, vdn.data_length);
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

        if (NULL == (ta->pkey.key.rsa.n = (unsigned char *)heapMalloc(hHeap, ta->pkey.key.rsa.nlen)) ||
            NULL == ( ta->pkey.key.rsa.e = (unsigned char *)heapMalloc(hHeap, ta->pkey.key.rsa.elen)))
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

        if (NULL == (ta->pkey.key.ec.q = (unsigned char *)heapMalloc(hHeap, ta->pkey.key.ec.qlen)))
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

void free_certificates(br_x509_certificate *certs, size_t num)
{
	size_t u;

	for (u = 0; u < num; u ++) {
		heapFree(hHeap, certs[u].data);
	}
}

size_t get_trusted_anchors(const char *cert_file, br_x509_trust_anchor *anchOut[])
{
    // Converts a PEM certificate in a string into the format required by BearSSL
    VECTORHANDLE xcs;
    az_span xcs_span;
    br_x509_trust_anchor work;
	br_x509_trust_anchor *anchArray;
    size_t u;
    size_t v;
    int num;
    int result;

    num = read_certificates_string(cert_file, &xcs_span);
    xcs = vector_wrap(hHeap, az_span_ptr(xcs_span), sizeof(br_x509_certificate), num);
    //xcs = read_certificates_string(az_span_ptr(content), az_span_size(content));
    //num = vector_get_count(xcs);

    if (num <= 0)
    {
        printf("No certificates found in string\n");
    }
    else
    {
        anchArray = (br_x509_trust_anchor *)heapMalloc(hHeap, sizeof(br_x509_trust_anchor) * num);

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

                    heapFree(hHeap, anchArray);
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

/*
size_t xxget_trusted_anchors(const char *ca_file, br_x509_trust_anchor **anchOut) {

    static const char CERTIFICATE[] = "CERTIFICATE";
    static const char X509_CERTIFICATE[] = "X509 CERTIFICATE";
    static const int CERTIFICATE_LEN = sizeof(CERTIFICATE) - 1;
    static const int X509_CERTIFICATE_LEN = sizeof(X509_CERTIFICATE) - 1;

    // Read the certificates from the file
    FILE *f = fopen(ca_file, "rb");

    if (f == NULL)
        return 0;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *certs = heapMalloc(hHeap, fsize);

    if (certs == NULL)
        return 0;

    long read = fread(certs, 1, fsize, f);
    
    fclose(f);

    if (read != fsize) {
        heapFree(hHeap, certs);
        return 0;
    }

    int cert_count = 0;
	unsigned char *buf;
    buffer_head bv;
	char *po_name;
	size_t rc = 0;
  	br_pem_decoder_context pc;
	int inobj;
	int extra_nl;

    br_pem_decoder_init(&pc);
    buf = certs;
    inobj = 0;
	po_name;
	extra_nl = 1;
    *anchOut = NULL;

    br_x509_trust_anchor *work = NULL;
    *anchOut = &(work[0]);

    HEAPINFO hi;

    // Decode the certificate string
    while (read > 0) {
		size_t tlen;

		tlen = br_pem_decoder_push(&pc, buf, read);
		buf += tlen;
		read -= tlen;
		switch (br_pem_decoder_event(&pc)) {

		case BR_PEM_BEGIN_OBJ:
            po_name = heapMalloc(hHeap, 80); 
            strncpy(po_name, br_pem_decoder_name(&pc), 80);
            po_name = heapRealloc(hHeap, po_name, strlen(po_name) + 1);
            bv.buffer = NULL;
            bv.buffer_length = 0;
            bv.data_length = 0;
            bv.error = false;
			br_pem_decoder_setdest(&pc, vblob_append, &bv);
			inobj = 1;
			break;

		case BR_PEM_END_OBJ:
			if (inobj) {

                if (0 == memcmp(po_name, CERTIFICATE, CERTIFICATE_LEN)
                || (0 == memcmp(po_name, X509_CERTIFICATE, X509_CERTIFICATE_LEN))) {
                    heapFree(hHeap, po_name);
                    po_name = NULL;

                    if (bv.error == false)
                    {
                        br_x509_certificate xc;
                        br_x509_trust_anchor ta;

                        bv.buffer = heapRealloc(hHeap, bv.buffer, bv.data_length);
                        xc.data = bv.buffer;
                        xc.data_len = bv.data_length;

                        if (0 == certificate_to_trust_anchor(&xc, &ta))
                        {
                            heapFree(hHeap, xc.data);
                            heapFree(hHeap, certs);
                            heapFree(hHeap, po_name);
                            heapFree(hHeap, bv.buffer);
                            free_all_ta_contents(*anchOut, cert_count);
                            heapFree(hHeap, *anchOut);

                            return 0;
                        }

                        work = heapRealloc(hHeap, work, sizeof(ta) * (cert_count + 1));
                        work[cert_count] = ta;
                        heapFree(hHeap, xc.data);
                        inobj = 0;
                        cert_count++;
                    }
                }
                else
                {
                    heapFree(hHeap, bv.buffer);
                }
			}
			break;

		case BR_PEM_ERROR:
    		// ERROR: invalid PEM encoding
	        heapFree(hHeap, certs);
			heapFree(hHeap, po_name);
			heapFree(hHeap, bv.buffer);
            free_all_ta_contents(*anchOut, cert_count);
            heapFree(hHeap, *anchOut);

    		return 0;
		}

		/*
		 * We add an extra newline at the end, in order to
		 * support PEM files that lack the newline on their last
		 * line (this is somwehat invalid, but PEM format is not
		 * standardised and such files do exist in the wild, so
		 * we'd better accept them).
		 * /
		if (read == 0 && extra_nl) {
			extra_nl = 0;
			buf = (unsigned char *)"\n";
			read = 1;
		}
	}

	if (inobj) {
		fprintf(stderr, "ERROR: unfinished PEM object\n");
        heapFree(hHeap, certs);
		heapFree(hHeap, po_name);
		heapFree(hHeap, bv.buffer);
        free_all_ta_contents(*anchOut, cert_count);
        heapFree(hHeap, *anchOut);
		return 0;
	}

    heapFree(hHeap, certs);

    *anchOut = work;

	return cert_count;
}
*/
static void free_all_ta_contents(br_x509_trust_anchor *anch, int count)
{
    for (int i = 0; i < count; i++)
    {
        free_ta_contents(anch + i);
    }
}

static void free_ta_contents(br_x509_trust_anchor *ta)
{
	heapFree(hHeap, ta->dn.data);
	switch (ta->pkey.key_type) 
    {
	case BR_KEYTYPE_RSA:
		heapFree(hHeap, ta->pkey.key.rsa.n);
		heapFree(hHeap, ta->pkey.key.rsa.e);
		break;
	case BR_KEYTYPE_EC:
		heapFree(hHeap, ta->pkey.key.ec.q);
		break;
	}

    heapFree(hHeap, ta);
}


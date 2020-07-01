#include <stdbool.h>
#include <stdio.h>
#include <bearssl.h>

#include "heap.h"
#include "azheap.h"
#include "bearssltagenerator.h"

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

    if (pk == NULL) 
    {
        return 0;
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
            result = 1;
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
            result = 1;
        }
        break;
    default:
        // ERROR: unsupported public key type in CA
        free_ta_contents(ta);
        return 0;
    }
}

size_t get_trusted_anchors(const char *ca_file, br_x509_trust_anchor **anchOut) {

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
		 */
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


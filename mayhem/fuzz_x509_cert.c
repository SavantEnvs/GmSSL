#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <gmssl/x509_cer.h>
#include <gmssl/x509_key.h>
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const uint8_t *in = data;
	size_t inlen = size;
	const uint8_t *cert = NULL;
	size_t certlen = 0;
	X509_KEY key;
	const uint8_t *p;
	size_t len;

	if (x509_cert_from_der(&cert, &certlen, &in, &inlen) != 1) {
		return 0;
	}
	x509_cert_print(fuzz_sink(), 0, 0, "Certificate", cert, certlen);
	memset(&key, 0, sizeof(key));
	x509_cert_get_subject_public_key(cert, certlen, &key);
	x509_cert_get_issuer(cert, certlen, &p, &len);
	x509_cert_get_subject(cert, certlen, &p, &len);
	x509_cert_verify_by_ca_cert(cert, certlen, cert, certlen, "1234567812345678", 16);
	return 0;
}

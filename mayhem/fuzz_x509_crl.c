#include <stdint.h>
#include <stddef.h>
#include <gmssl/x509_crl.h>
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const uint8_t *in = data;
	size_t inlen = size;
	const uint8_t *crl = NULL;
	size_t crllen = 0;

	if (x509_crl_from_der(&crl, &crllen, &in, &inlen) != 1) {
		return 0;
	}
	x509_crl_print(fuzz_sink(), 0, 0, "CertificateList", crl, crllen);
	return 0;
}

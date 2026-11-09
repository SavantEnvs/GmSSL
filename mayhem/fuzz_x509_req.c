#include <stdint.h>
#include <stddef.h>
#include <gmssl/x509_req.h>
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const uint8_t *in = data;
	size_t inlen = size;
	const uint8_t *req = NULL;
	size_t reqlen = 0;

	if (x509_req_from_der(&req, &reqlen, &in, &inlen) != 1) {
		return 0;
	}
	x509_req_print(fuzz_sink(), 0, 0, "CertificationRequest", req, reqlen);
	x509_req_verify(req, reqlen, "1234567812345678", 16);
	return 0;
}

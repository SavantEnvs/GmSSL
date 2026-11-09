#include <stdint.h>
#include <stddef.h>
#include <gmssl/ocsp.h>
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const uint8_t *in;
	size_t inlen;
	const uint8_t *p = NULL;
	size_t plen = 0;
	int status;

	ocsp_response_print(fuzz_sink(), 0, 0, "OCSPResponse", data, size);
	ocsp_request_print(fuzz_sink(), 0, 0, "OCSPRequest", data, size);
	ocsp_basic_response_print(fuzz_sink(), 0, 0, "BasicOCSPResponse", data, size);

	in = data;
	inlen = size;
	if (ocsp_response_from_der(&status, &p, &plen, &in, &inlen) == 1 && p) {
		ocsp_basic_response_print(fuzz_sink(), 0, 0, "BasicOCSPResponse", p, plen);
	}
	return 0;
}

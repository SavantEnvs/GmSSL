#include <stdint.h>
#include <stddef.h>
#include <gmssl/tls.h>
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	tls_record_print(fuzz_sink(), 0, 0, 0, data, size);
	tls_record_print(fuzz_sink(), 0, 0, TLS_cipher_ecdhe_sm4_cbc_sm3, data, size);
	return 0;
}

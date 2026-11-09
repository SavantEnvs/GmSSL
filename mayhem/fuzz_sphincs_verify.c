#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <gmssl/sphincs.h>

// Input layout: public_key[32] signature[SPHINCS_SIGNATURE_SIZE] message[rest]
// A short input is zero-extended, so every input reaches sphincs_verify_finish() with a full-size signature.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	SPHINCS_KEY key;
	SPHINCS_SIGN_CTX ctx;
	uint8_t pubkey[SPHINCS_PUBLIC_KEY_SIZE] = {0};
	static uint8_t sig[SPHINCS_SIGNATURE_SIZE];
	const uint8_t *cp = pubkey;
	size_t pubkeylen = sizeof(pubkey);
	size_t n;

	memset(&key, 0, sizeof(key));
	memset(sig, 0, sizeof(sig));

	n = size < sizeof(pubkey) ? size : sizeof(pubkey);
	memcpy(pubkey, data, n);
	data += n;
	size -= n;

	n = size < sizeof(sig) ? size : sizeof(sig);
	memcpy(sig, data, n);
	data += n;
	size -= n;

	if (sphincs_public_key_from_bytes(&key, &cp, &pubkeylen) != 1) {
		return 0;
	}
	if (sphincs_verify_init(&ctx, &key, sig, sizeof(sig)) != 1) {
		return 0;
	}
	sphincs_verify_update(&ctx, data, size);
	sphincs_verify_finish(&ctx);
	return 0;
}

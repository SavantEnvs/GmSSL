#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <gmssl/sm2.h>
#include <gmssl/x509_key.h>
#include <gmssl/pkcs8.h>
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	SM2_KEY key;
	SM2_SIGNATURE sig;
	SM2_CIPHERTEXT ciphertext;
	X509_KEY xkey;
	const uint8_t *attrs;
	size_t attrslen;
	const uint8_t *in;
	size_t inlen;
	uint8_t buf[SM2_MAX_PLAINTEXT_SIZE];
	size_t buflen;

	memset(&key, 0, sizeof(key));
	in = data; inlen = size;
	sm2_private_key_from_der(&key, &in, &inlen);

	memset(&key, 0, sizeof(key));
	in = data; inlen = size;
	sm2_public_key_info_from_der(&key, &in, &inlen);

	memset(&key, 0, sizeof(key));
	in = data; inlen = size;
	sm2_private_key_info_from_der(&key, &attrs, &attrslen, &in, &inlen);

	memset(&xkey, 0, sizeof(xkey));
	in = data; inlen = size;
	x509_public_key_info_from_der(&xkey, &in, &inlen);

	memset(&key, 0, sizeof(key));
	in = data; inlen = size;
	sm2_private_key_info_decrypt_from_der(&key, &attrs, &attrslen, "password", &in, &inlen);

	in = data; inlen = size;
	sm2_signature_from_der(&sig, &in, &inlen);
	sm2_signature_print(fuzz_sink(), 0, 0, "Signature", data, size);

	in = data; inlen = size;
	if (sm2_ciphertext_from_der(&ciphertext, &in, &inlen) == 1) {
		sm2_key_set_private_key(&key, (const uint64_t[4]){1, 0, 0, 0});
		sm2_do_decrypt(&key, &ciphertext, buf, &buflen);
	}
	sm2_ciphertext_print(fuzz_sink(), 0, 0, "Ciphertext", data, size);

	pkcs8_enced_private_key_info_print(fuzz_sink(), 0, 0, "EncryptedPrivateKeyInfo", data, size);
	return 0;
}

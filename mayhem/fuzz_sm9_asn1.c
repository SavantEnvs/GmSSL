#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <gmssl/sm9.h>
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	SM9_SIGN_MASTER_KEY sign_msk;
	SM9_SIGN_KEY sign_key;
	SM9_SIGNATURE sig;
	SM9_ENC_MASTER_KEY enc_msk;
	SM9_ENC_KEY enc_key;
	SM9_Z256_POINT C1;
	const uint8_t *c2, *c3;
	size_t c2len;
	const uint8_t *in;
	size_t inlen;

	memset(&sign_msk, 0, sizeof(sign_msk));
	in = data; inlen = size;
	sm9_sign_master_key_from_der(&sign_msk, &in, &inlen);

	memset(&sign_msk, 0, sizeof(sign_msk));
	in = data; inlen = size;
	sm9_sign_master_public_key_from_der(&sign_msk, &in, &inlen);

	memset(&sign_msk, 0, sizeof(sign_msk));
	in = data; inlen = size;
	sm9_sign_master_key_info_decrypt_from_der(&sign_msk, "password", &in, &inlen);

	memset(&sign_key, 0, sizeof(sign_key));
	in = data; inlen = size;
	sm9_sign_key_from_der(&sign_key, &in, &inlen);

	memset(&sign_key, 0, sizeof(sign_key));
	in = data; inlen = size;
	sm9_sign_key_info_decrypt_from_der(&sign_key, "password", &in, &inlen);

	in = data; inlen = size;
	if (sm9_signature_from_der(&sig, &in, &inlen) == 1) {
		memset(&sign_msk, 0, sizeof(sign_msk));
	}

	memset(&enc_msk, 0, sizeof(enc_msk));
	in = data; inlen = size;
	sm9_enc_master_key_from_der(&enc_msk, &in, &inlen);

	memset(&enc_msk, 0, sizeof(enc_msk));
	in = data; inlen = size;
	sm9_enc_master_public_key_from_der(&enc_msk, &in, &inlen);

	memset(&enc_msk, 0, sizeof(enc_msk));
	in = data; inlen = size;
	sm9_enc_master_key_info_decrypt_from_der(&enc_msk, "password", &in, &inlen);

	memset(&enc_key, 0, sizeof(enc_key));
	in = data; inlen = size;
	sm9_enc_key_from_der(&enc_key, &in, &inlen);

	memset(&enc_key, 0, sizeof(enc_key));
	in = data; inlen = size;
	sm9_enc_key_info_decrypt_from_der(&enc_key, "password", &in, &inlen);

	in = data; inlen = size;
	sm9_ciphertext_from_der(&C1, &c2, &c2len, &c3, &in, &inlen);
	sm9_ciphertext_print(fuzz_sink(), 0, 0, "Ciphertext", data, size);
	return 0;
}

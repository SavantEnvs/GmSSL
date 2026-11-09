#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <gmssl/sm4.h>

// Input layout: key[16] iv[12] tag[16] aad_len[1] aad[aad_len] ciphertext[rest]
#define HDR (16 + 12 + 16 + 1)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	SM4_KEY key;
	uint8_t iv[12], tag[16], cbc_iv[16];
	const uint8_t *aad, *in;
	size_t aadlen, inlen, outlen;
	uint8_t out[512 + 32];

	// The key, iv and tag occupy a fixed 45-byte header; shorter inputs cannot be split.
	if (size < HDR) {
		return -1;
	}
	memcpy(iv, data + 16, 12);
	memcpy(tag, data + 28, 16);
	aadlen = data[44];
	if (size < HDR + aadlen) {
		return -1;
	}
	aad = data + HDR;
	in = aad + aadlen;
	inlen = size - HDR - aadlen;
	if (inlen > 512) {
		inlen = 512;
	}

	sm4_set_decrypt_key(&key, data);
	memcpy(cbc_iv, data + 16, 12);
	memcpy(cbc_iv + 12, data + 28, 4);

	sm4_cbc_padding_decrypt(&key, cbc_iv, in, inlen, out, &outlen);

	sm4_set_encrypt_key(&key, data);
	sm4_gcm_decrypt(&key, iv, sizeof(iv), aad, aadlen, in, inlen, tag, sizeof(tag), out);
	sm4_gcm_decrypt(&key, iv, 8, aad, aadlen, in, inlen, tag, 12, out);
#ifdef ENABLE_SM4_CCM
	sm4_ccm_decrypt(&key, iv, 12, aad, aadlen, in, inlen, tag, 16, out);
	sm4_ccm_decrypt(&key, iv, 7, aad, aadlen, in, inlen, tag, 8, out);
#endif
	sm4_ctr_encrypt(&key, cbc_iv, in, inlen, out);
#ifdef ENABLE_SM4_OFB
	sm4_ofb_encrypt(&key, cbc_iv, in, inlen, out);
#endif
#ifdef ENABLE_SM4_CFB
	sm4_cfb_decrypt(&key, 16, cbc_iv, in, inlen, out);
#endif
#ifdef ENABLE_SM4_FF1
	{
		char digits[64];
		size_t i, n = inlen > 32 ? 32 : inlen;
		for (i = 0; i < n; i++) {
			digits[i] = '0' + (in[i] % 10);
		}
		if (sm4_ff1_init(&key, data) == 1) {
			sm4_ff1_decrypt(&key, digits, n, aad, aadlen, digits + 32);
		}
	}
#endif
	return 0;
}

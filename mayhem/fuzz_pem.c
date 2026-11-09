#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <gmssl/pem.h>
#include <gmssl/sm2.h>
#include <gmssl/x509_cer.h>

#define MAX_DER 8192

static FILE *open_input(const uint8_t *data, size_t size)
{
	return fmemopen((void *)data, size, "rb");
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FILE *fp;
	uint8_t der[MAX_DER];
	size_t derlen;
	SM2_KEY key;

	// fmemopen(3) requires a non-NULL buffer and (on older libcs) a non-zero size.
	if (size == 0) {
		return -1;
	}

	if (!(fp = open_input(data, size))) {
		return -1;
	}
	pem_read(fp, "CERTIFICATE", der, &derlen, sizeof(der));
	fclose(fp);

	if (!(fp = open_input(data, size))) {
		return -1;
	}
	x509_certs_from_pem(der, &derlen, sizeof(der), fp);
	fclose(fp);

	if (!(fp = open_input(data, size))) {
		return -1;
	}
	memset(&key, 0, sizeof(key));
	sm2_public_key_info_from_pem(&key, fp);
	fclose(fp);

	if (!(fp = open_input(data, size))) {
		return -1;
	}
	memset(&key, 0, sizeof(key));
	sm2_private_key_info_decrypt_from_pem(&key, "password", fp);
	fclose(fp);
	return 0;
}

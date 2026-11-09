#include <stdint.h>
#include <stddef.h>
#include <gmssl/cms.h>
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const uint8_t *in = data;
	size_t inlen = size;
	const uint8_t *content = NULL;
	size_t contentlen = 0;
	int type;

	cms_print(fuzz_sink(), 0, 0, "ContentInfo", data, size);
	cms_content_info_print(fuzz_sink(), 0, 0, "ContentInfo", data, size);
	if (cms_content_info_from_der(&type, &content, &contentlen, &in, &inlen) != 1) {
		return 0;
	}
	switch (type) {
	case OID_cms_signed_data:
		cms_signed_data_print(fuzz_sink(), 0, 0, "SignedData", content, contentlen);
		break;
	case OID_cms_enveloped_data:
		cms_enveloped_data_print(fuzz_sink(), 0, 0, "EnvelopedData", content, contentlen);
		break;
	}
	return 0;
}

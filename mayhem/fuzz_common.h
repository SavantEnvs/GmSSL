#ifndef MAYHEM_FUZZ_COMMON_H
#define MAYHEM_FUZZ_COMMON_H
#include <stdio.h>

// Print routines write to a FILE*; a single read-only sink keeps iterations independent of each other.
static FILE *fuzz_sink(void)
{
	static FILE *fp = NULL;
	if (!fp) {
		fp = fopen("/dev/null", "w");
	}
	return fp;
}
#endif

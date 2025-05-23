#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ACVP_tests.h"

// common functions **************************************************************************
uint8_t hexCharToDecimal(char c)
{
	if (c >= '0' && c <= '9') {
		return (uint8_t) (c - '0');
	} else if (c >= 'a' && c <= 'f') {
		return (uint8_t) (c - 'a' + 10);
	} else if (c >= 'A' && c <= 'F') {
		return (uint8_t) (c - 'A' + 10);
	} else {
		fprintf(stderr, "Invalid hex character: %c\n", c);
		return 0;
	}
}

void hexStringToByteArray(const char *hexString, uint8_t *byteArray)
{
	size_t len = strlen(hexString);

	if (len % 2 != 0) {
		fprintf(stderr, "Hex string must have an even number of characters\n");
		exit(EXIT_FAILURE);
	}

	for (size_t i = 0, j = 0; i < len; i += 2, j++) {
		byteArray[j] = (uint8_t) ((hexCharToDecimal(hexString[i]) << 4) | hexCharToDecimal(hexString[i + 1]));
	}
}

char decimalToHexChar(uint8_t d)
{
    if (d <= 9) {
        return '0' + d;
    } else if (d <= 15) {
        return 'A' + (d - 10);
    } else {
        fprintf(stderr, "Invalid value: %u\n", d);
        return '?';
    }
}

void byteArrayToHexString(const uint8_t *byteArray, size_t byteArrayLen, char *hexString)
{
    for (size_t i = 0; i < byteArrayLen; i++) {
        uint8_t byte = byteArray[i];
        hexString[2 * i]     = decimalToHexChar((byte >> 4) & 0x0F);
        hexString[2 * i + 1] = decimalToHexChar(byte & 0x0F);
    }
    hexString[2 * byteArrayLen] = '\0';
}

void selectPrmSet(char *prmSetString, const slh_param_t **prmSet)
{
    // Compare prmSetString with the names of the parameter sets
    if (strcmp(prmSetString, "SLH-DSA-SHA2-128s") == 0) {
        *prmSet = &slh_dsa_sha2_128s;
    }
    else if (strcmp(prmSetString, "SLH-DSA-SHAKE-128s") == 0) {
        *prmSet = &slh_dsa_shake_128s;
    }
    else if (strcmp(prmSetString, "SLH-DSA-SHA2-128f") == 0) {
        *prmSet = &slh_dsa_sha2_128f;
    }
    else if (strcmp(prmSetString, "SLH-DSA-SHAKE-128f") == 0) {
        *prmSet = &slh_dsa_shake_128f;
    }
    else if (strcmp(prmSetString, "SLH-DSA-SHA2-192s") == 0) {
        *prmSet = &slh_dsa_sha2_192s;
    }
    else if (strcmp(prmSetString, "SLH-DSA-SHAKE-192s") == 0) {
        *prmSet = &slh_dsa_shake_192s;
    }
    else if (strcmp(prmSetString, "SLH-DSA-SHA2-192f") == 0) {
        *prmSet = &slh_dsa_sha2_192f;
    }
    else if (strcmp(prmSetString, "SLH-DSA-SHAKE-192f") == 0) {
        *prmSet = &slh_dsa_shake_192f;
    }
    else if (strcmp(prmSetString, "SLH-DSA-SHA2-256s") == 0) {
        *prmSet = &slh_dsa_sha2_256s;
    }
    else if (strcmp(prmSetString, "SLH-DSA-SHAKE-256s") == 0) {
        *prmSet = &slh_dsa_shake_256s;
    }
    else if (strcmp(prmSetString, "SLH-DSA-SHA2-256f") == 0) {
        *prmSet = &slh_dsa_sha2_256f;
    }
    else if (strcmp(prmSetString, "SLH-DSA-SHAKE-256f") == 0) {
        *prmSet = &slh_dsa_shake_256f;
    }
    else {
        // Handle unknown prmSetString (if needed)
        *prmSet = NULL;  // or provide a default set
    }
}

int fixedKeygenRbg(uint8_t *x, size_t xlen)
{
    size_t n = prmSet_g->n;

    hexStringToByteArray(seed_g.skSeedString,x);
	hexStringToByteArray(seed_g.skPrfString,x+n);
	hexStringToByteArray(seed_g.pkSeedString,x+2*n);

	return 0;
}

int fixedSigRbg(uint8_t *x, size_t xlen)
{
    memcpy(x,addRnd_g,xlen);

	return 0;
}
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "slh_param.h"
#include "slh_dsa.h"  

// defines ***********************************************************************************
#define ACVP_TEST

#define MAX_N         32
#define MAX_PK_BYTES  2 * MAX_N
#define MAX_SK_BYTES  4 * MAX_N
#define MAX_SIG_BYTES 1000 *4 8.4

// types **************************************************************************************
typedef enum interface_e
{
    SLH_INTERNAL,
    SLH_EXTERNAL
} interface_e;

// functions ***********************************************************************************
void hexStringToByteArray(const char *hexString, uint8_t *byteArray);
void byteArrayToHexString(const uint8_t *byteArray, size_t byteArrayLen, char *hexString);
void selectPrmSet(char *prmSetString, const slh_param_t **prmSet);
int fixedKeygenRbg(uint8_t *x, size_t xlen);
int fixedSigRbg(uint8_t *x, size_t xlen);

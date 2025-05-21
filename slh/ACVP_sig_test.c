
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ACVP_tests.h"
#include "slh_dsa.h"

/*
arg 1  := tgId
arg 2  := tcId
arg 3  := prmSet
arg 4  := deterministic
arg 5  := interface
arg 6  := m_sz
arg 7  := m
arg 8  := ctxlen
arg 9  := ctxStr
arg 10 := sk
arg 11 := sig
arg 12 := addRnd
*/


int main(int argc, char *argv[])
{
	/* one of the args is arg 0 */
	if(argc != 13)
	{
		printf("Arg count is %d! \r\n", argc);
		printf("Usage: ./ACVP_sig_test <tgId> <tcId> <prmSet> <deterministic> <interface> <m_sz> <m> <ctxLen> <ctxStr> <sk> <sig> <addRnd> \r\n");
		return -1;
	}

	/* process arg vars */
	uint8_t tgId = (uint8_t)atoi(argv[1]);
	uint8_t tcId = (uint8_t)atoi(argv[2]);
	selectPrmSet(argv[3],&prmSet_g);
    deterministic_g = (!strcmp(argv[4],"True")) ? SLH_DETERMINISTIC : SLH_NON_DETERMINISTIC;
    interface_e interface = (!strcmp(argv[5],"internal")) ? SLH_INTERNAL : SLH_EXTERNAL;
    size_t m_sz = atoi(argv[6])/2;
    uint8_t *m = (uint8_t *)malloc(m_sz * sizeof(uint8_t));
    if(m_sz != 0)
    {
        hexStringToByteArray(argv[7], m);
    }
    size_t ctxLen = atoi(argv[8])/2;
    uint8_t *ctxStr = (uint8_t *)malloc(ctxLen * sizeof(uint8_t));

    if(interface == SLH_EXTERNAL && ctxLen != 0)
    {
        hexStringToByteArray(argv[9], ctxStr);
    }
    uint8_t sk[MAX_SK_BYTES] = {0};
    hexStringToByteArray(argv[10], sk);
    size_t sig_sz = strlen(argv[11]);
    uint8_t *sig = (uint8_t *)malloc(sig_sz * sizeof(uint8_t));
    memset(sig,0,sig_sz);
    uint8_t *sigExpected = (uint8_t *)malloc(sig_sz * sizeof(uint8_t));
    hexStringToByteArray(argv[11], sigExpected);
    if(deterministic_g == SLH_NON_DETERMINISTIC){hexStringToByteArray(argv[12], addRnd_g);}

    if(interface == SLH_EXTERNAL)
    {
        slh_sign(sig,m,m_sz,sk,fixedSigRbg,prmSet_g,ctxStr,ctxLen);
    }
    else {
        slh_sign_internal(sig,0,0,m,m_sz,sk,prmSet_g,addRnd_g);
    }

	if(memcmp(sig,sigExpected,sig_sz))
	{
		printf("Signature does not match expected value for (tgId,tcId): (%d,%d)! \r\n", tgId, tcId);
		
        free(m);
        free(ctxStr);
        free(sig);
        free(sigExpected);

        return -1;
	}
    printf("Signature matches expected value for (tgId,tcId): (%d,%d)! \r\n", tgId, tcId);

    free(m);
    free(ctxStr);
    free(sig);
    free(sigExpected);

	return 0;
}
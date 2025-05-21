
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ACVP_tests.h"
#include "slh_dsa.h"

/*
arg 1  := tgId
arg 2  := tcId
arg 3  := prmSet
arg 4  := interface
arg 5  := m_sz
arg 6  := m
arg 7  := ctxlen
arg 8  := ctxStr
arg 9  := pk
arg 10 := sig
arg 11 := validSig
*/


int main(int argc, char *argv[])
{
	/* one of the args is arg 0 */
	if(argc != 12)
	{
		printf("Arg count is %d! \r\n", argc);
		printf("Usage: ./ACVP_ver_test <tgId> <tcId> <prmSet> <interface> <m_sz> <m> <ctxLen> <ctxStr> <pk> <sig> \r\n");
		return -1;
	}

	/* process arg vars */
	uint8_t tgId = (uint8_t)atoi(argv[1]);
	uint8_t tcId = (uint8_t)atoi(argv[2]);
	selectPrmSet(argv[3],&prmSet_g);
    interface_e interface = (!strcmp(argv[5],"internal")) ? SLH_INTERNAL : SLH_EXTERNAL;
    size_t m_sz = atoi(argv[5])/2;
    uint8_t *m = (uint8_t *)malloc(m_sz * sizeof(uint8_t));
    if(m_sz != 0)
    {
        hexStringToByteArray(argv[6], m);
    }
    size_t ctxLen = atoi(argv[7])/2;
    uint8_t *ctxStr = (uint8_t *)malloc(ctxLen * sizeof(uint8_t));
    if(interface == SLH_EXTERNAL && ctxLen != 0)
    {
        hexStringToByteArray(argv[8], ctxStr);
    }
    uint8_t pk[MAX_PK_BYTES] = {0};
    hexStringToByteArray(argv[9], pk);
    size_t sig_sz = strlen(argv[10]);
    uint8_t *sig = (uint8_t *)malloc(sig_sz * sizeof(uint8_t));
    memset(sig,0,sig_sz);
    bool validSig = (!strcmp(argv[11],"true"));
    bool result;

    if(interface == SLH_EXTERNAL)
    {
        result = slh_verify(m,m_sz,sig,pk,prmSet_g,ctxStr,ctxLen);
    }
    else {
        result = slh_verify_internal(ctxStr,0,m,m_sz,sig,pk,prmSet_g);
    }

	if(result != validSig)
	{
		printf("Verification result does not match expectation for (tgId,tcId): (%d,%d)! \r\n", tgId, tcId);
		
        free(m);
        free(ctxStr);
        free(sig);

        return -1;
	}
    printf("Verification result matches expectation for (tgId,tcId): (%d,%d)! \r\n", tgId, tcId);
    
    free(m);
    free(ctxStr);
    free(sig);

	return 0;
}
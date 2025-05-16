#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ACVP_tests.h"

// hardcoded example usage *******************************************************************

/*
from JSON ->

"parameterSet": "SLH-DSA-SHA2-128s",
"skSeed": "AC379F047FAAB2004F3AE32350AC9A3D",
"skPrf": "829FFF0AA59E956A87F3971C4D58E710",
"pkSeed": "0566D240CC519834322EAFBCC73C79F5",
"sk": "AC379F047FAAB2004F3AE32350AC9A3D829FFF0AA59E956A87F3971C4D58E7100566D240CC519834322EAFBCC73C79F5A4B84F02E8BF0CBD54017B2D3C494B57",
"pk": "0566D240CC519834322EAFBCC73C79F5A4B84F02E8BF0CBD54017B2D3C494B57"
*/

/*
static int hardcoded_keygen_rbg(uint8_t *x, size_t xlen)
{
	size_t n = slh_dsa_sha2_128s.n;

    char skSeedString[] = "AC379F047FAAB2004F3AE32350AC9A3D";
    char skPrfString[] = "829FFF0AA59E956A87F3971C4D58E710";
    char pkSeedString[] = "0566D240CC519834322EAFBCC73C79F5";

    hexStringToByteArray(skSeedString,x);
	hexStringToByteArray(skPrfString,x+n);
	hexStringToByteArray(pkSeedString,x+2*n);

	return 0;
}

int main()
{
    uint8_t pk[MAX_PK_BYTES]          = {0};
    uint8_t sk[MAX_SK_BYTES]          = {0};
	uint8_t pk_expected[MAX_PK_BYTES] = {0};
    uint8_t sk_expected[MAX_SK_BYTES] = {0};

	char skString[] = "AC379F047FAAB2004F3AE32350AC9A3D829FFF0AA59E956A87F3971C4D58E7100566D240CC519834322EAFBCC73C79F5A4B84F02E8BF0CBD54017B2D3C494B57";
    char pkString[] = "0566D240CC519834322EAFBCC73C79F5A4B84F02E8BF0CBD54017B2D3C494B57";
	hexStringToByteArray(skString, sk_expected);
	hexStringToByteArray(pkString, pk_expected);

	slh_keygen(pk,sk,&hardcoded_keygen_rbg,&slh_dsa_sha2_128s);

	if(memcmp(sk,sk_expected,sizeof(sk)))
	{
		printf("SK does not match expected value! \r\n");
		return -1;
	}

	else if(memcmp(pk,pk_expected,sizeof(pk)))
	{
		printf("PK does not match expected value! \r\n");
		return -1;
	}

	printf("All tests passed! \r\n");
	return 0;
}
*/

/*
arg 1 := tgId
arg 2 := tcId
arg 3 := prmSet
arg 4 := skSeed
arg 5 := skPrf
arg 6 := pkSeed
arg 7 := sk
arg 8 := pk
*/

int main(int argc, char *argv[])
{
	/* one of the args is arg 0 */
	if(argc != 9)
	{
		printf("%d \r\n", argc);
		printf("Usage: ./ACVP_keygen_test <tgId> <tcId> <prmSet> <skSeed> <skPrf> <pkSeed> <sk> <pk> \r\n");
		return -1;
	}

	uint8_t sk[MAX_SK_BYTES] = {0};
	uint8_t pk[MAX_PK_BYTES] = {0};
	uint8_t skExpected[MAX_SK_BYTES] = {0};
	uint8_t pkExpected[MAX_PK_BYTES] = {0};

	/* process arg vars */
	uint8_t tgId = (uint8_t)atoi(argv[1]);
	uint8_t tcId = (uint8_t)atoi(argv[2]);
	selectPrmSet(argv[3],&prmSet_g);
	seed_g.skSeedString = argv[4];
    seed_g.skPrfString = argv[5];
    seed_g.pkSeedString = argv[6];
	hexStringToByteArray(argv[7], skExpected);
	hexStringToByteArray(argv[8], pkExpected);

	slh_keygen(pk,sk,fixedKeygenRbg,prmSet_g);

	if(memcmp(sk,skExpected,sizeof(sk)))
	{
		printf("SK does not match expected value in keygen for (tgId,tcId): (%d,%d)! \r\n", tgId, tcId);
		return -1;
	}

	else if(memcmp(pk,pkExpected,sizeof(pk)))
	{
		printf("PK does not match expected value in keygen for (tgId,tcId): (%d,%d)! \r\n", tgId, tcId);
		return -1;
	}

	printf("Correct output for (tgId,tcId): (%d,%d)! \r\n", tgId, tcId);
	
	return 0;
}
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ACVP_tests.h"
#include "slh_dsa.h"

#include "kat_drbg.h" 

//  fake test drbg state
aes256_ctr_drbg_t kat_drbg, iut_drbg;

const slh_param_t *iut = &slh_dsa_sha2_128s;

//  for the callback interface
int iut_randombytes(uint8_t *x, size_t xlen)
{
    aes256ctr_xof(&iut_drbg, x, xlen);
    return 0;
}

int zeroBytes(uint8_t *x, size_t xlen)
{
    memset(x,0,xlen);

    return 0;
}

int rigBytes(uint8_t *x, size_t xlen)
{
    char *riggedBytes = "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D";
    hexStringToByteArray(riggedBytes, x);

    return 0;
}

// hardcoded ****************************************************************
int main()
{
    uint8_t seed[48] = { 0 };
    // uint8_t msg[33 * 1] = { 0 };
    uint8_t *msg = (uint8_t *)malloc(sizeof(uint8_t));
    msg[0] = 63;
    
    size_t msg_sz= 0, pk_sz = 0, sk_sz = 0, sig_sz = 0, sm_sz = 0;

    uint8_t pk[2 * 32] = { 0 };
    uint8_t sk[4 * 32] = { 0 };
    uint8_t sm[50000 + 33 * 1];

    //  initialize kat seed drbg
    for (int i = 0; i < 48; i++) {
        seed[i] = i;
    }
    aes256ctr_xof_init(&kat_drbg, seed);

    pk_sz = slh_pk_sz(iut);
    sk_sz = slh_sk_sz(iut);
    sig_sz = slh_sig_sz(iut);

    aes256ctr_xof(&kat_drbg, seed, 48);

    msg_sz = 33;

    aes256ctr_xof(&kat_drbg, msg, msg_sz);

    //  initialize target drbg
    // aes256ctr_xof_init(&iut_drbg, seed);
    // slh_keygen(pk, sk, &iut_randombytes, iut);
    prmSet_g = iut;
    seed_g.skSeedString = "AC379F047FAAB2004F3AE32350AC9A3D";
    seed_g.skPrfString = "829FFF0AA59E956A87F3971C4D58E710";
    seed_g.pkSeedString = "0566D240CC519834322EAFBCC73C79F5";
    slh_keygen(pk, sk, &fixedKeygenRbg, iut);

    char pkStrGen[pk_sz*2+1];
    byteArrayToHexString(pk,pk_sz,pkStrGen);
    printf("pkStrGen: %s \r\n\r\n", pkStrGen);
    char skStrGen[sk_sz*2+1];
    byteArrayToHexString(sk,sk_sz,skStrGen);
    printf("skStrGen: %s \r\n\r\n", skStrGen);

    uint8_t ctx_str[4];
    size_t ctx_str_len = 4;

    // char *skStr = "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2DB505D7CFAD1B497499323C8686325E47AC524902FC81F5032BC27B17D9261EBD";
    // hexStringToByteArray(skStr, sk);
    // char *pkStr = "B505D7CFAD1B497499323C8686325E47AC524902FC81F5032BC27B17D9261EBD";
    // hexStringToByteArray(pkStr, pk);

    // printf("pkstr: %s \r\n", pkStr);

    sm_sz = slh_sign(sm, msg, msg_sz, sk, &iut_randombytes, iut,ctx_str,ctx_str_len);

    printf("sm: \r\n");
    for(int i = 0; i < 50; i++){
        printf("%d",sm[i]);
    }
    printf("\r\n\r\n");

    memcpy(sm + sm_sz, msg, msg_sz);
    sm_sz += msg_sz;

    if (!slh_verify(sm + sig_sz, msg_sz, sm, pk, iut,ctx_str,ctx_str_len)) {
        printf("Verification failed! \r\n");
    }

    return 0;
}

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

// int main(int argc, char *argv[])
// {
// 	/* one of the args is arg 0 */
// 	if(argc != 14)
// 	{
// 		printf("Arg count is %d! \r\n", argc);
// 		printf("Usage: ./ACVP_sig_test <tgId> <tcId> <prmSet> <deterministic> <interface> <m_sz> <m> <ctxLen> <ctxStr> <sk> <sig> <addRnd> <pk> \r\n");
// 		return -1;
// 	}

// 	/* process arg vars */
// 	uint8_t tgId = (uint8_t)atoi(argv[1]);
// 	uint8_t tcId = (uint8_t)atoi(argv[2]);
// 	selectPrmSet(argv[3],&prmSet_g);
//     deterministic_g = (!strcmp(argv[4],"True")) ? SLH_DETERMINISTIC : SLH_NON_DETERMINISTIC;
//     interface_e interface = (!strcmp(argv[5],"internal")) ? SLH_INTERNAL : SLH_EXTERNAL;
//     size_t m_sz = atoi(argv[6]);
//     uint8_t *m = (uint8_t *)malloc(m_sz * sizeof(uint8_t));
//     if(m_sz != 0)
//     {
//         hexStringToByteArray(argv[7], m);
//     }
//     size_t ctxLen = atoi(argv[8]);
//     uint8_t *ctxStr = (uint8_t *)malloc(ctxLen * sizeof(uint8_t));
//     if(interface == SLH_EXTERNAL && ctxLen != 0)
//     {
//         hexStringToByteArray(argv[9], ctxStr);
//     }
//     uint8_t sk[MAX_SK_BYTES] = {0};
//     hexStringToByteArray(argv[10], sk);
//     size_t sig_sz = strlen(argv[11]);
//     uint8_t *sig = (uint8_t *)malloc(sig_sz * sizeof(uint8_t));
//     memset(sig,0,sig_sz);
//     uint8_t *sigExpected = (uint8_t *)malloc(sig_sz * sizeof(uint8_t));
//     hexStringToByteArray(argv[11], sigExpected);
//     if(deterministic_g == SLH_NON_DETERMINISTIC){hexStringToByteArray(argv[12], addRnd_g);}
//     uint8_t pk[MAX_PK_BYTES] = {0};
//     hexStringToByteArray(argv[13], pk);

//     if(interface == SLH_EXTERNAL)
//     {
//         slh_sign(sig,m,m_sz,sk,fixedSigRbg,prmSet_g,ctxStr,ctxLen);
//     }
//     else {
//         slh_sign_internal(sig,0,0,m,m_sz,sk,prmSet_g,addRnd_g);
//     }

//     printf("signature: \r\n");
//     for(int i = 0; i<50; i++){
//         printf("%d",sig[i]);
//     }
//     printf("\r\n\r\n\r\n");

//     printf("signature expected : \r\n");
//     for(int i = 0; i<50; i++){
//         printf("%d",sigExpected[i]);
//     }
//     printf("\r\n\r\n\r\n");

// 	if(memcmp(sig,sigExpected,sig_sz))
// 	{
// 		printf("Signature does not match expected value for (tgId,tcId): (%d,%d)! \r\n", tgId, tcId);
		
//         // free(m);
//         // free(ctxStr);
//         // free(sig);
//         // free(sigExpected);

//         // return -1;
// 	}

//     memcpy(sig + sig_sz, m, m_sz);
//     sig_sz += m_sz;

//     if (!slh_verify(sig + sig_sz, m_sz, sig, pk, prmSet_g,ctxStr,ctxLen)) {
//         printf("Verification failed! \r\n");
//     }
	
//     free(m);
//     free(ctxStr);
//     free(sig);
//     free(sigExpected);

// 	return 0;
// }
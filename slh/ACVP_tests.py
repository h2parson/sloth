import subprocess
import json

'''
Keygen tests format

arg 1 := tgId
arg 2 := tcId
arg 3 := prmSet
arg 4 := skSeed
arg 5 := skPrf
arg 6 := pkSeed
arg 7 := sk
arg 8 := pk
'''

# Creates command to call C program to run a keygen testcase
def makeKeygenTestCmd(tgId,tcId,prmSet,skSeed,skPrf,pkSeed,sk,pk):
    command = "./ACVP_keygen_test "
    command += (str(tgId) + " ")
    command += (str(tcId) + " ")
    command += (str(prmSet) + " ")
    command += (str(skSeed) + " ")
    command += (str(skPrf) + " ")
    command += (str(pkSeed) + " ")
    command += (str(sk) + " ")
    command += str(pk)
    return command

# Creates command to call C program to run a keygen testcase
def makeSigTestCmd(tgId,tcId,prmSet,deterministic,interface,m_sz,m,ctxLen,ctxStr,sk,sig,addRnd,pk):
    command = "./ACVP_sig_test "
    command += (str(tgId) + " ")
    command += (str(tcId) + " ")
    command += (str(prmSet) + " ")
    command += (str(deterministic) + " ")
    command += (str(interface) + " ")
    command += (str(m_sz) + " ")
    command += (str(m) + " ")
    command += (str(ctxLen) + " ")
    command += (str(ctxStr) + " ")
    command += (str(sk) + " ")
    command += (str(sig) + " ")
    command += str(addRnd + " ")
    command += (str(pk))
    return command

# Function performs all keygen tests for a given parameter set
def keygenTestPrmSet(prmSet):
    with open("../ACVP-Server-1.1.0.39/gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json", 'r') as fp:
        slh_dsa_kg_acvp = json.load(fp)

        for variant in slh_dsa_kg_acvp["testGroups"]:
            if variant["parameterSet"] == prmSet:
                for testCase in variant["tests"]:
                    tgId = str(variant["tgId"])
                    tcId = str(testCase["tcId"])
                    prmSet = prmSet
                    skSeed = str(testCase["skSeed"])
                    skPrf = str(testCase["skPrf"])
                    pkSeed = str(testCase["pkSeed"])
                    sk = str(testCase["sk"])
                    pk = str(testCase["pk"])

                    subprocess.run(makeKeygenTestCmd(tgId,tcId,prmSet,skSeed,skPrf,pkSeed,sk,pk), shell=True)

# Function performs all signing tests for a given parameter set
def sigTestPrmSet(prmSet):
    with open("../ACVP-Server-1.1.0.39/gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json", 'r') as fp:
        slh_dsa_sig_acvp = json.load(fp)

        for variant in slh_dsa_sig_acvp["testGroups"]:
            if variant["parameterSet"] == prmSet:
                if variant["signatureInterface"] == "internal":
                    variantFound = True
                    for testCase in variant["tests"]:
                        tgId = str(variant["tgId"])
                        tcId = str(testCase["tcId"])
                        prmSet = prmSet
                        deterministic = str(variant["deterministic"])
                        interface = str(variant["signatureInterface"])
                        m = str(testCase["message"])
                        m_sz = len(m)
                        if m_sz == 0:
                            m = "-"
                        ctxStr = str(testCase["context"]) if interface == "external" else "-"
                        ctxLen = len(ctxStr)
                        if ctxLen == 0:
                            ctxStr = "-"
                        sk = str(testCase["sk"])
                        pk = str(testCase["pk"])
                        sig = str(testCase["signature"])
                        addRnd = str(testCase["additionalRandomness"]) if deterministic == "false" else "-"
    
                        subprocess.run(makeSigTestCmd(tgId,tcId,prmSet,deterministic,interface,m_sz,m,ctxLen,ctxStr,sk,sig,addRnd,pk), shell=True)
                        if variantFound:
                            return

# Variable Declaration
prmSets = ["SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128s",
           "SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f",
           "SLH-DSA-SHA2-192s", "SLH-DSA-SHAKE-192s",
           "SLH-DSA-SHA2-192f", "SLH-DSA-SHAKE-192f",
           "SLH-DSA-SHA2-256s", "SLH-DSA-SHAKE-256s",
           "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-256f"]

# Begin main program
# Keygen tests
# for prmSet in prmSets:
#     keygenTestPrmSet(prmSet)

# Signature tests
sigTestPrmSet("SLH-DSA-SHA2-128f")
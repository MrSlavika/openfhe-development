#include "binfhecontext.h"
#include <benchmark/benchmark.h>

using namespace lbcrypto;


double f_sigmoid(double x)
{
    return 1 / (1 + std::exp(-x));
}

enum functype
{
    LMP22,
    COMPRESS,
    CANCELSIGN,
    SELECT,
    PRESELECT,
    SELECT_ALT,
    COMP,
    WoPPBS1,
    WoPPBS2,
    BFVMULT,
    KS21,
    UNKNOWN
};
// NOTE: for SELECT and COMP, smaller Bg can be used for the non-multi-value bootstraps

// sign decomp info, to support 5 bits of ptxt when q=2^12
//  n = 745,  qin <= 2^14
//  n = 930,  qin <= 2^19
//  n = 1305, qin <= 2^28
// to support 4 bits of ptxt when q = 2^11
//  n = 745,  qin <= 2^15
//  n = 930,  qin <= 2^20
//  n = 1305, qin <= 2^30

// NativeInteger P54 = FirstPrime<NativeInteger>(54, 1 << 12);
// NativeInteger Q54 = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(54, 1 << 12), 1 << 12); // XXX: OpenFHE has a bug here, they used N instead of m
// NativeInteger Q27 = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 1 << 11), 1 << 11);

NativeInteger Q53 = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(53, 1 << 12), 1 << 12);
NativeInteger P53 = FirstPrime<NativeInteger>(53, 1 << 12);
NativeInteger Q26 = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(26, 1 << 11), 1 << 11);

uint32_t n35 = 1340;
uint32_t n25 = 955;
uint32_t n20 = 760;

struct ParamSet
{
    std::string desc;
    // ....
    functype ftype;
    uint32_t p;    // plaintext space
    NativeInteger extra; // extra param. e.g. pmid for preselect_CKKS
    double deltain;
    double deltaout;
    NativeInteger qout;
    double (*f)(double);
    // basic scheme params
    uint32_t n;
    uint32_t N;
    NativeInteger q;
    NativeInteger Q;
    NativeInteger qKS;
    double std;
    uint32_t baseKS;
    uint32_t baseG;
    uint32_t baseR;
    // extra scheme params
    uint32_t basePK;
    NativeInteger qfrom;
    uint32_t baseG0;
    uint32_t baseGMV;
    uint32_t beta_precise; // NOTE: only PRESELECT needs this
    std::vector<uint32_t> baseGs;
    uint32_t pkkey_flags;
    bool multithread;
    NativeInteger P;
    uint32_t baseRL;
    // those affected by pkkey_flags:
    //      SELECT: half
    //      CANCELSIGN: full
    //      PRESELECT: const(CKKS), full(discrete)
    //      ReLU: half_trans
    //      multi-value FDFB(SELECT and COMP): full

    // those affected by multithread:
    //      SELECT(both multi-value and non-multi-value, packing)
    //      PRESELECT(batch select, packing)
    //      COMP
};

std::vector<ParamSet> param_sets = {
// {"******************************************** standard ********************************************", UNKNOWN}, // bannner, ok
{"standard params for EvalFunc, p = 8", 
LMP22, 8, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 11, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
0, 0, 0, 0, 55, {}, 0, false, 0, 0},
{"standard params for FDFB, p = 32", 
KS21, 32, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 30, 1 << 6, 0, 56, {}, RingGSWCryptoParams::PKKEY_CONST, false, 0, 0},
{"standard params for FDFB, p = 32", 
KS21, 32, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 14, 0,
1 << 5, uint64_t(1) << 35, 1 << 10, 0, 56, {}, RingGSWCryptoParams::PKKEY_CONST, false, 0, 0},
{"standard params for FDFB, p = 32", 
KS21, 32, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 11, 0,
1 << 5, uint64_t(1) << 35, 1 << 13, 0, 56, {}, RingGSWCryptoParams::PKKEY_CONST, false, 0, 0},
{"standard params for FDFB, p = 16", 
KS21, 16, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 30, 1 << 8, 0, 56, {}, RingGSWCryptoParams::PKKEY_CONST, false, 0, 0},
{"standard params for FDFB, p = 16", 
KS21, 16, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 14, 0,
1 << 5, uint64_t(1) << 35, 1 << 12, 0, 56, {}, RingGSWCryptoParams::PKKEY_CONST, false, 0, 0},
{"standard params for FDFB, p = 16", 
KS21, 16, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 11, 0,
1 << 5, uint64_t(1) << 35, 1 << 15, 0, 56, {}, RingGSWCryptoParams::PKKEY_CONST, false, 0, 0},
{"standard params for Comp, p = 32", 
COMP, 32, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
0, 0, 0, 0, 56, {}, 0, false, 0, 0},
{"standard params for Comp, p = 16", 
COMP, 16, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
0, 0, 0, 0, 56, {}, 0, false, 0, 0},
{"standard params for Comp, p = 32, MULTI-VALUE", 
COMP, 32, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
0, 0, 0, 128, 56, {1 << 18, 1 << 27}, 0, false, 0, 0},
{"standard params for Comp, p = 16, MULTI-VALUE", 
COMP, 16, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 25, 3.19, 1 << 5, 1 << 27, 0,
0, 0, 0, 64, 55, {}, 0, false, 0, 0},
{"standard params for WoPPBS1, p = 16", 
WoPPBS1, 16, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 11, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 30, 0, 0, 55, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"standard params for WoPPBS1, p = 16, MULTI-VALUE", 
WoPPBS1, 16, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 11, Q53, 1 << 20, 3.19, 1 << 5, 1 << 11, 0,
1 << 5, 1 << 30, 0, 32, 55, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"standard params for WoPPBS2, p = 32", 
WoPPBS2, 32, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 14, 0,
1 << 5, 1 << 30, 0, 0, 56, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"standard params for WoPPBS2, p = 16", 
WoPPBS2, 16, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 30, 0, 0, 56, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"standard params for WoPPBS2, p = 32, MULTI-VALUE", 
WoPPBS2, 32, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 6, 0,
1 << 5, 1 << 30, 0, 128, 56, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"standard params for WoPPBS2, p = 16, MULTI-VALUE", 
WoPPBS2, 16, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 11, 0,
1 << 5, 1 << 30, 0, 64, 56, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"standard params for WoPPBS1+, p = 16", 
WoPPBS1, 16, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 11, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 25, 0, 0, 55, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"standard params for WoPPBS1+, p = 16, MULTI-VALUE", 
WoPPBS1, 16, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 11, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 25, 0, 32, 55, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"standard params for FDFB-BFVMul, p = 32", 
BFVMULT, 32, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 25, 0, 0, 56, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"standard params for FDFB-BFVMul, p = 32, MULTI-VALUE", 
BFVMULT, 32, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 11, 0,
1 << 5, 1 << 25, 0, 128, 56, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"standard params for FDFB-BFVMul, p = 16, MULTI-VALUE", 
BFVMULT, 16, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 25, 0, 64, 56, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"standard params for FDFB-Compress, p = 16", 
COMPRESS, 16, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
0, 0, 0, 0, 56, {}, 0, false, 0, 0},
{"standard params for FDFB-CancelSign, p = 16", 
CANCELSIGN, 16, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 11, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 15, 0, 0, 55, {}, RingGSWCryptoParams::PKKEY_FULL, false, 0, 0},
{"standard params for FDFB-Select, p = 32", 
SELECT, 32, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 15, 0, 0, 56, {}, RingGSWCryptoParams::PKKEY_HALF, false, 0, 0},
{"standard params for FDFB-Select, p = 16", 
SELECT, 16, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 15, 0, 0, 56, {}, RingGSWCryptoParams::PKKEY_HALF, false, 0, 0},
{"standard params for FDFB-Select, p = 32, MULTI-VALUE", 
SELECT, 32, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 15, 0, 64, 56, {1 << 18, 1 << 27}, RingGSWCryptoParams::PKKEY_HALF, false, 0, 0},
{"standard params for FDFB-Select, p = 16, MULTI-VALUE", 
SELECT, 16, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 15, 0, 32, 56, {1 << 18, 1 << 27}, RingGSWCryptoParams::PKKEY_HALF, false, 0, 0},
{"standard params for FDFB-PreSelect, p = 32", 
PRESELECT, 32, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 20, 2, 0, 56, {}, RingGSWCryptoParams::PKKEY_FULL, false, 0, 0},
{"standard params for FDFB-PreSelect, p = 16", 
PRESELECT, 16, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 20, 4, 0, 56, {}, RingGSWCryptoParams::PKKEY_FULL, false, 0, 0},
{"standard params for FDFB-SelectAlt, p = 32", 
SELECT_ALT, 32, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 15, 0, 0, 56, {}, RingGSWCryptoParams::PKKEY_FULL, false, 0, 0},
{"standard params for FDFB-SelectAlt, p = 16", 
SELECT_ALT, 16, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 15, 0, 0, 56, {}, RingGSWCryptoParams::PKKEY_FULL, false, 0, 0},
{"standard params for FDFB-SelectAlt, p = 32, MULTI-VALUE", 
SELECT_ALT, 32, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 15, 0, 128, 56, {1 << 18, 1 << 27}, RingGSWCryptoParams::PKKEY_FULL, false, 0, 0},
{"standard params for FDFB-SelectAlt, p = 16, MULTI-VALUE", 
SELECT_ALT, 16, 0, 0, 0, 0, nullptr, 
n35, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 15, 0, 64, 56, {1 << 18, 1 << 27}, RingGSWCryptoParams::PKKEY_FULL, false, 0, 0},
// {"******************************************** small & tiny ********************************************", UNKNOWN}, // banner
{"small params for EvalFunc, p = 16", 
LMP22, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 11, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
0, 0, 0, 0, 42, {}, 0, false, 0, 0},
{"small params for FDFB, p = 32", 
KS21, 32, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 30, 1 << 7, 0, 42, {}, RingGSWCryptoParams::PKKEY_CONST, false, 0, 0},
{"small params for FDFB, p = 32", 
KS21, 32, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 14, 0,
1 << 5, uint64_t(1) << 35, 1 << 11, 0, 42, {}, RingGSWCryptoParams::PKKEY_CONST, false, 0, 0},
{"small params for FDFB, p = 32", 
KS21, 32, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 11, 0,
1 << 5, uint64_t(1) << 35, 1 << 14, 0, 42, {}, RingGSWCryptoParams::PKKEY_CONST, false, 0, 0},
{"small params for FDFB, p = 16", 
KS21, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 30, 1 << 9, 0, 42, {}, RingGSWCryptoParams::PKKEY_CONST, false, 0, 0},
{"small params for FDFB, p = 16", 
KS21, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 14, 0,
1 << 5, uint64_t(1) << 35, 1 << 13, 0, 42, {}, RingGSWCryptoParams::PKKEY_CONST, false, 0, 0},
{"small params for FDFB, p = 16", 
KS21, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 11, 0,
1 << 5, uint64_t(1) << 35, 1 << 16, 0, 42, {}, RingGSWCryptoParams::PKKEY_CONST, false, 0, 0},
{"small params for Comp, p = 32", 
COMP, 32, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
0, 0, 0, 0, 42, {}, 0, false, 0, 0},
{"small params for Comp, p = 16", 
COMP, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
0, 0, 0, 0, 42, {}, 0, false, 0, 0},
{"tiny params for Comp, p = 16", 
COMP, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 10, 1 << 11, Q26, 1 << 20, 3.19, 1 << 5, 1 << 5, 0,
0, 0, 0, 0, 53, {}, 0, false, 0, 0},
{"small params for Comp, p = 32, MULTI-VALUE", 
COMP, 32, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0, // NOTE: Bg = 2^18
0, 0, 0, 128, 42, {}, 0, false, 0, 0},
{"small params for Comp, p = 16, MULTI-VALUE", 
COMP, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
0, 0, 0, 64, 42, {}, 0, false, 0, 0},
{"small params for WoPPBS1, p = 16", 
WoPPBS1, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 11, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 30, 0, 0, 42, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"small params for WoPPBS1, p = 16, MULTI-VALUE", 
WoPPBS1, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 11, Q53, 1 << 20, 3.19, 1 << 5, 1 << 11, 0,
1 << 5, 1 << 25, 0, 32, 42, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"small params for WoPPBS2, p = 32", 
WoPPBS2, 32, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 14, 0,
1 << 5, 1 << 30, 0, 0, 42, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"small params for WoPPBS2, p = 16", 
WoPPBS2, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 30, 0, 0, 42, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"small params for WoPPBS2, p = 32, MULTI-VALUE", 
WoPPBS2, 32, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 8, 0,
1 << 5, 1 << 30, 0, 128, 42, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"small params for WoPPBS2, p = 16, MULTI-VALUE", 
WoPPBS2, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 11, 0,
1 << 5, 1 << 30, 0, 64, 42, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"small params for WoPPBS1+, p = 16", 
WoPPBS1, 16, 0, 0, 0, 0, nullptr, 
n25, 1 << 11, 1 << 11, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 20, 0, 0, 47, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"small params for WoPPBS1+, p = 16, MULTI-VALUE", 
WoPPBS1, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 11, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 20, 0, 32, 42, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"small params for FDFB-BFVMul, p = 32", 
BFVMULT, 32, 0, 0, 0, 0, nullptr, 
n25, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 25, 0, 0, 47, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"small params for FDFB-BFVMul, p = 32, MULTI-VALUE", 
BFVMULT, 32, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 14, 0,
1 << 5, 1 << 25, 0, 128, 42, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"small params for FDFB-BFVMul, p = 16, MULTI-VALUE", 
BFVMULT, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 20, 0, 64, 42, {}, RingGSWCryptoParams::PKKEY_CONST, false, P53, 1 << 27},
{"small params for FDFB-Compress, p = 16", 
COMPRESS, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
0, 0, 0, 0, 42, {}, 0, false, 0, 0},
{"small params for FDFB-CancelSign, p = 16", 
CANCELSIGN, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 11, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 15, 0, 0, 42, {}, RingGSWCryptoParams::PKKEY_FULL, false, 0, 0},
{"small params for FDFB-Select, p = 32", 
SELECT, 32, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 15, 0, 0, 42, {}, RingGSWCryptoParams::PKKEY_HALF, false, 0, 0},
{"small params for FDFB-Select, p = 16", 
SELECT, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 15, 0, 0, 42, {}, RingGSWCryptoParams::PKKEY_HALF, false, 0, 0},
{"tiny params for FDFB-Select, p = 16", 
SELECT, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 10, 1 << 11, Q26, 1 << 20, 3.19, 1 << 5, 1 << 5, 0,
1 << 5, 1 << 15, 0, 0, 53, {}, RingGSWCryptoParams::PKKEY_HALF, false, 0, 0},
{"small params for FDFB-Select, p = 32, MULTI-VALUE", 
SELECT, 32, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 15, 0, 64, 42, {1 << 18, 1 << 27}, RingGSWCryptoParams::PKKEY_HALF, false, 0, 0},
{"small params for FDFB-Select, p = 16, MULTI-VALUE", 
SELECT, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 15, 0, 32, 42, {}, RingGSWCryptoParams::PKKEY_HALF, false, 0, 0},
{"small params for FDFB-PreSelect, p = 32", 
PRESELECT, 32, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 20, 8, 0, 42, {}, RingGSWCryptoParams::PKKEY_FULL, false, 0, 0},
{"small params for FDFB-PreSelect, p = 16", 
PRESELECT, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 20, 8, 0, 42, {}, RingGSWCryptoParams::PKKEY_FULL, false, 0, 0},
{"small params for FDFB-SelectAlt, p = 32", 
SELECT_ALT, 32, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 15, 0, 0, 42, {}, RingGSWCryptoParams::PKKEY_FULL, false, 0, 0},
{"small params for FDFB-SelectAlt, p = 16", 
SELECT_ALT, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 15, 0, 0, 42, {}, RingGSWCryptoParams::PKKEY_FULL, false, 0, 0},
{"tiny params for FDFB-SelectAlt, p = 16", 
SELECT_ALT, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 10, 1 << 11, Q26, 1 << 20, 3.19, 1 << 5, 1 << 4, 0,
1 << 5, 1 << 15, 0, 0, 45, {}, RingGSWCryptoParams::PKKEY_FULL, false, 0, 0},
{"small params for FDFB-SelectAlt, p = 32, MULTI-VALUE", 
SELECT_ALT, 32, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 15, 0, 128, 42, {1 << 18, 1 << 27}, RingGSWCryptoParams::PKKEY_FULL, false, 0, 0},
{"small params for FDFB-SelectAlt, p = 16, MULTI-VALUE", 
SELECT_ALT, 16, 0, 0, 0, 0, nullptr, 
n20, 1 << 11, 1 << 12, Q53, 1 << 20, 3.19, 1 << 5, 1 << 18, 0,
1 << 5, 1 << 15, 0, 64, 42, {1 << 18, 1 << 27}, RingGSWCryptoParams::PKKEY_FULL, false, 0, 0},
// {"******************************************** CKKS ********************************************", UNKNOWN}, // banner
// 7 in total
{"small params for EvalFunc-CKKS, f_sigmoid(-8.0, 8.0)->(-2.0, 2.0)", // ok
LMP22, 0, 0, 1 << 7, 1 << 23, 1 << 25, f_sigmoid, 
n25, 1 << 11, 1 << 11, Q53, 1 << 25, 3.19, 1 << 5, 1 << 27, 0,
0, 0, 0, 0, 47, {}, 0, false, 0, 0},
{"small params for Comp-CKKS, f_sigmoid(-8.0, 8.0)->(-2.0, 2.0)", // ok
COMP, 0, 0, 1 << 8, 1 << 23, 1 << 25, f_sigmoid, 
n25, 1 << 11, 1 << 12, Q53, 1 << 25, 3.19, 1 << 5, 1 << 27, 0,
0, 0, 0, 0, 47, {}, 0, false, 0, 0},
{"small params for FDFB-Compress-CKKS, f_sigmoid(-8.0, 8.0)->(-2.0, 2.0)", // ok
COMPRESS, 0, 0, 1 << 8, 1 << 23, 1 << 25, f_sigmoid, 
n25, 1 << 11, 1 << 12, Q53, 1 << 25, 3.19, 1 << 5, 1 << 27, 0,
0, 0, 0, 0, 47, {}, 0, false, 0, 0},
{"small params for FDFB-CancelSign-CKKS, f_sigmoid(-8.0, 8.0)->(-2.0, 2.0)", // ok
CANCELSIGN, 0, 0, 1 << 7, 1 << 23, 1 << 25, f_sigmoid, 
n25, 1 << 11, 1 << 11, Q53, 1 << 25, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 25, 0, 0, 47, {}, RingGSWCryptoParams::PKKEY_FULL, false, 0, 0},
{"small params for FDFB-Select-CKKS, f_sigmoid(-8.0, 8.0)->(-2.0, 2.0)", // ok
SELECT, 0, 0, 1 << 8, 1 << 23, 1 << 25, f_sigmoid, 
n25, 1 << 11, 1 << 12, Q53, 1 << 25, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 25, 0, 0, 47, {}, RingGSWCryptoParams::PKKEY_HALF, false, 0, 0},
{"small params for FDFB-PreSelect-CKKS, f_sigmoid(-8.0, 8.0)->(-2.0, 2.0)",  // ok
PRESELECT, 0, 1 << 8, 1 << 8, 1 << 23, 1 << 25, f_sigmoid, 
n25, 1 << 11, 1 << 12, Q53, 1 << 25, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 25, 2, 0, 47, {}, RingGSWCryptoParams::PKKEY_CONST, false, 0, 0},
{"small params for FDFB-SelectAlt-CKKS, f_sigmoid(-8.0, 8.0)->(-2.0, 2.0)", // ok
SELECT_ALT, 0, 0, 1 << 8, 1 << 23, 1 << 25, f_sigmoid, 
n25, 1 << 11, 1 << 12, Q53, 1 << 25, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 25, 0, 0, 47, {}, RingGSWCryptoParams::PKKEY_FULL, false, 0, 0},
{"small params for Comp-CKKS, f_sigmoid(-8.0, 8.0)->(-2.0, 2.0)", // ok
COMP, 0, 1, 1 << 8, 1 << 23, 1 << 25, f_sigmoid, 
n25, 1 << 11, 1 << 12, Q53, 1 << 25, 3.19, 1 << 5, 1 << 27, 0,
0, 0, 0, 0, 47, {}, 0, false, 0, 0},
};

class MyFixture : public benchmark::Fixture
{
public:
    int64_t cur_param_set_id = -1;
    BinFHEContext cc;
    LWEPrivateKey sk;
};

BENCHMARK_DEFINE_F(MyFixture, SignTest)
(benchmark::State &st)
{

    ParamSet param_set = param_sets[st.range(0)];
    if(cur_param_set_id != st.range(0)){ // new param set, update cc & sk
        cur_param_set_id = st.range(0);
        std::cout << "Chosen parameter set: " << param_set.desc << '\n';
        cc = BinFHEContext();
        cc.GenerateBinFHEContext(param_set.n, param_set.N, param_set.q, param_set.Q, param_set.qKS, param_set.std, param_set.baseKS,
                             param_set.baseG, param_set.baseR, param_set.basePK, param_set.qfrom, param_set.baseG0, param_set.baseGMV, param_set.beta_precise, param_set.p,
                             param_set.baseGs, param_set.pkkey_flags, param_set.multithread, param_set.P, param_set.baseRL, GINX);
        sk = cc.KeyGen();
        cc.BTKeyGen(sk);
    }

    functype ftype = param_set.ftype;

    // auxilary CKKS scheme
    // uint32_t ckks_n = 1 << 16;
    // NativeInteger ckks_Q = uint64_t(1) << 55; // 2^60 is not supported by OpenFHE
    // uint32_t ckks_B_ks;
    // if(param_set.n == n35)
    //     ckks_B_ks = 1 << 12;
    // else if(param_set.n == n25)
    //     ckks_B_ks = 1 << 5;
    // else
    //     OPENFHE_THROW(openfhe_error, "n should be n35 or n25");
    // LWEEncryptionScheme ckks_scheme;
    // // n, N, q, Q, (N, Q) is `outsider` parameters, and (n, q) is `insider` parameters.
    // auto lweparams  = std::make_shared<LWECryptoParams>(param_set.n, ckks_n, param_set.qKS, ckks_Q, param_set.qKS, param_set.std, ckks_B_ks);
    // auto ckks_sk = ckks_scheme.KeyGen(ckks_n, ckks_Q);
    // auto ckks_ksk = ckks_scheme.KeySwitchGenMult(lweparams, sk, ckks_sk);

    // Sample Program: Step 3: Create the to-be-evaluated funciton and obtain its corresponding LUT
    int p = param_set.p; // p = 0 for CKKS

    // NOTE: we only test power-of-2 p for simplicity
    // Initialize random function from Z_p to Z_p
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(p);
    std::vector<NativeInteger> lut(p);
    for (auto &ele : lut)
        ele = dug.GenerateInteger();
    // std::cout << "Evaluate random lut" << lut << "." << std::endl;
    // std::cout << "functype is " << ftype << ".\n";

    // Sample Program: Step 4: evalute f(x) homomorphically and decrypt
    // Note that we check for all the possible plaintexts.
    size_t ptxt_space = p;
    if (p == 0)
    {
        ptxt_space = param_set.q.ConvertToInt(); // CKKS ptxt = full
        dug.SetModulus(ptxt_space);
    }
    bool special_case = param_set.extra.ConvertToInt() > 0;
    for (auto _ : st)
    {
        st.PauseTiming();
        size_t m = dug.GenerateInteger().ConvertToInt();
        auto ct1 = cc.Encrypt(sk, m % ptxt_space, FRESH, ptxt_space);
        // NOTE: if our target is benchmarking only, we do not need to care about the input value
        LWECiphertext ct_f;
        st.ResumeTiming();

        switch (ftype)
        {
        case LMP22:
            ct_f = cc.EvalFuncTest(ct1, lut, param_set.deltain, param_set.deltaout, param_set.qout, param_set.f);
            break;
        case COMPRESS:
            ct_f = cc.EvalFuncCompress(ct1, lut, param_set.deltain, param_set.deltaout, param_set.qout, param_set.f);
            break;
        case CANCELSIGN:
            ct_f = cc.EvalFuncCancelSign(ct1, lut, param_set.deltain, param_set.deltaout, param_set.qout, param_set.f);
            break;
        case SELECT:
            ct_f = cc.EvalFuncSelect(ct1, lut, param_set.deltain, param_set.deltaout, param_set.qout, param_set.f, param_set.baseGs.size() > 0 ? 1 << 27: param_set.baseG);
            break;
        case PRESELECT:
            ct_f = cc.EvalFuncPreSelect(ct1, lut, param_set.deltain, param_set.deltaout, param_set.qout, param_set.f,
                                        param_set.extra); // NOTE: extra = pmid here
            break;
        case COMP: // TODO: more f_property
            ct_f = cc.EvalFuncComp(ct1, lut, param_set.deltain, param_set.deltaout, param_set.qout, param_set.f, 
                special_case ? 1 : 0, special_case ? 0.5 : 0, param_set.baseGs.size() > 0 ? 1 << 27: param_set.baseG);
            break;
        case BFVMULT:
            ct_f = cc.EvalFuncBFV(ct1, lut, param_set.deltain, param_set.deltaout, param_set.qout, param_set.f);
            break;
        case SELECT_ALT:
            ct_f = cc.EvalFuncSelectAlt(ct1, lut, param_set.deltain, param_set.deltaout, param_set.qout, param_set.f, param_set.baseGs.size() > 0 ? 1 << 27: param_set.baseG);
            break;
        case WoPPBS1:
            ct_f = cc.EvalFuncWoPPBS1(ct1, lut, param_set.deltain, param_set.deltaout, param_set.qout, param_set.f);
            break;
        case WoPPBS2:
            ct_f = cc.EvalFuncWoPPBS2(ct1, lut, param_set.deltain, param_set.deltaout, param_set.qout, param_set.f);
            break;
        case KS21:
            ct_f = cc.EvalFuncKS21(ct1, lut, param_set.deltain, param_set.deltaout, param_set.qout, param_set.f);
            break;
        default:
            OPENFHE_THROW(openfhe_error, "unknown functype");
            break;
        }

    }
}

// the last 7 params are for CKKS
BENCHMARK_REGISTER_F(MyFixture, SignTest)->DenseRange(param_sets.size() - 8, param_sets.size()-1, 1)->Repetitions(100);
BENCHMARK_MAIN();

//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Example for the FHEW scheme arbitrary function evaluation
 */

// #define PROFILE
#include "binfhecontext.h"

using namespace lbcrypto;

double f_sigmoid(double x)
{
    return 1 / (1 + std::exp(-x));
}

// just to illustrate the affect of Lipschitz constant on evaluation error
double f_sigmoid2(double x){
    return f_sigmoid(x * 2);
}

double f_id(double x){
    return x;
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

// outdated params (<128-bit security)
// NativeInteger P54 = FirstPrime<NativeInteger>(54, 1 << 12);
// NativeInteger Q54 = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(54, 1 << 12), 1 << 12); // XXX: OpenFHE has a bug here, they used N instead of m
// NativeInteger Q27 = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 1 << 11), 1 << 11);

// updated params (128-bit security)
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
//(2**12, 745, 2**54, 2**11, 2**11, 2**15, 2**35, 2**5)
std::vector<ParamSet> param_sets = {
{"******************************************** standard ********************************************", UNKNOWN}, // bannner, ok
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
{"******************************************** small & tiny ********************************************", UNKNOWN}, // banner
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
{"******************************************** CKKS ********************************************", UNKNOWN}, // banner
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
{"small params for Comp-CKKS, f_sigmoid(-8.0, 8.0)->(-2.0, 2.0) [odd function test]", // ok
COMP, 0, 1, 1 << 8, 1 << 23, 1 << 25, f_sigmoid, // NOTE: here extra = 1 means this function is computed using the odd-function trick
n25, 1 << 11, 1 << 12, Q53, 1 << 25, 3.19, 1 << 5, 1 << 27, 0,
0, 0, 0, 0, 47, {}, 0, false, 0, 0},
{"******************************************** CKKS(id) ********************************************", UNKNOWN}, // banner
{"small params for EvalFunc-CKKS, f_id(-8.0, 8.0)->(-8.0, 8.0)", // ok
LMP22, 0, 0, 1 << 7, 1 << 7, 1 << 11, f_id, 
n25, 1 << 11, 1 << 11, Q53, 1 << 25, 3.19, 1 << 5, 1 << 27, 0,
0, 0, 0, 0, 47, {}, 0, false, 0, 0},
{"small params for Comp-CKKS, f_id(-8.0, 8.0)->(-8.0, 8.0)", // ok
COMP, 0, 0, 1 << 8, 1 << 8, 1 << 12, f_id, 
n25, 1 << 11, 1 << 12, Q53, 1 << 25, 3.19, 1 << 5, 1 << 27, 0,
0, 0, 0, 0, 47, {}, 0, false, 0, 0},
{"small params for FDFB-Compress-CKKS, f_id(-8.0, 8.0)->(-8.0, 8.0)", // ok
COMPRESS, 0, 0, 1 << 8, 1 << 8, 1 << 12, f_id, 
n25, 1 << 11, 1 << 12, Q53, 1 << 25, 3.19, 1 << 5, 1 << 27, 0,
0, 0, 0, 0, 47, {}, 0, false, 0, 0},
{"small params for FDFB-CancelSign-CKKS, f_id(-8.0, 8.0)->(-8.0, 8.0)", // ok
CANCELSIGN, 0, 0, 1 << 7, 1 << 7, 1 << 11, f_id, 
n25, 1 << 11, 1 << 11, Q53, 1 << 25, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 25, 0, 0, 47, {}, RingGSWCryptoParams::PKKEY_FULL, false, 0, 0},
{"small params for FDFB-Select-CKKS, f_id(-8.0, 8.0)->(-8.0, 8.0)", // ok
SELECT, 0, 0, 1 << 8, 1 << 8, 1 << 12, f_id, 
n25, 1 << 11, 1 << 12, Q53, 1 << 25, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 25, 0, 0, 47, {}, RingGSWCryptoParams::PKKEY_HALF, false, 0, 0},
{"small params for FDFB-PreSelect-CKKS, f_id(-8.0, 8.0)->(-8.0, 8.0)",  // ok
PRESELECT, 0, 1 << 8, 1 << 8, 1 << 8, 1 << 12, f_id, 
n25, 1 << 11, 1 << 12, Q53, 1 << 25, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 25, 2, 0, 47, {}, RingGSWCryptoParams::PKKEY_CONST, false, 0, 0},
{"small params for FDFB-SelectAlt-CKKS, f_id(-8.0, 8.0)->(-8.0, 8.0)", // ok
SELECT_ALT, 0, 0, 1 << 8, 1 << 8, 1 << 12, f_id, 
n25, 1 << 11, 1 << 12, Q53, 1 << 25, 3.19, 1 << 5, 1 << 27, 0,
1 << 5, 1 << 25, 0, 0, 47, {}, RingGSWCryptoParams::PKKEY_FULL, false, 0, 0},
{"small params for Comp-CKKS, f_id(-8.0, 8.0)->(-8.0, 8.0) [odd function test]", // ok
COMP, 0, 1, 1 << 8, 1 << 8, 1 << 12, f_id, // NOTE: here extra = 1 means this function is computed using the odd-function trick
n25, 1 << 11, 1 << 12, Q53, 1 << 25, 3.19, 1 << 5, 1 << 27, 0,
0, 0, 0, 0, 47, {}, 0, false, 0, 0},
};

int main(int argc, char **argv)
{
    // Sample Program: Step 1: Set CryptoContext
    /**
     * parameter set
     * LWE Q = 2^17  # upper bound is 2^29
     * LWE n = 1305
     * q_ks = 2^35
     * B_ks = 2^5
     * case
     *  LWE Q >= 2^26, B_g = 2^14, N = 2^11, RLWE Q ~= 2^54, q = 2^12, max Bnd = 72  # HomNoiseReduction can use B_g = 2^18
     *  LWE Q >= 2^17, B_g = 2^18, N = 2^11, RLWE Q ~= 2^54, q = 2^12, max Bnd = 59 ~ 55
     *  LWE Q >= 2^12, B_g = 2^27, N = 2^11, RLWE Q ~= 2^54, q = 2^12, max Bnd = 58 ~ 55 -> Q = 2^12 is used for arbitrary func eval
     *  LWE Q =  2^11, B_g = 2^5 , N = 2^10, RLWE Q ~= 2^27, q = 2^12 -> for arbitrary func eval
     *
     * new case
     * LWE Q >= 2^21, B_g = 2^18
     * LWE Q >= 2^12, B_g = 2^27
     */
    if (argc <= 1)
    {
        std::cout << "Please specify a parameter set among listed below:\n";
        for (size_t i = 0; i < param_sets.size(); i++)
            std::cout << i << ": " << param_sets[i].desc << '\n';
        return 0;
    }    
    
    // std::cout << "Q54 = " << Q_54 << "; P54 = " << P54 << "; Q27 = " << Q27 << '\n';

    ParamSet param_set = param_sets[std::stoi(argv[1])];
    std::cout << "Chosen parameter set: " << param_set.desc << '\n';

    functype ftype = param_set.ftype;

    // Sample Program: Step 1: Set CryptoContext
    auto cc = BinFHEContext();
    // LMP22 and CANCELSIGN reserves one bit for padding; for SELECT, we need to set B_g to 2^18
    // note that we can use B_g = 2^27 for the last bootstrap in SELECT
    cc.GenerateBinFHEContext(param_set.n, param_set.N, param_set.q, param_set.Q, param_set.qKS, param_set.std, param_set.baseKS,
                             param_set.baseG, param_set.baseR, param_set.basePK, param_set.qfrom, param_set.baseG0, param_set.baseGMV, param_set.beta_precise, param_set.p,
                             param_set.baseGs, param_set.pkkey_flags, param_set.multithread, param_set.P, param_set.baseRL, GINX);
    // cc.GenerateBinFHEContext(STD128, ftype == LMP22 || ftype == CANCELSIGN, 12, 0, GINX, false, ftype == SELECT ? (1 << 18) : 0);

    // Sample Program: Step 2: Key Generation

    // Generate the secret key
    auto sk = cc.KeyGen();

    // auxilary CKKS scheme
    uint32_t ckks_n = 1 << 16;
    NativeInteger ckks_Q = uint64_t(1) << 55; // 2^60 is not supported by OpenFHE
    uint32_t ckks_B_ks;
    if(param_set.n == n35)
        ckks_B_ks = 1 << 12;
    else if(param_set.n == n25)
        ckks_B_ks = 1 << 5;
    else
        OPENFHE_THROW(openfhe_error, "n should be n35 or n25");
    LWEEncryptionScheme ckks_scheme;
    // n, N, q, Q, (N, Q) is `outsider` parameters, and (n, q) is `insider` parameters.
    auto lweparams  = std::make_shared<LWECryptoParams>(param_set.n, ckks_n, param_set.qKS, ckks_Q, param_set.qKS, param_set.std, ckks_B_ks);
    auto ckks_sk = ckks_scheme.KeyGen(ckks_n, ckks_Q);
    auto ckks_ksk = ckks_scheme.KeySwitchGenMult(lweparams, sk, ckks_sk);

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 3: Create the to-be-evaluated funciton and obtain its corresponding LUT
    int p = param_set.p; // p = 0 for CKKS

    // NOTE: we only test power-of-2 p for simplicity
    // Initialize random function from Z_p to Z_p
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(p);
    std::vector<NativeInteger> lut(p);
    for (auto &ele : lut)
        ele = dug.GenerateInteger();
    //std::cout << "Evaluate random lut" << lut << "." << std::endl;
    std::cout << "functype is " << ftype << ".\n";

    // Sample Program: Step 4: evalute f(x) homomorphically and decrypt
    // Note that we check for all the possible plaintexts.
    uint64_t time_counter = 0;
    // double diff_sum = 0, diff_square_sum = 0;
    size_t n_loop = p;
    size_t ptxt_space = p;
    double input_bound = 0;
    bool extracted = false; // if set to true, input continuous ciphertext is KSed and MSed from a CKKS ciphertext
    bool rand_input = false; // if set to true, input continuous ciphertext will be random
    bool fixed_point = false; // if set to true, all input continuous ciphertext will be assigned to `fixed_input`
    double fixed_input = 0;
    size_t eval_iter = 1;

    std::vector<double> diff_sum(eval_iter), diff_square_sum(eval_iter);

    if (p == 0)
    {
        input_bound = param_set.q.ConvertToDouble() / param_set.deltain / 2;
        n_loop = 1000;                            // number of CKKS evals
        ptxt_space = extracted ? ckks_Q.ConvertToInt() : param_set.q.ConvertToInt(); // CKKS ptxt = full
        dug.SetModulus(ptxt_space);
    }
    std::vector<size_t> err_iters;
    // bool special_case = param_set.extra.ConvertToInt() > 0 && param_set.f == f_sigmoid; // special case for Comp
    uint32_t f_property = param_set.extra > 0 ? 1 : 0;
    double shift = (f_property && param_set.f == f_sigmoid) ? 0.5 : 0;

    // std::cout << "input bound = " << input_bound << ", ptxt space = " << ptxt_space << '\n';

    double ckks_deltain = param_set.deltain * ckks_Q.ConvertToDouble() / param_set.q.ConvertToDouble();
    double actual_deltain = extracted ? ckks_deltain : param_set.deltain;

    for (size_t i = 0; i < n_loop; i++)
    {
        size_t m = i;
        LWECiphertext ct1;
        if (p == 0)
        {   
            if(fixed_point)
                m = fixed_input * actual_deltain + 0.5;
            else if (rand_input)
                m = dug.GenerateInteger().ConvertToInt();
            else
            {
                double tmp = double(i + 1) * 2 * input_bound / (n_loop + 1) - input_bound;
                if (tmp < 0)
                    tmp += 2 * input_bound;
                m = tmp * actual_deltain;
                // std::cout << "tmp = " << tmp << ", deltain = " << actual_deltain << ", m = " << m << '\n';
            }
            if(extracted){
                ct1 = ckks_scheme.Encrypt(lweparams, ckks_sk, m, ptxt_space, ckks_Q); // the only usage of lweparams here is to provide a dgg
                // freshly extracted ct1 is error-free
                LWEPlaintext tmp;
                cc.Decrypt(ckks_sk, ct1, &tmp, ptxt_space);
                cc.GetLWEScheme()->EvalAddConstEq(ct1, NativeInteger(m).ModSub(tmp, ptxt_space));
                // mod switch + key switch + mod switch
                ct1 = ckks_scheme.ModSwitch(param_set.qKS, ct1);
                ct1 = ckks_scheme.KeySwitchMult(lweparams, ckks_ksk, ct1);
                ct1 = ckks_scheme.ModSwitch(param_set.q, ct1);
            }
            else{
                ct1 = cc.Encrypt(sk, m % ptxt_space, FRESH, ptxt_space);
                LWEPlaintext tmp;
                cc.Decrypt(sk, ct1, &tmp, ptxt_space);
                cc.GetLWEScheme()->EvalAddConstEq(ct1, NativeInteger(m).ModSub(tmp, ptxt_space));
            }
        }
        else
            ct1 = cc.Encrypt(sk, m % ptxt_space, FRESH, ptxt_space);
        LWECiphertext ct_f;
        for(size_t j = 0; j < eval_iter; j++){
            auto t_start = std::chrono::steady_clock::now();
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
                    f_property, shift, param_set.baseGs.size() > 0 ? 1 << 27: param_set.baseG);
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
            auto t_end = std::chrono::steady_clock::now();
            std::cout << "time elapsed = " << (t_end - t_start).count() << " ns\n";
                time_counter += (t_end - t_start).count();
            // check correctness / precision
            if (p > 0)
            {
                LWEPlaintext result;
                cc.Decrypt(sk, ct_f, &result, p);

                std::cout << "Input: " << m << ". Expected: " << lut[m] << ". Evaluated = " << result << ".";
                if (static_cast<uint64_t>(result) != lut[m].ConvertToInt())
                {
                    std::cout << " ERROR!!!!!!!!!!";
                    err_iters.push_back(i);
                }
                std::cout << "\n\n";
            }
            else
            {
                LWEPlaintext result;
                cc.Decrypt(sk, ct_f, &result, ct_f->GetModulus().ConvertToInt());

                int64_t m_signed = m, res_signed = result;
                if (m >= ptxt_space / 2)
                    m_signed -= ptxt_space;
                if (result >= static_cast<int64_t>(ct_f->GetModulus().ConvertToInt()) / 2)
                    res_signed -= ct_f->GetModulus().ConvertToInt();

                std::cout << "Evaluated int = " << res_signed << "\n";

                double fp_result = double(res_signed) / param_set.deltaout,
                    fp_in = double(m_signed) / actual_deltain;
                double expected = fp_in;
                for(size_t k = 0; k <= j; k++)
                    expected = param_set.f(expected);
                double diff = abs(expected - fp_result);
                std::cout << "Input: " << fp_in << ". Expected: " << expected
                        << ". Evaluated = " << fp_result << ". Diff = " << diff << ". ";
                if (diff >= 0.1)
                {
                    std::cout << "TOO LARGE!!!!!\n";
                    err_iters.push_back(i);
                }
                std::cout << "\n\n";
                // diff_sum += diff;
                // diff_square_sum += diff * diff;
                diff_sum[j] += diff;
                diff_square_sum[j] += diff * diff;
            }
            // iterate
            ct1 = std::make_shared<LWECiphertextImpl>(*ct_f);
        } // end j = [evaliter]
        std::cout << "##############################\n";
    }
    std::cout << "Mean elapsed time = " << time_counter / (n_loop * eval_iter) << '\n';
    if (p == 0)
    {
        for(size_t j = 0; j < eval_iter; j++){
            std::cout << "Mean diff " << j << " = " << diff_sum[j] / n_loop << "\n";
            std::cout << "Diff std " << j << " = " << sqrt(diff_square_sum[j] / n_loop) << "\n";
        }
    }
    std::cout << "Err iters are: " << err_iters << '\n';
    return err_iters.size() > 0 ? 1 : 0;
}

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
  Example for the FHEW scheme large precision sign evaluation
 */

// #define PROFILE
#include "binfhecontext.h"

using namespace lbcrypto;

NativeInteger Q53 = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(53, 1 << 12), 1 << 12);
uint32_t n35 = 1340;

enum DecompType
{
    LMP22,
    LMP22ALT,
    REDUCE,
    COMPRESS
};

std::vector<uint32_t> get_bases(DecompType decomp_type, uint64_t qin)
{
    switch (decomp_type)
    {
    case LMP22:
        if (qin > 1 << 29)
            OPENFHE_THROW(openfhe_error, "max qin = 2^29");
        if (qin >= 1 << 26)
            return {1 << 14, 1 << 18, 1 << 27};
        if (qin >= 1 << 17)
            return {1 << 18, 1 << 27};
        return {1 << 27};
    case LMP22ALT:
        if(qin > uint64_t(1) << 31)
            OPENFHE_THROW(openfhe_error, "max qin = 2^31");
        if(qin >= 1 << 28)
            return {1 << 14, 1 << 18, 1 << 27};
        if(qin >= 1 << 20)
            return {1 << 18, 1 << 27};
        return {1 << 27};
    case REDUCE:
        if (qin > uint64_t(1) << 31)
            OPENFHE_THROW(openfhe_error, "max qin = 2^31");
        if(qin >= 1 << 29)
            return {1 << 14, 1 << 18, 1 << 27};
        if (qin >= 1 << 20)
            return {1 << 18, 1 << 27};
        return {1 << 27};
    case COMPRESS:
        if(qin > uint64_t(1) << 33)
            OPENFHE_THROW(openfhe_error, "max qin = 2^33");
        if(qin >= 1 << 30)
            return {1 << 14, 1 << 18, 1 << 27};
        if (qin >= 1 << 21)
            return {1 << 18, 1 << 27};
        return {1 << 27};
    default:
        OPENFHE_THROW(openfhe_error, "unrecognized case");
    }
}

struct ParamSet
{
    std::string desc;
    DecompType dec_type;
    uint32_t p;
    // basic scheme params
    uint32_t n;
    uint32_t N;
    NativeInteger q;
    NativeInteger Q;
    NativeInteger qKS;
    double std;
    uint32_t baseKS;
    uint32_t baseR;
    // extra params
    uint32_t beta_precise;
};

std::vector<ParamSet> param_sets = {
    {"Decomposition Using HomFloor", LMP22, 16, n35, 1 << 11, 1 << 12, Q53, uint64_t(1) << 35, 3.19, 1 << 5, 0, 55},
    {"Decomposition Using HomFloorAlt", LMP22ALT, 32, n35, 1 << 11, 1 << 12, Q53, uint64_t(1) << 35, 3.19, 1 << 5, 0, 55},
    {"Decomposition Using HomDecomp-Reduce", REDUCE, 16, n35, 1 << 11, 1 << 12, Q53, uint64_t(1) << 35, 3.19, 1 << 5, 0, 55},
    {"Decomposition Using HomDecomp-FDFB", COMPRESS, 32, n35, 1 << 11, 1 << 12, Q53, uint64_t(1) << 35, 3.19, 1 << 5, 0, 55}};

int main(int argc, char **argv)
{
    if (argc <= 2)
    {
        std::cout << "Usages: " << argv[0] << " param_set_id qin\n";
        std::cout << "Please specify a parameter set among listed below:\n";
        for (size_t i = 0; i < param_sets.size(); i++)
            std::cout << i << ": " << param_sets[i].desc << '\n';
        return 0;
    }
    size_t param_idx = std::stoi(argv[1]);
    uint64_t qin = uint64_t(1) << std::stoi(argv[2]);
    ParamSet param_set = param_sets[param_idx];
    std::cout << "select param set = " << param_set.desc << '\n';
    std::vector<uint32_t> baseGs = get_bases(param_set.dec_type, qin);
    auto B_g = baseGs[0];
    /**
     * parameter sets
     * n = n35
     * q_ks = 2^35
     * B_ks = 2^5
     *
     * HomFloor
     * Q <= 2^29
     * case
     *  LWE Q >= 2^26, B_g = 2^14, N = 2^11, RLWE Q ~= 2^54, q = 2^12  # HomNoiseReduction can use B_g = 2^18
     *  LWE Q >= 2^17, B_g = 2^18, N = 2^11, RLWE Q ~= 2^54, q = 2^12
     *  LWE Q >= 2^12, B_g = 2^27, N = 2^11, RLWE Q ~= 2^54, q = 2^12 -> Q = 2^12 is used for arbitrary func eval
     *  LWE Q =  2^11, B_g = 2^5 , N = 2^10, RLWE Q ~= 2^27, q = 2^12 -> for arbitrary func eval
     *
     * HomFloorAlt
     * Q <= 2^31
     * case
     *  Q >= 2^28, B_g = 2^14
     *  Q >= 2^20, B_g = 2^18
     *  otherwise, Q = 2^27
     */

    /**
     * parameter set for DecompNew
     * Q <= 2^31 (XXX: theoretical max Q = 2^32, however experiment suggests that the error rate when Q=2^32 is quite large)
     * NOTE: maybe the ACC error is not completely random (as suggested in GBA21)
     * 
     * case
     *   LWE Q >= 2^29, B_g = 2^14
     *   LWE Q >= 2^20, B_g = 2^18
     *   otherwise,     B_g = 2^27
     *
     * parameter set for DecompCompress
     * upper bound for Q is 2^33
     * case
     *   LWE Q >= 2^30, B_g = 2^14
     *   LWE Q >= 2^21, B_g = 2^18
     *   otherwise,     B_g = 2^27
     */

    auto cc = BinFHEContext();

    // Set the ciphertext modulus to be 1 << 17
    // Note that normally we do not use this way to obtain the input ciphertext.
    // Instead, we assume that an LWE ciphertext with large ciphertext
    // modulus is already provided (e.g., by extracting from a CKKS ciphertext).
    // However, we do not provide such a step in this example.
    // Therefore, we use a brute force way to create a large LWE ciphertext.
    cc.GenerateBinFHEContext(param_set.n, param_set.N, param_set.q, param_set.Q, param_set.qKS, param_set.std,
                             param_set.baseKS, B_g, param_set.baseR, 0, 0, 0, 0, 0, param_set.p, baseGs, 0, false, 0, 0, GINX);

    /**
     * note:
     * beta is always 128
     * Q = LWE ctxt modulus
     * q = lower bits space = RLWE ring dimension * 2 if arbfunc is False else RLWE ring dimension
     * p = plaintext space mod Q
     */

    int factor = 1 << int(log2(qin) - log2(param_set.q.ConvertToInt())); // Q/q
    int p = cc.GetMaxPlaintextSpace().ConvertToInt() * factor;           // Obtain the maximum plaintext space
    std::cout << "log2(large p) = " << int(log2(p)) << '\n';

    // Sample Program: Step 2: Key Generation
    // Generate the secret key
    auto sk = cc.KeyGen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);

    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 3: Extract the MSB and decrypt to check the result
    // Note that we check for 8 different numbers
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(p);
    for (int i = 0; i < 8; i++)
    {
        // We first encrypt with large Q
        auto m = dug.GenerateInteger().ConvertToInt();
        auto ct1 = cc.Encrypt(sk, m, FRESH, p, qin);
        std::vector<LWECiphertext> decomp_array;
        // Get the MSB
        switch (param_set.dec_type)
        {
        case LMP22:
            decomp_array = cc.EvalDecomp(ct1);
            break;
        case LMP22ALT:
            decomp_array = cc.EvalDecompAlt(ct1);
            break;
        case REDUCE:
            decomp_array = cc.EvalDecompNew(ct1);
            break;
        case COMPRESS:
            decomp_array = cc.EvalDecompCompress(ct1);
            break;
        default:
            OPENFHE_THROW(openfhe_error, "unrecognized dec type");
        }
        size_t k = 0;
        for (uint32_t j = p; j > 1; j /= param_set.p, k++, m /= param_set.p)
        {
            LWEPlaintext plain;
            size_t cur_mod = std::min(j, param_set.p);
            cc.Decrypt(sk, decomp_array[k], &plain, cur_mod);
            LWEPlaintext expected = m % cur_mod;
            std::cout << "expected = " << expected << ", got = " << plain << ". ";
            if (expected != plain)
                std::cout << "ERROR!!!\n";
            else
                std::cout << "\n";
        }
        if (k != decomp_array.size())
            std::cout << "something wrong: " << p << " ### " << param_set.p << " ### " << decomp_array.size() << '\n';
        std::cout << "\n";
    }

    return 0;
}

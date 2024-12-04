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
  Example for the FHEW scheme large precision ReLU evaluation
 */

// #define PROFILE
#include "binfhecontext.h"

using namespace lbcrypto;

NativeInteger Q53 = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(53, 1 << 12), 1 << 12);
uint32_t n35 = 1340;

// enum JobType {
//     DECOMP,
//     RELU,
//     SIGN
// };

// enum DecompType {
//     HOMFLOOR,
//     HOMFLOOR_ALT,
//     HOMDECOMP_REDUCE,
//     HOMDECOMP_FDFB
// };

struct ParamSet
{
    std::string desc;
    uint32_t qin;
    uint32_t p_large; // ptxt space for large LWE ciphertext
    uint32_t p;
    uint32_t relu_baseG; // baseG for ReLU
    double delta;
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
    // extra params
    uint32_t basePK;
    NativeInteger qfrom;
    uint32_t beta_precise;
    std::vector<uint32_t> baseGs;
    uint32_t pkkey_flags;
};

std::vector<ParamSet> param_sets = {
    {"ReLU with HomDecomp-Reduce, p = 2^10, Bg = 2^27", 1 << 28, 1 << 10, 16, 1 << 27, 0, n35, 1 << 11, 1 << 12, Q53, uint64_t(1) << 35, 3.19, 1 << 5, 1 << 18, 0, 1 << 5, uint64_t(1) << 35, 56, {1 << 18, 1 << 27}, RingGSWCryptoParams::PKKEY_HALF_TRANS},
    {"ReLU with HomDecomp-Reduce, p = 2^18, Bg = 2^18", 1 << 28, 1 << 18, 16, 1 << 18, 0, n35, 1 << 11, 1 << 12, Q53, uint64_t(1) << 35, 3.19, 1 << 5, 1 << 18, 0, 1 << 5, uint64_t(1) << 35, 56, {1 << 18, 1 << 27}, RingGSWCryptoParams::PKKEY_HALF_TRANS},
    {"ReLU with HomDecomp-Reduce, p = 2^22, Bg = 2^14", 1 << 28, 1 << 22, 16, 1 << 14, 0, n35, 1 << 11, 1 << 12, Q53, uint64_t(1) << 35, 3.19, 1 << 5, 1 << 18, 0, 1 << 5, uint64_t(1) << 35, 56, {1 << 14, 1 << 18, 1 << 27}, RingGSWCryptoParams::PKKEY_HALF_TRANS},
    {"ReLU with HomDecomp-Reduce, CKKS, Bg = 2^27", 1 << 28, 0, 32, 1 << 27, 1 << 24, n35, 1 << 11, 1 << 12, Q53, uint64_t(1) << 35, 3.19, 1 << 5, 1 << 18, 0, 1 << 5, uint64_t(1) << 35, 56, {1 << 18, 1 << 27}, RingGSWCryptoParams::PKKEY_HALF_TRANS},
    {"ReLU with HomDecomp-Reduce, CKKS, Bg = 2^18", 1 << 28, 0, 32, 1 << 18, 1 << 24, n35, 1 << 11, 1 << 12, Q53, uint64_t(1) << 35, 3.19, 1 << 5, 1 << 18, 0, 1 << 5, uint64_t(1) << 35, 56, {1 << 18, 1 << 27}, RingGSWCryptoParams::PKKEY_HALF_TRANS},
    {"ReLU with HomDecomp-Reduce, CKKS, Bg = 2^14", 1 << 28, 0, 32, 1 << 14, 1 << 24, n35, 1 << 11, 1 << 12, Q53, uint64_t(1) << 35, 3.19, 1 << 5, 1 << 18, 0, 1 << 5, uint64_t(1) << 35, 56, {1 << 14, 1 << 18, 1 << 27}, RingGSWCryptoParams::PKKEY_HALF_TRANS},
};

int main(int argc, char **argv)
{
    if (argc <= 1)
    {
        std::cout << "Please specify a parameter set among listed below:\n";
        for (size_t i = 0; i < param_sets.size(); i++)
            std::cout << i << ": " << param_sets[i].desc << '\n';
        return 0;
    }
    size_t param_idx = std::stoi(argv[1]);
    ParamSet param_set = param_sets[param_idx];
    std::cout << "selected param set: " << param_set.desc << '\n';
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
                             param_set.baseKS, param_set.baseG, param_set.baseR, param_set.basePK, param_set.qfrom, 0, 0, 0, param_set.p, param_set.baseGs, param_set.pkkey_flags, false, 0, 0, GINX);

    /**
     * note:
     * beta is always 128
     * Q = LWE ctxt modulus
     * q = lower bits space = RLWE ring dimension * 2 if arbfunc is False else RLWE ring dimension
     * p = plaintext space mod Q
     */

    uint32_t p = param_set.p_large;
    if (p == 0)
        p = param_set.qin;

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
    size_t time_counter = 0;
    size_t nloop = 8;
    std::vector<size_t> err_iters;
    double diff_sum = 0, diff_square_sum = 0;
    for (size_t i = 0; i < nloop; i++)
    {
        // We first encrypt with large Q
        auto m = dug.GenerateInteger().ConvertToInt();

        auto t_start = std::chrono::steady_clock::now();
        auto ct1 = cc.Encrypt(sk, m, FRESH, p, param_set.qin);
        // only decomp algorithms is refractored, because sign & relu can be computed using decomp
        auto decomp_vec = cc.EvalDecompNew(ct1);
        LWECiphertext ct_msd = decomp_vec[decomp_vec.size() - 1];

        // XXX: debug
        // LWEPlaintext dbg;
        // cc.Decrypt(sk, ct_msd, &dbg, 2);
        // std::cout << "ct_sgn = " << dbg << "\n";
        // debug

        auto ct_relu = cc.EvalReLU(ct1, ct_msd, 1 << 27, param_set.relu_baseG);

        auto t_end = std::chrono::steady_clock::now();
        std::cout << "time elapsed = " << (t_end - t_start).count() << " ns\n";
        time_counter += (t_end - t_start).count();

        if (param_set.p_large > 0)
        {
            LWEPlaintext res;
            cc.Decrypt(sk, ct_relu, &res, p);
            uint32_t expected = (m >= p / 2) ? 0 : m;
            std::cout << "m = " << m << ". MSB(m) = " << (m >= p / 2) << ". res = " << res << ". ";
            if (res != expected){
                std::cout << "ERROR!!!";
                err_iters.push_back(i);}
            std::cout << "\n\n";
        }
        else{ // CKKS
            LWEPlaintext res;
            cc.Decrypt(sk, ct_relu, &res, ct_relu->GetModulus().ConvertToInt());

            int64_t m_signed = m, res_signed = res;
            if (m >= p / 2)
                m_signed -= p;
            if (res >= static_cast<int64_t>(ct_relu->GetModulus().ConvertToInt()) / 2)
                res_signed -= ct_relu->GetModulus().ConvertToInt();

            std::cout << "Evaluated int = " << res_signed << "\n";

            double fp_result = double(res_signed) / (param_set.delta * ct_relu->GetModulus().ConvertToDouble() / param_set.qin),
                   fp_in = double(m_signed) / param_set.delta;
            double expected = fp_in > 0 ? fp_in : 0, diff = abs(expected - fp_result);
            std::cout << "Input: " << fp_in << ". Expected: " << expected
                      << ". Evaluated = " << fp_result << ". Diff = " << diff << ". ";
            if (diff >= 0.1)
            {
                std::cout << "TOO LARGE!!!!!\n";
                err_iters.push_back(i);
            }
            std::cout << "\n\n";
            diff_sum += diff;
            diff_square_sum += diff * diff;
        }
    }
    std::cout << "Mean elapsed time = " << time_counter / nloop << " ns\n";
    if(param_set.p_large == 0){
        std::cout << "Mean diff = " << diff_sum / nloop << '\n';
        std::cout << "Mean stddev = " << sqrt(diff_square_sum / nloop) << '\n';
    }
    std::cout << "Err iters are: " << err_iters << '\n';
    return err_iters.size() > 0 ? 1 : 0;
}

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
  Implementation file for Boolean Circuit FHE context class
 */

#include "binfhecontext.h"
#include <string>
#include <unordered_map>

static constexpr double STD_DEV = 3.19;

namespace lbcrypto {

void BinFHEContext::GenerateBinFHEContext(uint32_t n, uint32_t N, const NativeInteger& q, const NativeInteger& Q,
                                          double std, uint32_t baseKS, uint32_t baseG, uint32_t baseR,
                                          SecretKeyDist keyDist, BINFHE_METHOD method, uint32_t numAutoKeys) {
    auto lweparams = std::make_shared<LWECryptoParams>(n, N, q, Q, Q, std, baseKS);
    auto rgswparams =
        std::make_shared<RingGSWCryptoParams>(N, Q, q, baseG, baseR, method, std, keyDist, true, numAutoKeys);
    m_params       = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams);
    m_binfhescheme = std::make_shared<BinFHEScheme>(method);
}
/**
 * baseR is used only for DM method, it does not matter what we set it to
*/
void BinFHEContext::GenerateBinFHEContext(uint32_t n, uint32_t N, const NativeInteger& q, const NativeInteger& Q,
                                          const NativeInteger& qKS, double std, uint32_t baseKS, uint32_t baseG,
                                          uint32_t baseR, uint32_t basePK, const NativeInteger& qfrom, uint32_t baseG0,
                                          uint32_t baseGMV, uint32_t beta_precise, uint32_t p,
                                          const std::vector<uint32_t>& baseGs, uint32_t pkkey_flags, bool multithread,
                                          const NativeInteger& P, uint32_t baseRL, BINFHE_METHOD method) {
    auto lweparams  = std::make_shared<LWECryptoParams>(n, N, q, Q, qKS, std, baseKS);
    auto rgswparams = std::make_shared<RingGSWCryptoParams>(N, Q, q, baseG, baseR, method, std, false, basePK, qfrom,
                                                            baseG0, baseGMV, baseGs, pkkey_flags, P, baseRL);
    m_params        = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams, multithread);
    m_binfhescheme  = std::make_shared<BinFHEScheme>(method);
    m_beta_precise  = beta_precise;  // FIXME: still kind of ugly... this property should belong to a single EK
    m_half_gap      = p > 0 ? (q.ConvertToInt() + p) / (2 * p) : 64;
}

void BinFHEContext::GenerateBinFHEContext(BINFHE_PARAMSET set, bool arbFunc, uint32_t logQ, int64_t N,
                                          BINFHE_METHOD method, bool timeOptimization, uint32_t B_g) {
    if (set != STD128 && set != STD128_Binary && set != TOY)
        OPENFHE_THROW("STD128 and TOY are the only supported sets");
    if (logQ > 29)
        OPENFHE_THROW("logQ > 29 is not supported");
    if (logQ < 11)
        OPENFHE_THROW("logQ < 11 is not supported");

    auto logQprime = 54;
    uint32_t baseG = 0;
    if (logQ > 25) {
        baseG = 1 << 14;
    }
    else if (logQ > 16) {
        baseG = 1 << 18;
    }
    else if (logQ > 11) {
        baseG = 1 << 27;
    }
    else {  // if (logQ == 11)
        baseG     = 1 << 5;
        logQprime = 27;
    }
    if (B_g != 0)  // manual override
        baseG = B_g;

    // choose minimum ringD satisfying sl and Q
    // if specified some larger N, security is also satisfied
    auto minRingDim  = StdLatticeParm::FindRingDim(HEStd_ternary, HEStd_128_classic, logQprime);
    uint32_t ringDim = N > minRingDim ? N : minRingDim;

    // find prime Q for NTT
    NativeInteger Q = LastPrime<NativeInteger>(logQprime, 2 * ringDim);

    // q = 2*ringDim by default for maximum plaintext space, if needed for arbitrary function evaluation, q = ringDim
    uint32_t q = arbFunc ? ringDim : 2 * ringDim;

    BasicInteger qKS = 1 << 27;

    uint32_t n      = (set == TOY) ? 32 : 1305;
    auto lweparams  = std::make_shared<LWECryptoParams>(n, ringDim, q, Q, qKS, STD_DEV, 32);
    auto rgswparams = std::make_shared<RingGSWCryptoParams>(ringDim, Q, q, baseG, 23, method, STD_DEV, UNIFORM_TERNARY,
                                                            ((logQ != 11) && timeOptimization));

    m_params           = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams);
    m_binfhescheme     = std::make_shared<BinFHEScheme>(method);
    m_timeOptimization = timeOptimization;

}

void BinFHEContext::GenerateBinFHEContext(BINFHE_PARAMSET set, BINFHE_METHOD method) {
    enum { PRIME = 0 };  // value for modKS if you want to use the intermediate prime for modulus for key switching
    // clang-format off
    static const std::unordered_map<BINFHE_PARAMSET, BinFHEContextParams> paramsMap{
    //  { BINFHE_PARAMSET      { bits, cycOrder, latParam, modq,   modKS,  stdDev, Bks,        Bg, Brk, autoKeys,         keyDist } },
        { T_1024_30,           {   16,     2048,      512, 1024,   16384, STD_DEV, 128,       256,  32,       10, UNIFORM_TERNARY } },
        { T_1024_30_Binary,    {   16,     2048,      512, 1024,   16384, STD_DEV, 128,       256,  32,       10,          BINARY } },
        { T_1024_36,           {   16,     2048,      512,  512,   16384, STD_DEV, 512,    262144,  32,       10, UNIFORM_TERNARY } },
        { T_1024_36_Binary,    {   16,     2048,      512,  512,   16384, STD_DEV, 512,    262144,  32,       10,          BINARY } },
        { T_2048_50,           {   22,     4096,     1024, 1024, 2097152, STD_DEV,  32,  33554432,  64,       10, UNIFORM_TERNARY } },
        { T_2048_50_Binary,    {   22,     4096,     1024, 1024, 2097152, STD_DEV,  32,  33554432,  64,       10,          BINARY } },
        { TOY,                 {   27,     1024,       64,  512,   PRIME, STD_DEV,  25,       512,  23,        9, UNIFORM_TERNARY } },
        { MEDIUM,              {   28,     2048,      422, 1024,   16384, STD_DEV, 128,      1024,  32,       10, UNIFORM_TERNARY } },
        { STD128_AP,           {   27,     2048,      503, 1024,   16384, STD_DEV,  32,       512,  32,       10, UNIFORM_TERNARY } },
        { STD128,              {   27,     2048,      503, 1024,   16384, STD_DEV,  32,       512,  32,       10, UNIFORM_TERNARY } },
        { STD128_Binary,       {   27,     2048,      503, 1024,   16384, STD_DEV,  32,       512,  32,       10,          BINARY } },
        { STD128_3,            {   27,     2048,      595, 1024,   65536, STD_DEV,  64,       128,  32,       10, UNIFORM_TERNARY } },
        { STD128_4,            {   27,     2048,      595, 2048,   65536, STD_DEV,  64,       128,  64,       10, UNIFORM_TERNARY } },
        { STD128Q,             {   25,     2048,      534, 1024,   16384, STD_DEV,  32,       128,  32,       10, UNIFORM_TERNARY } },
        { STD128Q_3,           {   50,     4096,      600, 2048,   32768, STD_DEV,  32,  33554432,  64,       10, UNIFORM_TERNARY } },
        { STD128Q_3_Binary,    {   50,     4096,      600, 2048,   32768, STD_DEV,  32,  33554432,  64,       10,          BINARY } },
        { STD128Q_4,           {   50,     4096,      641, 2048,   65536, STD_DEV,  64,  33554432,  64,       10, UNIFORM_TERNARY } },
        { STD192,              {   37,     4096,      790, 2048,   16384, STD_DEV,  32,    524288,  64,       10, UNIFORM_TERNARY } },
        { STD192_3,            {   37,     4096,      875, 4096,   65536, STD_DEV,  64,    524288,  64,       10, UNIFORM_TERNARY } },
        { STD192_4,            {   37,     4096,      875, 4096,   65536, STD_DEV,  64,      8192,  64,       10, UNIFORM_TERNARY } },
        { STD192Q,             {   35,     4096,      875, 1024,   32768, STD_DEV,  32,      4096,  32,       10, UNIFORM_TERNARY } },
        { STD192Q_3,           {   34,     4096,      922, 2048,   65536, STD_DEV,  16,      4096,  64,       10, UNIFORM_TERNARY } },
        { STD192Q_4,           {   34,     4096,      980, 2048,  131072, STD_DEV,  16,      4096,  64,       10, UNIFORM_TERNARY } },
        { STD256,              {   29,     4096,     1076, 2048,   32768, STD_DEV,  32,      1024,  64,       10, UNIFORM_TERNARY } },
        { STD256_3,            {   29,     4096,     1145, 2048,   65536, STD_DEV,  64,       256,  64,       10, UNIFORM_TERNARY } },
        { STD256_4,            {   29,     4096,     1145, 4096,   65536, STD_DEV,  64,       256,  64,       10, UNIFORM_TERNARY } },
        { STD256Q,             {   27,     4096,     1225, 1024,   65536, STD_DEV,  16,       128,  32,       10, UNIFORM_TERNARY } },
        { STD256Q_3,           {   27,     4096,     1400, 4096,   65536, STD_DEV,  21,        64,  64,       10, UNIFORM_TERNARY } },
        { STD256Q_4,           {   27,     4096,     1625, 4096, 2097152, STD_DEV,  16,        64,  64,       10, UNIFORM_TERNARY } },
        { STD128_LMKCDEY,      {   28,     2048,      447, 2048,   16384, STD_DEV,  32,      1024,  64,       10,        GAUSSIAN } },
        { STD128_3_LMKCDEY,    {   27,     2048,      556, 2048,   32768, STD_DEV,  32,       512,  64,       10, UNIFORM_TERNARY } },
        { STD128_4_LMKCDEY,    {   27,     2048,      595, 2048,   65536, STD_DEV,  64,       128,  64,       10, UNIFORM_TERNARY } },
        { STD128Q_LMKCDEY,     {   27,     2048,      483, 2048,   16384, STD_DEV,  32,       512,  64,       10,        GAUSSIAN } },
        { STD128Q_3_LMKCDEY,   {   25,     2048,      643, 2048,   65536, STD_DEV,  64,       128,  64,       10, UNIFORM_TERNARY } },
        { STD128Q_4_LMKCDEY,   {   50,     4096,      641, 4096,   65536, STD_DEV,  64,  33554432,  64,       10, UNIFORM_TERNARY } },
        { STD192_LMKCDEY,      {   39,     4096,      716, 2048,   32768, STD_DEV,  32,   1048576,  64,       10,        GAUSSIAN } },
        { STD192_3_LMKCDEY,    {   39,     4096,      771, 4096,   65536, STD_DEV,  64,   1048576,  64,       10,        GAUSSIAN } },
        { STD192_4_LMKCDEY,    {   37,     4096,      875, 4096,   65536, STD_DEV,  64,      8192,  64,       10, UNIFORM_TERNARY } },
        { STD192Q_LMKCDEY,     {   36,     4096,      776, 4096,   32768, STD_DEV,  32,    262144,  64,       10,        GAUSSIAN } },
        { STD192Q_3_LMKCDEY,   {   36,     4096,      834, 4096,   65536, STD_DEV,  64,      4096,  64,       10,        GAUSSIAN } },
        { STD192Q_4_LMKCDEY,   {   34,     4096,      949, 4096,   65536, STD_DEV,  64,      4096,  64,       10, UNIFORM_TERNARY } },
        { STD256_LMKCDEY,      {   30,     4096,      939, 2048,   32768, STD_DEV,  32,      1024,  64,       10,        GAUSSIAN } },
        { STD256_3_LMKCDEY,    {   29,     4096,     1076, 4096,   32768, STD_DEV,  32,       256,  64,       10, UNIFORM_TERNARY } },
        { STD256_4_LMKCDEY,    {   29,     4096,     1145, 4096,   65536, STD_DEV,  64,       256,  64,       10, UNIFORM_TERNARY } },
        { STD256Q_LMKCDEY,     {   28,     4096,     1019, 4096,   32768, STD_DEV,  32,      1024,  64,       10,        GAUSSIAN } },
        { STD256Q_3_LMKCDEY,   {   26,     4096,     1242, 4096,   65536, STD_DEV,  64,       128,  64,       10, UNIFORM_TERNARY } },
        { STD256Q_4_LMKCDEY,   {   26,     4096,     1320, 4096,  131072, STD_DEV,  64,        64,  64,       10, UNIFORM_TERNARY } },
        { LPF_STD128,          {   27,     2048,      556, 2048,   32768, STD_DEV,  32,       128,  64,       10, UNIFORM_TERNARY } },
        { LPF_STD128Q,         {   25,     2048,      645, 2048,   65536, STD_DEV,  64,       128,  64,       10, UNIFORM_TERNARY } },
        { LPF_STD128_LMKCDEY,  {   27,     2048,      556, 2048,   32768, STD_DEV,  32,       512,  64,       10, UNIFORM_TERNARY } },
        { LPF_STD128Q_LMKCDEY, {   25,     2048,      600, 2048,   32768, STD_DEV,  32,       128,  64,       10, UNIFORM_TERNARY } },
        { SIGNED_MOD_TEST,     {   28,     2048,      512, 1024,   PRIME, STD_DEV,  25,       128,  23,       10, UNIFORM_TERNARY } },
    };
    // clang-format on

    auto search = paramsMap.find(set);
    if (paramsMap.end() == search)
        OPENFHE_THROW("unknown parameter set");
    auto& params = search->second;

    NativeInteger Q(
        PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(params.numberBits, params.cyclOrder), params.cyclOrder));

    usint ringDim   = params.cyclOrder / 2;
    auto lweparams  = (PRIME == params.modKS) ?
                         std::make_shared<LWECryptoParams>(params.latticeParam, ringDim, params.mod, Q, Q,
                                                           params.stdDev, params.baseKS) :
                         std::make_shared<LWECryptoParams>(params.latticeParam, ringDim, params.mod, Q, params.modKS,
                                                           params.stdDev, params.baseKS);

    // 2: hybrid; 1: composite; 0: gadget decompose
    int compositeNTT = (set == T_1024_30 || set == T_1024_30_Binary)
                           ? 2
                           : ((set == T_1024_36 || set == T_1024_36_Binary || set == T_2048_50 || set ==
                               T_2048_50_Binary)
                                  ? 1
                                  : 0);
    auto rgswparams =
        std::make_shared<RingGSWCryptoParams>(ringDim, Q, params.mod, params.gadgetBase, params.baseRK, method,
                                              params.stdDev, params.keyDist, false, params.numAutoKeys, compositeNTT);
    m_params = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams);

    // TODO: add check that (method == LMKCDEY) for LMKCDEY-optimized BINFHE_PARAMSETs
    m_binfhescheme = std::make_shared<BinFHEScheme>(method);
}

void BinFHEContext::GenerateBinFHEContext(const BinFHEContextParams& params, BINFHE_METHOD method) {
    enum { PRIME = 0 };  // value for modKS if you want to use the intermediate prime for modulus for key switching

    auto Q         = LastPrime<NativeInteger>(params.numberBits, params.cyclOrder);
    auto ringDim   = params.cyclOrder >> 1;
    auto lweparams = std::make_shared<LWECryptoParams>(params.latticeParam, ringDim, params.mod, Q,
                                                       (params.modKS == PRIME ? Q : params.modKS), params.stdDev,
                                                       params.baseKS, params.keyDist);
    auto rgswparams =
        std::make_shared<RingGSWCryptoParams>(ringDim, Q, params.mod, params.gadgetBase, params.baseRK, method,
                                              params.stdDev, params.keyDist, false, params.numAutoKeys);
    m_params       = std::make_shared<BinFHECryptoParams>(lweparams, rgswparams);
    m_binfhescheme = std::make_shared<BinFHEScheme>(method);
}

LWEPrivateKey BinFHEContext::KeyGen() const {
    auto&& LWEParams = m_params->GetLWEParams();
    if (LWEParams->GetKeyDist() == GAUSSIAN)
        return m_LWEscheme->KeyGenGaussian(LWEParams->Getn(), LWEParams->GetqKS());
    if (LWEParams->GetKeyDist() == BINARY)
        return m_LWEscheme->KeyGenBinary(LWEParams->Getn(), LWEParams->GetqKS());
    return m_LWEscheme->KeyGen(LWEParams->Getn(), LWEParams->GetqKS());
}

LWEPrivateKey BinFHEContext::KeyGenN() const {
    auto&& LWEParams = m_params->GetLWEParams();
    if (LWEParams->GetKeyDist() == GAUSSIAN)
        return m_LWEscheme->KeyGenGaussian(LWEParams->GetN(), LWEParams->GetQ());
    if (LWEParams->GetKeyDist() == BINARY)
        return m_LWEscheme->KeyGenBinary(LWEParams->GetN(), LWEParams->GetQ());
    return m_LWEscheme->KeyGen(LWEParams->GetN(), LWEParams->GetQ());
}

LWEKeyPair BinFHEContext::KeyGenPair() const {
    return m_LWEscheme->KeyGenPair(m_params->GetLWEParams());
}

LWEPublicKey BinFHEContext::PubKeyGen(ConstLWEPrivateKey& sk) const {
    return m_LWEscheme->PubKeyGen(m_params->GetLWEParams(), sk);
}

LWECiphertext BinFHEContext::Encrypt(ConstLWEPrivateKey& sk, LWEPlaintext m, BINFHE_OUTPUT output,
                                     LWEPlaintextModulus p, const NativeInteger& mod) const {
    auto&& LWEParams = m_params->GetLWEParams();

    auto ct = m_LWEscheme->Encrypt(LWEParams, sk, m, p, (mod == 0 ? LWEParams->Getq() : mod));

    // BINFHE_OUTPUT is kept as it is for backward compatibility but
    // this logic is obsolete now and commented out
    // if ((output != FRESH) && (p == 4)) {
    //    ct = m_binfhescheme->Bootstrap(m_params, m_BTKey, ct);
    //}
    return ct;
}

LWECiphertext BinFHEContext::Encrypt(ConstLWEPublicKey& pk, LWEPlaintext m, BINFHE_OUTPUT output, LWEPlaintextModulus p,
                                     const NativeInteger& mod) const {
    auto&& LWEParams = m_params->GetLWEParams();

    auto ct = m_LWEscheme->EncryptN(LWEParams, pk, m, p, (mod == 0 ? LWEParams->GetQ() : mod));

    // Switch from ct of modulus Q and dimension N to smaller q and n
    // This is done by default while calling Encrypt but the output could
    // be set to LARGE_DIM to skip this switching
    if (output == SMALL_DIM)
        return SwitchCTtoqn(m_BTKey.KSkey, ct);
    return ct;
}

LWECiphertext BinFHEContext::SwitchCTtoqn(ConstLWESwitchingKey& ksk, ConstLWECiphertext& ct) const {
    auto&& LWEParams = m_params->GetLWEParams();
    if ((ct->GetLength() != LWEParams->GetN()) && (ct->GetModulus() != LWEParams->GetQ()))
        OPENFHE_THROW("ciphertext dimension and modulus are not large N and Q");
    return m_LWEscheme->SwitchCTtoqn(LWEParams, ksk, ct);
}

void BinFHEContext::Decrypt(ConstLWEPrivateKey& sk, ConstLWECiphertext& ct, LWEPlaintext* result,
                            LWEPlaintextModulus p) const {
    m_LWEscheme->Decrypt(m_params->GetLWEParams(), sk, ct, result, p);
}

LWESwitchingKey BinFHEContext::KeySwitchGen(ConstLWEPrivateKey& sk, ConstLWEPrivateKey& skN) const {
    return m_LWEscheme->KeySwitchGen(m_params->GetLWEParams(), sk, skN);
}

void BinFHEContext::BTKeyGen(ConstLWEPrivateKey& sk, KEYGEN_MODE keygenMode) {
    auto&& RGSWParams = m_params->GetRingGSWParams();

    auto temp = RGSWParams->GetBaseG();
    auto skN = m_LWEscheme->KeyGen(RGSWParams->GetN(), RGSWParams->GetQ());

    if (RGSWParams->GetGPowerMap().size() > 0) {
        auto gpowermap    = RGSWParams->GetGPowerMap();
        bool init         = false;
        uint32_t first_bg = 0;
        for (std::map<uint32_t, std::vector<NativeInteger>>::iterator it = gpowermap.begin(); it != gpowermap.end();
             ++it) {
            RGSWParams->Change_BaseG(it->first);
            if (!init) {  // reuse generated PK keys
                m_BTKey_map[it->first] = m_binfhescheme->KeyGen(m_params, sk, skN, nullptr);
                init                   = true;
                first_bg               = it->first;
            }
            else
                m_BTKey_map[it->first] = m_binfhescheme->KeyGen(m_params, sk, skN, &m_BTKey_map[first_bg]);
        }
        RGSWParams->Change_BaseG(temp);
    }

    if (m_BTKey_map.size() != 0) {
        m_BTKey = m_BTKey_map[temp];
    }
    else {
        m_BTKey           = m_binfhescheme->KeyGen(m_params, sk, skN, nullptr);
        m_BTKey_map[temp] = m_BTKey;
    }
}

LWECiphertext BinFHEContext::EvalBinGate(const BINGATE gate, ConstLWECiphertext& ct1, ConstLWECiphertext& ct2) const {
    return m_binfhescheme->EvalBinGate(m_params, gate, m_BTKey, ct1, ct2);
}

LWECiphertext BinFHEContext::EvalBinGate(const BINGATE gate, const std::vector<LWECiphertext>& ctvector) const {
    return m_binfhescheme->EvalBinGate(m_params, gate, m_BTKey, ctvector);
}

LWECiphertext BinFHEContext::Bootstrap(ConstLWECiphertext& ct) const {
    return m_binfhescheme->Bootstrap(m_params, m_BTKey, ct);
}

LWECiphertext BinFHEContext::EvalNOT(ConstLWECiphertext& ct) const {
    return m_binfhescheme->EvalNOT(m_params, ct);
}

LWECiphertext BinFHEContext::EvalConstant(bool value) const {
    return m_LWEscheme->NoiselessEmbedding(m_params->GetLWEParams(), value);
}

LWECiphertext BinFHEContext::EvalFunc(ConstLWECiphertext& ct, const std::vector<NativeInteger>& LUT) const {
    return m_binfhescheme->EvalFunc(m_params, m_BTKey, ct, LUT, GetBeta());
}LWECiphertext BinFHEContext::EvalFuncTest(ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT, double deltain,
                                          double deltaout, NativeInteger qout, double (*f)(double m)) const {
    NativeInteger beta = GetBetaPrecise();
    return m_binfhescheme->EvalFuncTest(m_params, m_BTKey, ct, LUT, beta, deltain, deltaout, qout, f);
}

LWECiphertext BinFHEContext::EvalFuncCompress(ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                              double deltain, double deltaout, NativeInteger qout,
                                              double (*f)(double m)) const {
    NativeInteger beta = GetBetaPrecise();
    return m_binfhescheme->EvalFuncCompress(m_params, m_BTKey, ct, LUT, beta, deltain, deltaout, qout, f);
}

LWECiphertext BinFHEContext::EvalFuncCancelSign(ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                                double deltain, double deltaout, NativeInteger qout,
                                                double (*f)(double m)) const {
    NativeInteger beta = GetBetaPrecise();
    return m_binfhescheme->EvalFuncCancelSign(m_params, m_BTKey, ct, LUT, beta, deltain, deltaout, qout, f);
}

LWECiphertext BinFHEContext::EvalFuncSelect(ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                            double deltain, double deltaout, NativeInteger qout, double (*f)(double m),
                                            uint32_t baseG_small) const {
    NativeInteger beta = GetBetaPrecise();
    auto it_small      = m_BTKey_map.find(baseG_small);
    if (it_small == m_BTKey_map.end())
        OPENFHE_THROW(openfhe_error, "EK not found");
    return m_binfhescheme->EvalFuncSelect(m_params, m_BTKey, ct, LUT, beta, deltain, deltaout, qout, f,
                                          it_small->second, baseG_small);
}

LWECiphertext BinFHEContext::EvalFuncSelectAlt(ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                               double deltain, double deltaout, NativeInteger qout,
                                               double (*f)(double m), uint32_t baseG_small) const {
    NativeInteger beta = GetBetaPrecise();
    auto it_small      = m_BTKey_map.find(baseG_small);
    if (it_small == m_BTKey_map.end())
        OPENFHE_THROW(openfhe_error, "EK not found");
    return m_binfhescheme->EvalFuncSelectAlt(m_params, m_BTKey, ct, LUT, beta, deltain, deltaout, qout, f,
                                             it_small->second, baseG_small);
}

LWECiphertext BinFHEContext::EvalFuncPreSelect(ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                               double deltain, double deltaout, NativeInteger qout,
                                               double (*f)(double m), NativeInteger p_mid) const {
    NativeInteger beta = GetBetaPrecise();
    return m_binfhescheme->EvalFuncPreSelect(m_params, m_BTKey, ct, LUT, beta, deltain, deltaout, qout, f, p_mid);
}

LWECiphertext BinFHEContext::EvalFuncKS21(ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT, double deltain,
                                          double deltaout, NativeInteger qout, double (*f)(double m)) const {
    NativeInteger beta = GetBetaPrecise();
    return m_binfhescheme->EvalFuncKS21(m_params, m_BTKey, ct, LUT, beta, deltain, deltaout, qout, f);
}

LWECiphertext BinFHEContext::EvalFuncComp(ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT, double deltain,
                                          double deltaout, NativeInteger qout, double (*f)(double m),
                                          uint32_t f_property, double shift, uint32_t baseG_small) const {
    NativeInteger beta = GetBetaPrecise();
    auto it_small      = m_BTKey_map.find(baseG_small);
    if (it_small == m_BTKey_map.end())
        OPENFHE_THROW(openfhe_error, "EK not found");
    return m_binfhescheme->EvalFuncComp(m_params, m_BTKey, ct, LUT, beta, deltain, deltaout, qout, f, f_property, shift,
                                        it_small->second, baseG_small);
}

LWECiphertext BinFHEContext::EvalFuncBFV(ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT, double deltain,
                                         double deltaout, NativeInteger qout, double (*f)(double m)) const {
    NativeInteger beta = GetBetaPrecise();
    return m_binfhescheme->EvalFuncBFV(m_params, m_BTKey, ct, LUT, beta, deltain, deltaout, qout, f);
}

LWECiphertext BinFHEContext::EvalFuncWoPPBS1(ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                             double deltain, double deltaout, NativeInteger qout,
                                             double (*f)(double m)) const {
    NativeInteger beta = GetBetaPrecise();
    return m_binfhescheme->EvalFuncWoPPBS1(m_params, m_BTKey, ct, LUT, beta, deltain, deltaout, qout, f);
}

LWECiphertext BinFHEContext::EvalFuncWoPPBS2(ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                             double deltain, double deltaout, NativeInteger qout,
                                             double (*f)(double m)) const {
    NativeInteger beta = GetBetaPrecise();
    return m_binfhescheme->EvalFuncWoPPBS2(m_params, m_BTKey, ct, LUT, beta, deltain, deltaout, qout, f);
}

LWECiphertext BinFHEContext::EvalReLU(ConstLWECiphertext ct, ConstLWECiphertext ct_msd, size_t baseG_sgn,
                                      size_t baseG_sel) const {
    auto it_sgn = m_BTKey_map.find(baseG_sgn), it_sel = m_BTKey_map.find(baseG_sel);
    if (it_sgn == m_BTKey_map.end() || it_sel == m_BTKey_map.end())
        OPENFHE_THROW(openfhe_error, "EK not found");
    auto beta = GetBeta().ConvertToInt();
    return m_binfhescheme->EvalReLU(m_params, it_sgn->second, baseG_sgn, it_sel->second, baseG_sel, ct, ct_msd, beta);
}


LWECiphertext BinFHEContext::EvalFloor(ConstLWECiphertext& ct, uint32_t roundbits) const {
    //    auto q = m_params->GetLWEParams()->Getq().ConvertToInt();
    //    if (roundbits != 0) {
    //        NativeInteger newp = this->GetMaxPlaintextSpace();
    //        SetQ(q / newp * (1 << roundbits));
    //    }
    //    SetQ(q);
    //    return res;
    return m_binfhescheme->EvalFloor(m_params, m_BTKey, ct, GetBeta(), roundbits);
}

LWECiphertext BinFHEContext::EvalSign(ConstLWECiphertext& ct, bool schemeSwitch) {
    return m_binfhescheme->EvalSign(std::make_shared<BinFHECryptoParams>(*m_params), m_BTKey_map, ct, GetBeta(),
                                    schemeSwitch);
}
std::vector<LWECiphertext> BinFHEContext::EvalDecomp(ConstLWECiphertext ct, bool CKKS) {
    NativeInteger beta = GetBeta();
    return m_binfhescheme->EvalDecomp(m_params, m_BTKey_map, ct, beta, CKKS);
}

LWECiphertext BinFHEContext::EvalFloorAlt(ConstLWECiphertext ct, uint32_t roundbits) const {
    //    auto q = m_params->GetLWEParams()->Getq().ConvertToInt();
    //    if (roundbits != 0) {
    //        NativeInteger newp = this->GetMaxPlaintextSpace();
    //        SetQ(q / newp * (1 << roundbits));
    //    }
    //    SetQ(q);
    //    return res;
    return m_binfhescheme->EvalFloorAlt(m_params, m_BTKey, ct, GetBeta(), roundbits);
}

LWECiphertext BinFHEContext::EvalSignAlt(ConstLWECiphertext ct, bool fast, bool CKKS) {
    auto params        = std::make_shared<BinFHECryptoParams>(*m_params);
    NativeInteger beta = GetBeta();
    return m_binfhescheme->EvalSignAlt(params, m_BTKey_map, ct, beta, fast, CKKS);
}

std::vector<LWECiphertext> BinFHEContext::EvalDecompAlt(ConstLWECiphertext ct, bool CKKS) {
    NativeInteger beta = GetBeta();
    return m_binfhescheme->EvalDecompAlt(m_params, m_BTKey_map, ct, beta, CKKS);
}

LWECiphertext BinFHEContext::EvalFloorNew(ConstLWECiphertext ct, uint32_t roundbits) const {
    //    auto q = m_params->GetLWEParams()->Getq().ConvertToInt();
    //    if (roundbits != 0) {
    //        NativeInteger newp = this->GetMaxPlaintextSpace();
    //        SetQ(q / newp * (1 << roundbits));
    //    }
    //    SetQ(q);
    //    return res;
    return m_binfhescheme->EvalFloorNew(m_params, m_BTKey, ct, GetBeta(), roundbits);
}

LWECiphertext BinFHEContext::EvalSignNew(ConstLWECiphertext ct) {
    auto params        = std::make_shared<BinFHECryptoParams>(*m_params);
    NativeInteger beta = GetBeta();
    return m_binfhescheme->EvalSignNew(params, m_BTKey_map, ct, beta);
}

std::vector<LWECiphertext> BinFHEContext::EvalDecompNew(ConstLWECiphertext ct, bool CKKS) {
    NativeInteger beta = GetBeta();
    return m_binfhescheme->EvalDecompNew(m_params, m_BTKey_map, ct, beta, CKKS);
}

LWECiphertext BinFHEContext::EvalFloorCompress(ConstLWECiphertext ct, uint32_t roundbits) const {
    return m_binfhescheme->EvalFloorCompress(m_params, m_BTKey, ct, GetBeta(), roundbits);
}

LWECiphertext BinFHEContext::EvalSignCompress(ConstLWECiphertext ct) {
    return m_binfhescheme->EvalSignCompress(m_params, m_BTKey_map, ct, GetBeta(), GetBetaPrecise());
}

std::vector<LWECiphertext> BinFHEContext::EvalDecompCompress(ConstLWECiphertext ct, bool CKKS) {
    return m_binfhescheme->EvalDecompCompress(m_params, m_BTKey_map, ct, GetBeta(), GetBetaPrecise(), CKKS);
}
std::vector<NativeInteger> BinFHEContext::GenerateLUTviaFunction(NativeInteger (*f)(NativeInteger m, NativeInteger p),
                                                                 NativeInteger p) {
    if (!IsPowerOfTwo(p.ConvertToInt<BasicInteger>()))
        OPENFHE_THROW("plaintext p not power of two");

    NativeInteger q{GetParams()->GetLWEParams()->Getq()};
    NativeInteger x{0};

    std::vector<NativeInteger> vec(q.ConvertToInt(), q / p);
    for (size_t i = 0; i < vec.size(); ++i, x += p) {
        vec[i] *= f(x / q, p);  // x/q = (i*p)/q = i/(q/p)
        if (vec[i] >= q)        // (f(x/q, p) >= p) --> (f(x/q, p)*(q/p) >= q)
            OPENFHE_THROW("input function should output in Z_{p_output}");
    }
    return vec;
}

}  // namespace lbcrypto

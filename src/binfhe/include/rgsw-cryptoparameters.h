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

#ifndef _RGSW_CRYPTOPARAMETERS_H_
#define _RGSW_CRYPTOPARAMETERS_H_

#include "lattice/lat-hal.h"
#include "math/discretegaussiangenerator.h"
#include "math/nbtheory.h"
#include "utils/serializable.h"
#include "utils/utilities.h"

#include "binfhe-constants.h"

#include "lwe-ciphertext.h"
#include "lwe-keyswitchkey.h"
#include "lwe-cryptoparameters.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <map>

namespace lbcrypto {

/**
 * @brief Class that stores all parameters for the RingGSW scheme used in
 * bootstrapping
 */
class RingGSWCryptoParams : public Serializable {
public:
    RingGSWCryptoParams()                      = default;
    constexpr static uint32_t PKKEY_FULL       = 1 << 0;
    constexpr static uint32_t PKKEY_HALF       = 1 << 1;
    constexpr static uint32_t PKKEY_CONST      = 1 << 2;
    constexpr static uint32_t PKKEY_HALF_TRANS = 1 << 3;
    /**
   * Main constructor for RingGSWCryptoParams
   *
   * @param N ring dimension for RingGSW/RLWE used in bootstrapping
   * @param Q modulus for RingGSW/RLWE used in bootstrapping
   * @param q ciphertext modulus for additive LWE
   * @param baseG the gadget base used in the bootstrapping
   * @param baseR the base for the refreshing key
   * @param method bootstrapping method (DM or CGGI or LMKCDEY)
   * @param std standar deviation
   * @param keyDist secret key distribution
   * @param signEval flag if sign evaluation is needed
    * @param numAutoKeys number of automorphism keys in LMKCDEY bootstrapping
    * @param compositeNTT flag if composite NTT parameter set is used
   */

    explicit RingGSWCryptoParams(uint32_t N, NativeInteger Q, NativeInteger q, uint32_t baseG, uint32_t baseR,
                                 BINFHE_METHOD method, double std, bool signEval = false, uint32_t basePK = 1 << 5,
                                 const NativeInteger& qfrom = uint64_t(1) << 35, uint32_t baseG0 = 1 << 6,
                                 uint32_t baseGMV = 1 << 6, const std::vector<uint32_t>& baseGs = {},
                                 uint32_t pkkey_flags = 0, NativeInteger P = 0, uint32_t baseRL = 0,    uint32_t numAutoKeys = 10, int compositeNTT = 0)
        : m_N(N),
          m_Q(Q),
          m_q(q),
          m_baseG(baseG),
          m_baseR(baseR),
          m_method(method),
          m_basePK(basePK),
          m_qfrom(qfrom),
          m_baseG0(baseG0),
          m_baseGMV(baseGMV),
          m_pkkey_flags(pkkey_flags),
          m_P(P),
          m_baseRL(baseRL) {
        if (!IsPowerOfTwo(baseG))
            OPENFHE_THROW("Gadget base should be a power of two.");
        if ((method == LMKCDEY) && (numAutoKeys == 0))
            OPENFHE_THROW("numAutoKeys should be greater than 0.");

        // composite NTT
        m_compositeNTT = compositeNTT;
        if (compositeNTT) {
            if (m_Q == 61441 && q == 1024)
                m_P = 12289;
            else if (m_Q == 61441 && q == 512)
                m_P = 1038337;
            else if (m_Q == 4169729)
                m_P = 268369921;
            else
                throw std::invalid_argument("Unexpected modulus Q for composite NTT");
            m_PQ                  = m_P * m_Q;
            m_compositePolyParams = std::make_shared<ILNativeParams>(2 * N, m_PQ);
            auto logPQ{log(m_PQ.ConvertToDouble())};
            m_digitsG = static_cast<uint32_t>(std::ceil(logPQ / log(static_cast<double>(m_baseG))));
        }
        else {
            auto logQ{log(m_Q.ConvertToDouble())};
            m_digitsG = static_cast<uint32_t>(std::ceil(logQ / log(static_cast<double>(m_baseG))));
        }

        m_dgg.SetStd(std);
        NativeInteger rootOfUnity = RootOfUnity<NativeInteger>(2 * N, Q);

        // Precomputes the table with twiddle factors to support fast NTT
        ChineseRemainderTransformFTT<NativeVector>().PreCompute(rootOfUnity, 2 * N, Q);

        // Precomputes a polynomial for MSB extraction
        m_polyParams = std::make_shared<ILNativeParams>(2 * N, Q, rootOfUnity);

        if(m_P > 0){
            NativeInteger rootOfUnity_P = RootOfUnity<NativeInteger>(2 * N, m_P);
            ChineseRemainderTransformFTT<NativeVector>().PreCompute(rootOfUnity_P, 2 * N, m_P);
            m_polyParams_bfv = std::make_shared<ILNativeParams>(2 * N, m_P, rootOfUnity_P);
        }

        m_digitsG    = (uint32_t)std::ceil(log(Q.ConvertToDouble()) / log(static_cast<double>(m_baseG)));
        if (m_method == AP) {
            uint32_t digitCountR =
                (uint32_t)std::ceil(log(static_cast<double>(q.ConvertToInt())) / log(static_cast<double>(m_baseR)));
            // Populate digits
            NativeInteger value = 1;
            for (size_t i = 0; i < digitCountR; ++i) {
                m_digitsR.push_back(value);
                value *= m_baseR;
            }
        }

        // Computes baseG^i
        if (signEval) {
            uint32_t baseGlist[3] = {1 << 14, 1 << 18, 1 << 27};
            for (size_t j = 0; j < 3; ++j) {
                NativeInteger vTemp = NativeInteger(1);
                auto tempdigits =
                    (uint32_t)std::ceil(log(Q.ConvertToDouble()) / log(static_cast<double>(baseGlist[j])));
                std::vector<NativeInteger> tempvec(tempdigits);
                for (size_t i = 0; i < tempdigits; ++i) {
                    tempvec[i] = vTemp;
                    vTemp      = vTemp.ModMul(NativeInteger(baseGlist[j]), Q);
                }
                m_Gpower_map[baseGlist[j]] = tempvec;
                if (m_baseG == baseGlist[j])
                    m_Gpower = tempvec;
            }
        }
        else {
            NativeInteger vTemp = NativeInteger(1);
            for (size_t i = 0; i < m_digitsG; ++i) {
                m_Gpower.push_back(vTemp);
                vTemp = vTemp.ModMul(NativeInteger(m_baseG), Q);
            }
        }

        if (baseGs.size() > 0) {
            for (size_t j = 0; j < baseGs.size(); ++j) {
                NativeInteger vTemp = NativeInteger(1);
                auto tempdigits = (uint32_t)std::ceil(log(Q.ConvertToDouble()) / log(static_cast<double>(baseGs[j])));
                std::vector<NativeInteger> tempvec(tempdigits);
                for (size_t i = 0; i < tempdigits; ++i) {
                    tempvec[i] = vTemp;
                    vTemp      = vTemp.ModMul(NativeInteger(baseGs[j]), Q);
                }
                m_Gpower_map[baseGs[j]] = tempvec;
                if (m_baseG == baseGs[j])
                    m_Gpower = tempvec;
            }
        }

        // Sets the gate constants for supported binary operations
        m_gateConst = {
            NativeInteger(5) * (q >> 3),  // OR
            NativeInteger(7) * (q >> 3),  // AND
            NativeInteger(1) * (q >> 3),  // NOR
            NativeInteger(3) * (q >> 3),  // NAND
            NativeInteger(5) * (q >> 3),  // XOR_FAST
            NativeInteger(1) * (q >> 3)   // XNOR_FAST
        };

        // Computes polynomials X^m - 1 that are needed in the accumulator for the
        // CGGI bootstrapping
        if (m_method == GINX) {
            // loop for positive values of m
            for (size_t i = 0; i < N; ++i) {
                NativePoly aPoly = NativePoly(m_polyParams, Format::COEFFICIENT, true);
                aPoly[i].ModAddEq(NativeInteger(1), Q);  // X^m
                aPoly[0].ModSubEq(NativeInteger(1), Q);  // -1
                aPoly.SetFormat(Format::EVALUATION);
                m_monomials.push_back(aPoly);
            }

            // loop for negative values of m
            for (size_t i = 0; i < N; ++i) {
                NativePoly aPoly = NativePoly(m_polyParams, Format::COEFFICIENT, true);
                aPoly[i].ModSubEq(NativeInteger(1), Q);  // -X^m
                aPoly[0].ModSubEq(NativeInteger(1), Q);  // -1
                aPoly.SetFormat(Format::EVALUATION);
                m_monomials.push_back(aPoly);
            }
        }
        PreCompute(signEval);
    }

    /**
   * Performs precomputations based on the supplied parameters
   */
    void PreCompute(bool signEval = false);

    uint32_t GetN() const {
        return m_N;
    }

    const NativeInteger& GetQ() const {
        return m_Q;
    }

    const NativeInteger& GetP() const {
        return m_P;
    }

    const NativeInteger& GetPQ() const {
        return m_PQ;
    }

    const NativeInteger& Getq() const {
        return m_q;
    }

    uint32_t GetBaseG() const {
        return m_baseG;
    }

    uint32_t GetDigitsG() const {
        return m_digitsG;
    }

    uint32_t GetBaseR() const {
        return m_baseR;
    }
    uint32_t GetBasePK() const {
        return m_basePK;
    }

    const NativeInteger& GetQfrom() const {
        return m_qfrom;
    }

    uint32_t GetBaseG0() const {
        return m_baseG0;
    }

    uint32_t GetBaseGMV() const {
        return m_baseGMV;
    }

    uint32_t GetBaseRL() const {
        return m_baseRL;
    }

    uint32_t GetPKKeyFlags() const {
        return m_pkkey_flags;
    }

    uint32_t GetNumAutoKeys() const {
        return m_numAutoKeys;
    }

    const std::vector<NativeInteger>& GetDigitsR() const {
        return m_digitsR;
    }

    const std::shared_ptr<ILNativeParams> GetPolyParams() const {
        return m_polyParams;
    }
    const std::shared_ptr<ILNativeParams> GetPolyParamsP() const {
        return m_polyParams_bfv;
    }
    const std::shared_ptr<ILNativeParams> GetCompositePolyParams() const {
        return m_compositePolyParams;
    }

    const std::vector<NativeInteger>& GetGPower() const {
        return m_Gpower;
    }

    const std::vector<int32_t>& GetLogGen() const {
        return m_logGen;
    }

    const std::map<uint32_t, std::vector<NativeInteger>>& GetGPowerMap() const {
        return m_Gpower_map;
    }

    const DiscreteGaussianGeneratorImpl<NativeVector>& GetDgg() const {
        return m_dgg;
    }

    const std::vector<NativeInteger>& GetGateConst() const {
        return m_gateConst;
    }

    const NativePoly& GetMonomial(uint32_t i) const {
        return m_monomials[i];
    }

    BINFHE_METHOD GetMethod() const {
        return m_method;
    }

    SecretKeyDist GetKeyDist() const {
        return m_keyDist;
    }

    int IsCompositeNTT() const {
        return m_compositeNTT;
    }

    bool operator==(const RingGSWCryptoParams& other) const {
        return m_N == other.m_N && m_Q == other.m_Q && m_baseR == other.m_baseR && m_baseG == other.m_baseG &&
               m_basePK == other.m_basePK && m_qfrom == other.m_qfrom && m_baseG0 == other.m_baseG0 &&
               m_baseGMV == other.m_baseGMV && m_pkkey_flags == other.m_pkkey_flags && m_P == other.m_P && m_baseRL == other.m_baseRL;

    }

    bool operator!=(const RingGSWCryptoParams& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("bN", m_N));
        ar(::cereal::make_nvp("bQ", m_Q));
        ar(::cereal::make_nvp("bq", m_q));
        ar(::cereal::make_nvp("bR", m_baseR));
        ar(::cereal::make_nvp("bG", m_baseG));
        ar(::cereal::make_nvp("bmethod", m_method));
        ar(::cereal::make_nvp("bs", m_dgg.GetStd()));
        ar(::cereal::make_nvp("bdigitsG", m_digitsG));
        ar(::cereal::make_nvp("bparams", m_polyParams));
        ar(::cereal::make_nvp("numAutoKeys", m_numAutoKeys));
        ar(::cereal::make_nvp("bPK", m_basePK));
        ar(::cereal::make_nvp("qfrom", m_qfrom));
        ar(::cereal::make_nvp("bG0", m_baseG0));
        ar(::cereal::make_nvp("bGMV", m_baseGMV));
        ar(::cereal::make_nvp("bflag", m_pkkey_flags));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("bN", m_N));
        ar(::cereal::make_nvp("bQ", m_Q));
        ar(::cereal::make_nvp("bq", m_q));
        ar(::cereal::make_nvp("bR", m_baseR));
        ar(::cereal::make_nvp("bG", m_baseG));
        ar(::cereal::make_nvp("bmethod", m_method));
        double sigma = 0;
        ar(::cereal::make_nvp("bs", sigma));
        m_dgg.SetStd(sigma);
        ar(::cereal::make_nvp("bdigitsG", m_digitsG));
        ar(::cereal::make_nvp("bparams", m_polyParams));
        ar(::cereal::make_nvp("numAutoKeys", m_numAutoKeys));
        ar(::cereal::make_nvp("bPK", m_basePK));
        ar(::cereal::make_nvp("qfrom", m_qfrom));
        ar(::cereal::make_nvp("bG0", m_baseG0));
        ar(::cereal::make_nvp("bGMV", m_baseGMV));
        ar(::cereal::make_nvp("bflag", m_pkkey_flags));
        PreCompute();
    }

    std::string SerializedObjectName() const override {
        return "RingGSWCryptoParams";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

    void Change_BaseG(uint32_t BaseG) {
        if (m_baseG != BaseG) {
            m_baseG  = BaseG;
            m_Gpower = m_Gpower_map[m_baseG];
            m_digitsG =
                static_cast<uint32_t>(std::ceil(log(m_Q.ConvertToDouble()) / log(static_cast<double>(m_baseG))));
        }
    }

private:
    // modulus for the RingGSW/RingLWE scheme
    NativeInteger m_Q{};

    // another modulus for the RingGSW/RingLWE scheme
    NativeInteger m_P{};

    // composite modulus for the RingGSW/RingLWE scheme
    NativeInteger m_PQ{};

    // modulus for the RingLWE scheme
    NativeInteger m_q{};

    // ring dimension for RingGSW/RingLWE scheme
    uint32_t m_N{};

    // gadget base used in bootstrapping
    uint32_t m_baseG{};

    // base used for the refreshing key (used only for DM bootstrapping)
    uint32_t m_baseR{};

    // number of digits in decomposing integers mod Q
    uint32_t m_digitsG{};

    // powers of m_baseR (used only for DM bootstrapping)
    std::vector<NativeInteger> m_digitsR;

    // A vector of powers of baseG
    std::vector<NativeInteger> m_Gpower;

    // A vector of log by generator g (=5) (only for LMKCDEY)
    // Not exactly log, but a mapping similar to logarithm for efficiency
    // m_logGen[5^i (mod M)] = i (i > 0)
    // m_logGen[-5^i (mod M)] = -i ()
    // m_logGen[1] = 0
    // m_logGen[-1 (mod M)] = M (special case for efficiency)
    std::vector<int32_t> m_logGen;

    // Error distribution generator
    DiscreteGaussianGeneratorImpl<NativeVector> m_dgg;

    // A map of vectors of powers of baseG for sign evaluation
    std::map<uint32_t, std::vector<NativeInteger>> m_Gpower_map;

    // Parameters for polynomials in RingGSW/RingLWE
    std::shared_ptr<ILNativeParams> m_polyParams;

    // Parameters for composite polynomials in RingGSW/RingLWE
    std::shared_ptr<ILNativeParams> m_compositePolyParams;

    // Constants used in evaluating binary gates
    std::vector<NativeInteger> m_gateConst;

    // Precomputed polynomials in Format::EVALUATION representation for X^m - 1
    // (used only for CGGI bootstrapping)
    std::vector<NativePoly> m_monomials;

    // Bootstrapping method (DM or CGGI or LMKCDEY)
    BINFHE_METHOD m_method{BINFHE_METHOD::INVALID_METHOD};

    // Base used in LWE to RLWE packing
    uint32_t m_basePK;

    // input modulus for LWE to RLWE packing, output modulus is always Q
    NativeInteger m_qfrom;

    // Base used in polynomial x RLWE' multiplication in FDFB-PreSelect
    uint32_t m_baseG0;

    // Base used in low-noise multi-value bootstrap
    uint32_t m_baseGMV;

    // flags indicating which packing keys should be generated
    uint32_t m_pkkey_flags;


    // parameters for polymonials modulo P
    std::shared_ptr<ILNativeParams> m_polyParams_bfv;

    // base used in BFV relinearization
    uint32_t m_baseRL;
    // Secret key distribution: GAUSSIAN, UNIFORM_TERNARY, etc.
    SecretKeyDist m_keyDist{SecretKeyDist::UNIFORM_TERNARY};

    // number of automorphism keys (used only for LMKCDEY bootstrapping)
    uint32_t m_numAutoKeys{};

    // flag if composite NTT parameter set is used
    int m_compositeNTT{};
};

}  // namespace lbcrypto

#endif  // _RGSW_CRYPTOPARAMETERS_H_

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

#ifndef BINFHE_FHEW_H
#define BINFHE_FHEW_H

#include "binfhe-base-params.h"
#include "lwe-pke.h"
#include "rlwe-ciphertext.h"
#include "rgsw-acckey.h"
#include "rgsw-acc.h"
#include "rgsw-acc-dm.h"
#include "rgsw-acc-cggi.h"
#include "rgsw-acc-lmkcdey.h"

#include <map>
#include <memory>
#include <vector>

namespace lbcrypto {

// The struct for storing bootstrapping keys
typedef struct {
    // refreshing key
    RingGSWACCKey BSkey;
    // switching key
    LWESwitchingKey KSkey;
    // public key
    LWEPublicKey Pkey;
    // packing key with nOnes = N
    RLWESwitchingKey PKkey_full;
    // packing key with nOnes = N/2
    RLWESwitchingKey PKkey_half;
    // packing key with nOnes = N/8. NOTE: not needed for now
    // RLWESwitchingKey PKkey_batch;
    // packing key with one constant term set to 1
    RLWESwitchingKey PKkey_const;
    // packing key from sk to skN with nOnes = N/2. used for ReLU
    RLWESwitchingKey PKKey_half_trans;
    // BFV relinearization key
    std::shared_ptr<std::vector<RLWECiphertext>> BFV_relin_keys;
    // FIXME: remove; debug key
    LWEPrivateKey skey;
    LWEPrivateKey skeyN;
    NativePoly skeyNTT;
} RingGSWBTKey;

/**
 * @brief Ring GSW accumulator schemes described in
 * https://eprint.iacr.org/2014/816, https://eprint.iacr.org/2020/086 and https://eprint.iacr.org/2022/198
 */
class BinFHEScheme {
public:
    BinFHEScheme() = default;

    explicit BinFHEScheme(BINFHE_METHOD method) {
        if (method == AP)
            ACCscheme = std::make_shared<RingGSWAccumulatorDM>();
        else if (method == GINX)
            ACCscheme = std::make_shared<RingGSWAccumulatorCGGI>();
        else if (method == LMKCDEY)
            ACCscheme = std::make_shared<RingGSWAccumulatorLMKCDEY>();
        else
            OPENFHE_THROW("method is invalid");
    }

    /**
   * Generates a refresh key
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param LWEsk a shared pointer to the secret key of the underlying additive
   * @param keygenMode enum to indicate generation of secret key only (SYM_ENCRYPT) or
   * secret key, public key pair (PUB_ENCRYPT)
   * @return a shared pointer to the refresh key
   */
    RingGSWBTKey KeyGen(const std::shared_ptr<BinFHECryptoParams> params, ConstLWEPrivateKey LWEsk,
                        ConstLWEPrivateKey skN, RingGSWBTKey* ref) const;

    /**
   * Evaluates a binary gate (calls bootstrapping as a subroutine)
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param gate the gate; can be AND, OR, NAND, NOR, XOR, or XOR
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct1 first ciphertext
   * @param ct2 second ciphertext
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalBinGate(const std::shared_ptr<BinFHECryptoParams>& params, BINGATE gate, const RingGSWBTKey& EK,
                              ConstLWECiphertext& ct1, ConstLWECiphertext& ct2) const;

    /**
   * Evaluates a binary gate on a vector of ciphertexts (calls bootstrapping as a subroutine).
   * The evaluation of the gates in this function is specific to 3 input and 4 input
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param gate the gate; can be for 3-input: AND3, OR3, MAJORITY, CMUX, for 4-input: AND4, OR4
   * @param EK a shared pointer to the bootstrapping keys
   * @param ctvector vector of ciphertexts
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalBinGate(const std::shared_ptr<BinFHECryptoParams>& params, BINGATE gate, const RingGSWBTKey& EK,
                              const std::vector<LWECiphertext>& ctvector) const;

    /**
   * Evaluates NOT gate
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param ct1 the input ciphertext
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalNOT(const std::shared_ptr<BinFHECryptoParams>& params, ConstLWECiphertext& ct) const;

    /**
   * Bootstraps a fresh ciphertext
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct1 input ciphertext
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext Bootstrap(const std::shared_ptr<BinFHECryptoParams>& params, const RingGSWBTKey& EK,
                            ConstLWECiphertext& ct) const;

    /**
   * Evaluate an arbitrary function
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @param LUT the look-up table of the to-be-evaluated function
   * @param beta the error bound
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFunc(const std::shared_ptr<BinFHECryptoParams>& params, const RingGSWBTKey& EK,
                           ConstLWECiphertext& ct, const std::vector<NativeInteger>& LUT,
                           const NativeInteger& beta) const;
    /**
   * Evaluate an arbitrary function (using new LUT format, i.e. Zp-Zp mapping for upscaled messages, real-real mapping for CKKS messages)
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @param LUT the look-up table of the to-be-evaluated function, used only for Zp ciphertexts
   * @param beta the error bound
   * @param deltain scaling factor of input CKKS ciphertext
   * @param deltaout scaling factor of output CKKS ciphertext
   * @param f real function to be evaluated on CKKS ciphertext, used only for CKKS ciphertexts
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFuncTest(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                               ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT, const NativeInteger beta,
                               double deltain, double deltaout, NativeInteger qout, double (*f)(double m)) const;

    /**
   * Evaluate an arbitrary function using FDFB-Compress
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @param LUT the look-up table of the to-be-evaluated function, used only for Zp ciphertexts
   * @param beta the error bound
   * @param deltain scaling factor of input CKKS ciphertext
   * @param deltaout scaling factor of output CKKS ciphertext
   * @param f real function to be evaluated on CKKS ciphertext, used only for CKKS ciphertexts
   * @param is_signed if we interpret input as signed or not
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFuncCompress(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                   ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                   const NativeInteger beta, double deltain, double deltaout, NativeInteger qout,
                                   double (*f)(double m), bool is_signed = true) const;

    /**
   * Evaluate an arbitrary function using FDFB-CancelSign
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @param LUT the look-up table of the to-be-evaluated function, used only for Zp ciphertexts
   * @param beta the error bound
   * @param deltain scaling factor of input CKKS ciphertext
   * @param deltaout scaling factor of output CKKS ciphertext
   * @param f real function to be evaluated on CKKS ciphertext, used only for CKKS ciphertexts
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFuncCancelSign(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                     ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                     const NativeInteger beta, double deltain, double deltaout, NativeInteger qout,
                                     double (*f)(double m)) const;

    /**
   * Evaluate an arbitrary function using FDFB-Select
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @param LUT the look-up table of the to-be-evaluated function, used only for Zp ciphertexts
   * @param beta the error bound
   * @param deltain scaling factor of input CKKS ciphertext
   * @param deltaout scaling factor of output CKKS ciphertext
   * @param f real function to be evaluated on CKKS ciphertext, used only for CKKS ciphertexts
   * @param EK_small small EK for non-multi-value bts
   * @param baseG_small small Bg for non-multi-value bts
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFuncSelect(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                 ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT, const NativeInteger beta,
                                 double deltain, double deltaout, NativeInteger qout, double (*f)(double m),
                                 const RingGSWBTKey& EK_small, uint32_t baseG_small) const;

    /**
   * Evaluate an arbitrary function using FDFB-SelectAlt(3 bts)
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @param LUT the look-up table of the to-be-evaluated function, used only for Zp ciphertexts
   * @param beta the error bound
   * @param deltain scaling factor of input CKKS ciphertext
   * @param deltaout scaling factor of output CKKS ciphertext
   * @param f real function to be evaluated on CKKS ciphertext, used only for CKKS ciphertexts
   * @param EK_small small EK for non-multi-value bts
   * @param baseG_small small Bg for non-multi-value bts
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFuncSelectAlt(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                    ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                    const NativeInteger beta, double deltain, double deltaout, NativeInteger qout,
                                    double (*f)(double m), const RingGSWBTKey& EK_small, uint32_t baseG_small) const;

    /**
   * Evaluate an arbitrary function using FDFB-PreSelect
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @param LUT the look-up table of the to-be-evaluated function, used only for Zp ciphertexts
   * @param beta the error bound
   * @param deltain scaling factor of input CKKS ciphertext
   * @param deltaout scaling factor of output CKKS ciphertext
   * @param f real function to be evaluated on CKKS ciphertext, used only for CKKS ciphertexts
   * @param p_mid intermediate plaintext modulus for digit decomposition, used only for CKKS ciphertexts
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFuncPreSelect(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                    ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                    const NativeInteger beta, double deltain, double deltaout, NativeInteger qout,
                                    double (*f)(double m), NativeInteger p_mid) const;

    /**
   * Evaluate an arbitrary function using FDFB [KS21]  // only for benchmarking purpose
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @param LUT the look-up table of the to-be-evaluated function, used only for Zp ciphertexts
   * @param beta the error bound
   * @param deltain scaling factor of input CKKS ciphertext
   * @param deltaout scaling factor of output CKKS ciphertext
   * @param f real function to be evaluated on CKKS ciphertext, used only for CKKS ciphertexts
   * @param p_mid intermediate plaintext modulus for digit decomposition, used only for CKKS ciphertexts
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFuncKS21(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                               ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT, const NativeInteger beta,
                               double deltain, double deltaout, NativeInteger qout, double (*f)(double m)) const;
    /**
     * Evaluate an arbitrary function using Comp [CZB+22]
     *
    * @param params a shared pointer to RingGSW scheme parameters
    * @param EK a shared pointer to the bootstrapping keys
    * @param ct input ciphertext
    * @param LUT the look-up table of the to-be-evaluated function, used only for Zp ciphertexts
    * @param beta the error bound
    * @param deltain scaling factor of input CKKS ciphertext
    * @param deltaout scaling factor of output CKKS ciphertext
    * @param f real function to be evaluated on CKKS ciphertext, used only for CKKS ciphertexts
    * @param EK_small small EK for non-multi-value bts
    * @param baseG_small small Bg for non-multi-value bts
    * @param multi_thread whether use multithreading to accelerate
    * @return a shared pointer to the resulting ciphertext
    */
    LWECiphertext EvalFuncComp(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                               ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT, const NativeInteger beta,
                               double deltain, double deltaout, NativeInteger qout, double (*f)(double m),
                               uint32_t f_property, double shift, const RingGSWBTKey& EK_small,
                               uint32_t baseG_small) const;

    /**
   * Evaluate an arbitrary function using FDFB-BFVMult(improved WoPPBS-2)
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @param LUT the look-up table of the to-be-evaluated function, used only for Zp ciphertexts
   * @param beta the error bound
   * @param deltain scaling factor of input CKKS ciphertext
   * @param deltaout scaling factor of output CKKS ciphertext
   * @param qout output modulus, used only for CKKS ciphertexts
   * @param f real function to be evaluated on CKKS ciphertext, used only for CKKS ciphertexts
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFuncBFV(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                              ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT, const NativeInteger beta,
                              double deltain, double deltaout, NativeInteger qout, double (*f)(double m)) const;

    /**
   * Evaluate an arbitrary function using original WoPPBS-2
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @param LUT the look-up table of the to-be-evaluated function, used only for Zp ciphertexts
   * @param beta the error bound
   * @param deltain scaling factor of input CKKS ciphertext
   * @param deltaout scaling factor of output CKKS ciphertext
   * @param qout output modulus, used only for CKKS ciphertexts
   * @param f real function to be evaluated on CKKS ciphertext, used only for CKKS ciphertexts
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFuncWoPPBS2(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                  ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                  const NativeInteger beta, double deltain, double deltaout, NativeInteger qout,
                                  double (*f)(double m)) const;

    /**
   * Evaluate an arbitrary function using WoPPBS-1
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @param LUT the look-up table of the to-be-evaluated function, used only for Zp ciphertexts
   * @param beta the error bound
   * @param deltain scaling factor of input CKKS ciphertext
   * @param deltaout scaling factor of output CKKS ciphertext
   * @param qout output modulus, used only for CKKS ciphertexts
   * @param f real function to be evaluated on CKKS ciphertext, used only for CKKS ciphertexts
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFuncWoPPBS1(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                  ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                  const NativeInteger beta, double deltain, double deltaout, NativeInteger qout,
                                  double (*f)(double m)) const;

    /**
     * Evalute ReLU function
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param EK a shared pointer to the bootstrapping keys
     * @param ct input ciphertext
     * @param beta error bound for ct_sgn
    */
    LWECiphertext EvalReLU(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK_sgn,
                           uint32_t baseG_sgn, const RingGSWBTKey& EK_sel, uint32_t baseG_sel, ConstLWECiphertext ct,
                           ConstLWECiphertext ct_msd, size_t beta) const;

    /**
   * Evaluate a round down function
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @param beta the error bound
   * @param roundbits by how many bits to round down
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFloor(const std::shared_ptr<BinFHECryptoParams>& params, const RingGSWBTKey& EK,
                            ConstLWECiphertext& ct, const NativeInteger& beta, uint32_t roundbits = 0) const;

    /**
   * Evaluate a sign function over large precision
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys map
   * @param ct input ciphertext
   * @param beta the error bound
   * @param schemeSwitch flag that indicates if it should be compatible to scheme switching
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalSign(const std::shared_ptr<BinFHECryptoParams>& params,
                           const std::map<uint32_t, RingGSWBTKey>& EKs, ConstLWECiphertext& ct,
                           const NativeInteger& beta, bool schemeSwitch = false) const;

    /**
   * Evaluate digit decomposition over a large precision LWE ciphertext
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EKs a shared pointer to the bootstrapping keys map
   * @param ct input ciphertext
   * @param beta the error bound
   * @return a shared pointer to the resulting ciphertext
   */
    std::vector<LWECiphertext> EvalDecomp(const std::shared_ptr<BinFHECryptoParams> params,
                                          const std::map<uint32_t, RingGSWBTKey>& EKs, ConstLWECiphertext ct,
                                          const NativeInteger beta, bool CKKS) const;
    /**
   * Evaluate a round down function for an extracted CKKS ciphertext or a Brakerski's ciphertext with large error
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param ct1 input ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @param beta the error bound
   * @param bigger_q the ciphertext modulus
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFloorAlt(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                               ConstLWECiphertext ct, const NativeInteger beta, uint32_t roundbits = 0) const;

    /**
   * Evaluate a sign function over large precision for an extracted CKKS ciphertext or a Brakerski's ciphertext with large error
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param ct1 input ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @param beta the error bound
   * @param bigger_q the ciphertext modulus
   * @param fast follow HomFloorAlt by HomFloor for better performance
   * @param CKKS whether ct is an extracted CKKS ciphertext
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalSignAlt(const std::shared_ptr<BinFHECryptoParams> params,
                              const std::map<uint32_t, RingGSWBTKey>& EKs, ConstLWECiphertext ct,
                              const NativeInteger beta, bool fast, bool CKKS) const;

    /**
   * Evaluate a degit decomposition process for an extracted CKKS ciphertext or a Brakerski's ciphertext with large error
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param ct1 input ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @param beta the error bound
   * @param bigger_q the ciphertext modulus
   * @param fast follow HomFloorAlt by HomFloor for better performance
   * @param CKKS whether ct is an extracted CKKS ciphertext
   * @return a shared pointer to the resulting ciphertext
   */
    std::vector<LWECiphertext> EvalDecompAlt(const std::shared_ptr<BinFHECryptoParams> params,
                                             const std::map<uint32_t, RingGSWBTKey>& EKs, ConstLWECiphertext ct,
                                             const NativeInteger beta, bool CKKS) const;
    /**
   * Perform homomorphic LSB reduction
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param ct1 input ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @param beta the error bound
   * @param bigger_q the ciphertext modulus
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFloorNew(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                               ConstLWECiphertext ct, const NativeInteger beta, uint32_t roundbits = 0) const;

    /**
   * Evaluate a sign function over large precision using HomReduce
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param ct1 input ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @param beta the error bound
   * @param bigger_q the ciphertext modulus
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalSignNew(const std::shared_ptr<BinFHECryptoParams> params,
                              const std::map<uint32_t, RingGSWBTKey>& EKs, ConstLWECiphertext ct,
                              const NativeInteger beta) const;
    /**
   * Evaluate a degit decomposition process over a large precision LWE ciphertext using HomReduce
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param ct1 input ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @param beta the error bound
   * @param bigger_q the ciphertext modulus
   * @return a shared pointer to the resulting ciphertext
   */
    std::vector<LWECiphertext> EvalDecompNew(const std::shared_ptr<BinFHECryptoParams> params,
                                             const std::map<uint32_t, RingGSWBTKey>& EKs, ConstLWECiphertext ct,
                                             const NativeInteger beta, bool CKKS) const;
    /**
   * Clear LSBs using EvalFuncCompress
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param ct1 input ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @param beta the error bound
   * @param bigger_q the ciphertext modulus
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalFloorCompress(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                    ConstLWECiphertext ct, const NativeInteger beta, const NativeInteger precise_beta,
                                    uint32_t roundbits = 0) const;

    /**
   * Evaluate a sign function over large precision using EvalFloorCompress
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param ct1 input ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @param beta the error bound
   * @param bigger_q the ciphertext modulus
   * @return a shared pointer to the resulting ciphertext
   */
    LWECiphertext EvalSignCompress(const std::shared_ptr<BinFHECryptoParams> params,
                                   const std::map<uint32_t, RingGSWBTKey>& EKs, ConstLWECiphertext ct,
                                   const NativeInteger beta, const NativeInteger precise_beta) const;

    /**
   * Evaluate a degit decomposition process over a large precision LWE ciphertext using HomReduce
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param ct1 input ciphertext
   * @param lwescheme a shared pointer to additive LWE scheme
   * @param beta the error bound
   * @param bigger_q the ciphertext modulus
   * @return a shared pointer to the resulting ciphertext
   */
    std::vector<LWECiphertext> EvalDecompCompress(const std::shared_ptr<BinFHECryptoParams> params,
                                                  const std::map<uint32_t, RingGSWBTKey>& EKs, ConstLWECiphertext ct,
                                                  const NativeInteger beta, const NativeInteger precise_beta,
                                                  bool CKKS) const;


/**
* Switches ciphertext from LWE(q,N) to RLWE(Q,N), at the same time evaluating linear map
* {[m_i], pos_i} |-> sum(m_i*(1+X+...+X^(nOnes-1))*X^pos_i). pos_i is the param of RLWESwitchingKey
* i.e. produce a test vector (in ciphertext)
*
* @param params parameter for BinFHEScheme
* @param K switching key
* @param nOnes number of ones in linear map basis, i.e. 1+X+...+X^(nOnes-1)
* @param messages vector of {LWE ciphertext, right shift pos} pairs
* @return a shared pointer to the resulting ciphertext
*/
RLWECiphertext FunctionalKeySwitch(const std::shared_ptr<BinFHECryptoParams> params, ConstRLWESwitchingKey K,
                                   usint nOnes,
                                   const std::vector<std::pair<ConstLWECiphertext, size_t>>& messages) const;

/**
* Bootstrap an RLWE ciphertext
*
* @param params a shared pointer to RingGSW scheme parameters
* @param EK a shared pointer to the bootstrapping keys
* @param ct LWE ciphertext encrypting the index
* @param tv RLWE ciphertext, the test vector
* @param fmod output modulus
* @param raw if set to true, the acc after blind rotation will be directly returned without MS or KS
* @return the output RingLWE accumulator
*/
LWECiphertext BootstrapCtxt(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                            ConstLWECiphertext ct, ConstRLWECiphertext tv, const NativeInteger fmod,
                            bool raw = false, bool ms = true) const;

/**
 * BFV multiplication between two RLWE ciphertexts
 *
 * @param params BinFHE scheme parameter
 * @param EK RGSWBTKey
 * @param ct1 RLWE(Q/p*m1)
 * @param ct2 RLWE(Q/p*m2)
 * @param p plaintext modulus
 * @return RLWE(Q/p*m1m2)
*/
RLWECiphertext BFVMult(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                       const RLWECiphertext& ct1, const RLWECiphertext& ct2, uint32_t p) const;

/**
 * Extract the LWE ciphertext corresponding to X^pos from RLWE ciphertext
*/
LWECiphertext ManualExtract(ConstRLWECiphertext acc, size_t pos) const;

private:
    /**
   * Core bootstrapping operation
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param gate the gate; can be AND, OR, NAND, NOR, XOR, or XOR
   * @param ek a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @return the output RingLWE accumulator
   */
    RLWECiphertext BootstrapGateCore(const std::shared_ptr<BinFHECryptoParams>& params, BINGATE gate,
                                     ConstRingGSWACCKey& ek, ConstLWECiphertext& ct) const;

    // Arbitrary function evaluation purposes

    /**
   * Core bootstrapping operation
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param ek a shared pointer to the bootstrapping keys
   * @param ct input ciphertext
   * @param f function to evaluate in the functional bootstrapping
   * @param fmod modulus over which the function is defined
   * @return a shared pointer to the resulting ciphertext
   */
    template <typename Func>
    RLWECiphertext BootstrapFuncCore(const std::shared_ptr<BinFHECryptoParams>& params, ConstRingGSWACCKey& ek,
                                     ConstLWECiphertext& ct, const Func f, const NativeInteger& fmod) const;

    /**
   * Bootstraps a fresh ciphertext
   * NOTE: we add param `modswitch so that we can still use BootstrapFunc for multi-value bootstrap
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param &EK a shared pointer to the bootstrapping keys
   * @param ct input LWE ciphertext
   * @param f function that maps from ct.modulus to fmod (in multi-value boostrap, this will be a packed function. but the packed representation is transparent to BootstrapFunc)
   * @param fmod output ciphertext modulus (and output modulus for f)
   * @param modswitch if set to true, the ctxt after KS will be mod switched to fmod and returned; otherwise it is directly returned
   * @param raw if set to true, the ctxt after blind rotation will be directly returned, without MS or KS
   * @return the output RingLWE accumulator
   */

    template <typename Func>
    LWECiphertext BootstrapFunc(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                ConstLWECiphertext ct, const Func f, const NativeInteger fmod, bool raw = false,
                                bool ms = true) const;

    /**
   * Core bootstrapping operation
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a shared pointer to the bootstrapping keys
   * @param ct LWE ciphertext encrypting the index
   * @param tv RLWE ciphertext, the test vector
   * @return a shared pointer to the resulting ciphertext
   */
    RLWECiphertext BootstrapCtxtCore(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWACCKey ek,
                                     ConstLWECiphertext ct, ConstRLWECiphertext tv) const;

    /**
   * Changes a polynomial in R_Q to a scaled one in R_q
   *
   * @param q modulus to switch to
   * @param polyQ the input polynomial
   * @return resulting polynomial
   */
    NativeVector ModSwitch(NativeInteger q, const NativeVector& polyQ) const;

    /**
   * Changes a polynomial in R_Q to a scaled one in R_q inplace
   *
   * @param q modulus to switch to
   * @param polyQ the input polynomial
   */
    void ModSwitchInplace(NativeInteger q, NativeVector& polyQ) const;

    /**
     * Change RLWE ciphertext from vector representation to polynomial representation
    */
    RLWECiphertext vecs_to_RLWECiphertext(std::vector<NativeVector>&& vectors,
                                          const std::shared_ptr<ILNativeParams> params) const;

    /**
   * Generates a switching key to go from an LWE secret key with (q,N) to an RLWE secret
   * key with (Q,N), at the same time evaluating linear map a |-> a*(1+X+X^2+...+X^(N/2-1)).
   * i.e. produce a test vector (in ciphertext)
   *
   * @param params parameter for BinFHEScheme
   * @param sk old LWE secret key
   * @param skN new RLWE secret key in vector form
   * @param nOnes number of ones in linear map basis, i.e. 1+X+...+X^(nOnes-1)
   * @return a shared pointer to the switching key
   */
    RLWESwitchingKey FunctionalKeySwitchGen(const std::shared_ptr<BinFHECryptoParams> params, ConstLWEPrivateKey sk,
                                            const NativePoly& skNTT, usint nOnes) const;

    //XXX: debug
    RLWECiphertext FunctionalKeySwitchSimple(const std::shared_ptr<BinFHECryptoParams> params, ConstRLWESwitchingKey K,
                                             usint nOnes,
                                             const std::vector<std::pair<ConstLWECiphertext, size_t>>& messages) const;

    // NTL::ZZ_pX ToZZpX(const NativeVector& vec) const;

    // NativeVector FromZZpX(const NTL::ZZ_pX& poly) const;

    NativeVector PolyMult(const NativeVector& a, const NativeVector& s) const;

    /**
     * Extracts LWE ciphertexts packed in a large modulus Q
     * XXX: as a proof of concept version, we only support power-of-2 plaintext space for packed messages
     *      we note that non-power-of-2 plaintext space can also be supported by using an intermediate modulus
     * XXX: not used or implemented
     *
     * @param ct input LWE ciphertext with large modulus
     * @param msg_info vector of pairs, where each pair = <bit of message, bit of output modulus>
     * @param padding number of padding bits between messages (usually set to 1)
    */
    // std::vector<LWECiphertext> ExtractMultipleMessages(ConstLWECiphertext ct,
    //                                                    const std::vector<std::pair<size_t, size_t>>& msg_info,
    //                                                    size_t padding = 1) const;

    /**
     * Evaluate the negation of an LWE ciphertext
    */
    LWECiphertext EvalNegate(ConstLWECiphertext ct) const;

    /**
     * Extract LWE ciphertext from RLWE ciphertext
     * @param acc input RLWE ciphertext
     * NOTE: this function modifies ct
    */
    LWECiphertext ExtractACC(RLWECiphertext acc) const;

    /**
     * generate the RLWE' ciphertext for multi-value bootstrap or low noise multiplication (encrypting X^m*TV_0*B^i)
     *
     * @param params BinFHE scheme parameter
     * @param ct input LWE ciphertext as the LUT index (we require that ct is already 'unsigned')
     * @param beta bound of e_bt
     * @param p plaintext modulus
     * @param FDFB when set to true, generate RLWE' ciphertext for FDFB multi-value bootstrap (encrypting sgn(m)*X^m*TV_0*B^i and X^m*TV_0*B^i)
    */
    std::vector<RLWECiphertext> PrepareRLWEPrime(const std::shared_ptr<BinFHECryptoParams> params,
                                                 const RingGSWBTKey& EK, ConstLWECiphertext ct, NativeInteger beta,
                                                 size_t p, bool FDFB) const;

    /**
     * perform batch selection.
     * first ct will be bootstrapped to create an encryption of narrow-ranged [sgn], then this ciphertext is used to blind rotate a test vector
     *
     * @param params BinFHE scheme parameter
     * @param ct input LWE ciphertext as the selector (we require that ct is already 'unsigned')
     * @param beta bound of e_bt
     * @param pn_values vector of (pos_val, neg_val) pairs modulo Q, indicating the values to be selected when ct encrypts positive / negative message
     *
     * @return vector of selected LWE ciphertexts under (Q,N)
    */
    std::vector<LWECiphertext> BatchSelect(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                           ConstLWECiphertext ct, NativeInteger beta,
                                           const std::vector<std::pair<NativeInteger, NativeInteger>>& pn_values) const;

    /**
     * sign-decompose a polynomial using base B
     *
     * @param poly input polynomial to decompose
     * @param q the inner modulus for poly (i.e. we will mult poly by Q/q*..., so both q and Q can be viewed as poly's modulus)
     * @param B base for decomposition
    */
    std::vector<NativePoly> SignedDecomp(const std::shared_ptr<BinFHECryptoParams> params, const NativePoly& poly,
                                         size_t q, size_t B) const;

    /**
     * inner product between RLWE' and decomposed polynomial
     *
     * @param rlwe_prime RLWE' ciphertext
     * @param decomposed decomposed polynomial
    */
    RLWECiphertext InnerProduct(const std::vector<RLWECiphertext>& rlwe_prime,
                                const std::vector<NativePoly>& decomposed) const;

    /**
     * Generate BFV relinearization keys
     *
     * @param params BinFHE scheme parameters
     * @param skNTT RLWE secret key in NTT form
     * @return an RLWE' ciphertext encrypting skNTT
    */
    std::shared_ptr<std::vector<RLWECiphertext>> GenBFVRelinKeys(const std::shared_ptr<BinFHECryptoParams> params,
                                                                 const NativePoly& skNTT) const;

    NativeVector ComputeTV1(const NativeVector& tv) const;

    void inspect_lwe_ctxt(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK, uint32_t p,
                          ConstLWECiphertext ct, std::string name) const;

    int64_t inspect_lwe_ptxt(LWEPlaintext ptxt, uint32_t p, NativeInteger mod) const;

protected:
    std::shared_ptr<LWEEncryptionScheme> LWEscheme=std::make_shared<LWEEncryptionScheme>();
    std::shared_ptr<RingGSWAccumulator> ACCscheme=nullptr;

    /**
   * Checks type of input function
   *
   * @param lut look up table for the input function
   * @param mod modulus over which the function is defined
   * @return the function type: 0 for negacyclic, 1 for periodic, 2 for arbitrary
   */
    static uint32_t checkInputFunction(const std::vector<NativeInteger>& lut, NativeInteger mod) {
        size_t mid{lut.size() / 2};
        if (lut[0] == (mod - lut[mid])) {
            for (size_t i = 1; i < mid; ++i)
                if (lut[i] != (mod - lut[mid + i]))
                    return 2;
            return 0;
        }
        if (lut[0] == lut[mid]) {
            for (size_t i = 1; i < mid; ++i)
                if (lut[i] != lut[mid + i])
                    return 2;
            return 1;
        }
        return 2;
    }

};

}  // namespace lbcrypto

#endif

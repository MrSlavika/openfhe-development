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

#include "binfhe-base-scheme.h"

#include <string>

namespace lbcrypto {

RingGSWBTKey BinFHEScheme::KeyGen(const std::shared_ptr<BinFHECryptoParams> params, ConstLWEPrivateKey LWEsk,
                                  ConstLWEPrivateKey skN, RingGSWBTKey* ref) const {
    auto& LWEParams = params->GetLWEParams();
    auto N          = LWEParams->GetN();
    // ConstLWEPrivateKey skN = LWEscheme->KeyGen(LWEParams->GetN(), LWEParams->GetQ());

    // FIXME: refractor: there is no need to store KSkey & PKkey in every RingGSWBTKey, because it is not affected by baseG...
    //  maybe store the map from baseG to ACCkey in a single RingGSWBTKey? instead of storing multiple RingGSWBTKeys...
    RingGSWBTKey ek;

    auto& RGSWParams   = params->GetRingGSWParams();
    auto polyParams    = RGSWParams->GetPolyParams();
    NativePoly skNPoly = NativePoly(polyParams);

    if (ref != nullptr) {
        ek.PKkey_full       = ref->PKkey_full;
        ek.PKkey_half       = ref->PKkey_half;
        ek.PKkey_const      = ref->PKkey_const;
        ek.KSkey            = ref->KSkey;
        ek.PKKey_half_trans = ref->PKKey_half_trans;
        ek.BFV_relin_keys   = ref->BFV_relin_keys;

        ek.skeyNTT = ref->skeyNTT;
        skNPoly    = ek.skeyNTT;
    }
    else {
        skNPoly.SetValues(skN->GetElement(), Format::COEFFICIENT);
        skNPoly.SetFormat(Format::EVALUATION);
        ek.skeyNTT = skNPoly;

        ek.KSkey = LWEscheme->KeySwitchGen(LWEParams, LWEsk, skN);
        if (params->GetRingGSWParams()->GetBasePK() != 0) {
            auto flags = params->GetRingGSWParams()->GetPKKeyFlags();
            if (flags & RingGSWCryptoParams::PKKEY_FULL)
                ek.PKkey_full = this->FunctionalKeySwitchGen(params, skN, skNPoly, N);
            if (flags & RingGSWCryptoParams::PKKEY_HALF)
                ek.PKkey_half = this->FunctionalKeySwitchGen(params, skN, skNPoly, N / 2);
            if (flags & RingGSWCryptoParams::PKKEY_CONST)
                ek.PKkey_const = this->FunctionalKeySwitchGen(params, skN, skNPoly, 1);
            if (flags & RingGSWCryptoParams::PKKEY_HALF_TRANS)
                ek.PKKey_half_trans = this->FunctionalKeySwitchGen(params, LWEsk, skNPoly, N / 2);
        }
        if (params->GetRingGSWParams()->GetP() != 0) {
            ek.BFV_relin_keys = this->GenBFVRelinKeys(params, skNPoly);
        }
    }
    ek.BSkey = ACCscheme->KeyGenAcc(RGSWParams, skNPoly, LWEsk);

    // DEBUG only
    ek.skey  = std::make_shared<LWEPrivateKeyImpl>(*LWEsk);
    ek.skeyN = std::make_shared<LWEPrivateKeyImpl>(*skN);

    return ek;
}

// Full evaluation as described in https://eprint.iacr.org/2020/086
LWECiphertext BinFHEScheme::EvalBinGate(const std::shared_ptr<BinFHECryptoParams>& params, BINGATE gate,
                                        const RingGSWBTKey& EK, ConstLWECiphertext& ct1,
                                        ConstLWECiphertext& ct2) const {
    if (ct1 == ct2)
        OPENFHE_THROW("Input ciphertexts should be independant");

    LWECiphertext ctprep = std::make_shared<LWECiphertextImpl>(*ct1);
    // the additive homomorphic operation for XOR/NXOR is different from the other gates we compute
    // 2*(ct1 + ct2) mod 4 for XOR, 0 -> 0, 2 -> 1
    // XOR_FAST and XNOR_FAST are included for backwards compatibility; they map to XOR and XNOR
    if ((gate == XOR) || (gate == XNOR) || (gate == XOR_FAST) || (gate == XNOR_FAST)) {
        LWEscheme->EvalAddEq(ctprep, ct2);
        LWEscheme->EvalAddEq(ctprep, ctprep);
    }
    else {
        // for all other gates, we simply compute (ct1 + ct2) mod 4
        // for AND: 0,1 -> 0 and 2,3 -> 1
        // for OR: 1,2 -> 1 and 3,0 -> 0
        LWEscheme->EvalAddEq(ctprep, ct2);
    }

    auto acc{BootstrapGateCore(params, gate, EK.BSkey, ctprep)};

    // the accumulator result is encrypted w.r.t. the transposed secret key
    // we can transpose "a" to get an encryption under the original secret key
    std::vector<NativePoly>& accVec{acc->GetElements()};
    accVec[0] = accVec[0].Transpose();
    accVec[0].SetFormat(Format::COEFFICIENT);
    accVec[1].SetFormat(Format::COEFFICIENT);

    // we add Q/8 to "b" to to map back to Q/4 (i.e., mod 2) arithmetic.
    const auto& LWEParams = params->GetLWEParams();
    NativeInteger Q{LWEParams->GetQ()};
    NativeInteger b{(Q >> 3) + 1};
    b.ModAddFastEq(accVec[1][0], Q);

    auto ctExt = std::make_shared<LWECiphertextImpl>(std::move(accVec[0].GetValues()), std::move(b));
    // Modulus switching to a middle step Q'
    auto ctMS = LWEscheme->ModSwitch(LWEParams->GetqKS(), ctExt);
    // Key switching
    auto ctKS = LWEscheme->KeySwitch(LWEParams, EK.KSkey, ctMS);
    // Modulus switching
    return LWEscheme->ModSwitch(ct1->GetModulus(), ctKS);
}

// Full evaluation as described in https://eprint.iacr.org/2020/086
LWECiphertext BinFHEScheme::EvalBinGate(const std::shared_ptr<BinFHECryptoParams>& params, BINGATE gate,
                                        const RingGSWBTKey& EK, const std::vector<LWECiphertext>& ctvector) const {
    // check if the ciphertexts are all independent
    for (size_t i = 0; i < ctvector.size(); i++) {
        for (size_t j = i + 1; j < ctvector.size(); j++) {
            if (ctvector[j] == ctvector[i]) {
                OPENFHE_THROW("Input ciphertexts should be independent");
            }
        }
    }

    NativeInteger p = ctvector[0]->GetptModulus();

    LWECiphertext ctprep = std::make_shared<LWECiphertextImpl>(*ctvector[0]);
    ctprep->SetptModulus(p);
    if ((gate == MAJORITY) || (gate == AND3) || (gate == OR3) || (gate == AND4) || (gate == OR4)) {
        // we simply compute sum(ctvector[i]) mod p
        for (size_t i = 1; i < ctvector.size(); i++) {
            LWEscheme->EvalAddEq(ctprep, ctvector[i]);
        }
        auto acc = BootstrapGateCore(params, gate, EK.BSkey, ctprep);

        std::vector<NativePoly>& accVec = acc->GetElements();
        // the accumulator result is encrypted w.r.t. the transposed secret key
        // we can transpose "a" to get an encryption under the original secret key
        accVec[0] = accVec[0].Transpose();
        accVec[0].SetFormat(Format::COEFFICIENT);
        accVec[1].SetFormat(Format::COEFFICIENT);

        // we add Q/8 to "b" to to map back to Q/4 (i.e., mod 2) arithmetic.
        auto& LWEParams = params->GetLWEParams();
        NativeInteger Q = LWEParams->GetQ();
        NativeInteger b = Q / NativeInteger(2 * p) + 1;
        b.ModAddFastEq(accVec[1][0], Q);

        auto ctExt = std::make_shared<LWECiphertextImpl>(std::move(accVec[0].GetValues()), std::move(b));
        // Modulus switching to a middle step Q'
        auto ctMS = LWEscheme->ModSwitch(LWEParams->GetqKS(), ctExt);
        // Key switching
        auto ctKS = LWEscheme->KeySwitch(LWEParams, EK.KSkey, ctMS);
        // Modulus switching
        return LWEscheme->ModSwitch(ctvector[0]->GetModulus(), ctKS);
    }
    else if (gate == CMUX) {
        if (ctvector.size() != 3)
            OPENFHE_THROW("CMUX gate implemented for ciphertext vectors of size 3");

        auto ccNOT   = EvalNOT(params, ctvector[2]);
        auto ctNAND1 = EvalBinGate(params, NAND, EK, ctvector[0], ccNOT);
        auto ctNAND2 = EvalBinGate(params, NAND, EK, ctvector[1], ctvector[2]);
        auto ctCMUX  = EvalBinGate(params, NAND, EK, ctNAND1, ctNAND2);
        return ctCMUX;
    }
    else {
        OPENFHE_THROW("This gate is not implemented for vector of ciphertexts at this time");
    }
}
// Full evaluation as described in https://eprint.iacr.org/2020/086
LWECiphertext BinFHEScheme::Bootstrap(const std::shared_ptr<BinFHECryptoParams>& params, const RingGSWBTKey& EK,
                                      ConstLWECiphertext& ct) const {
    NativeInteger p = ct->GetptModulus();
    LWECiphertext ctprep{std::make_shared<LWECiphertextImpl>(*ct)};
    // ctprep = ct + q/4
    LWEscheme->EvalAddConstEq(ctprep, (ct->GetModulus() >> 2));

    auto acc{BootstrapGateCore(params, AND, EK.BSkey, ctprep)};

    // the accumulator result is encrypted w.r.t. the transposed secret key
    // we can transpose "a" to get an encryption under the original secret key
    std::vector<NativePoly>& accVec{acc->GetElements()};
    accVec[0] = accVec[0].Transpose();
    accVec[0].SetFormat(Format::COEFFICIENT);
    accVec[1].SetFormat(Format::COEFFICIENT);

    // we add Q/8 to "b" to to map back to Q/4 (i.e., mod 2) arithmetic.
    const auto& LWEParams = params->GetLWEParams();
    NativeInteger Q{LWEParams->GetQ()};
    NativeInteger b = Q / NativeInteger(2 * p) + 1;
    b.ModAddFastEq(accVec[1][0], Q);

    auto ctExt = std::make_shared<LWECiphertextImpl>(std::move(accVec[0].GetValues()), std::move(b));
    // Modulus switching to a middle step Q'
    auto ctMS = LWEscheme->ModSwitch(LWEParams->GetqKS(), ctExt);
    // Key switching
    auto ctKS = LWEscheme->KeySwitch(LWEParams, EK.KSkey, ctMS);
    // Modulus switching
    return LWEscheme->ModSwitch(ct->GetModulus(), ctKS);
}

// Evaluation of the NOT operation; no key material is needed
LWECiphertext BinFHEScheme::EvalNOT(const std::shared_ptr<BinFHECryptoParams>& params, ConstLWECiphertext& ct) const {
    NativeInteger q{ct->GetModulus()};
    uint32_t n{ct->GetLength()};

    NativeVector a(n, q);
    for (uint32_t i = 0; i < n; ++i)
        a[i] = ct->GetA(i) == 0 ? 0 : q - ct->GetA(i);

    return std::make_shared<LWECiphertextImpl>(std::move(a), (q >> 2).ModSubFast(ct->GetB(), q));
}

// Evaluate Arbitrary Function homomorphically
// Modulus of ct is q | 2N
LWECiphertext BinFHEScheme::EvalFunc(const std::shared_ptr<BinFHECryptoParams>& params, const RingGSWBTKey& EK,
                                     ConstLWECiphertext& ct, const std::vector<NativeInteger>& LUT,
                                     const NativeInteger& beta) const {
    auto ct1 = std::make_shared<LWECiphertextImpl>(*ct);
    NativeInteger q{ct->GetModulus()};
    uint32_t functionProperty{this->checkInputFunction(LUT, q)};

    if (functionProperty == 0) {  // negacyclic function only needs one bootstrap
        auto fLUT = [LUT](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            return LUT[x.ConvertToInt()];
        };
        LWEscheme->EvalAddConstEq(ct1, beta);
        return BootstrapFunc(params, EK, ct1, fLUT, q);
    }

    if (functionProperty == 2) {  // arbitary funciton
        const auto& LWEParams = params->GetLWEParams();
        uint32_t N{LWEParams->GetN()};
        if (q.ConvertToInt() > N) {  // need q to be at most = N for arbitary function
            std::string errMsg =
                "ERROR: ciphertext modulus q needs to be <= ring dimension for arbitrary function evaluation";
            OPENFHE_THROW(errMsg);
        }

        // TODO: figure out a way to not do this :(

        // repeat the LUT to make it periodic
        std::vector<NativeInteger> LUT2;
        LUT2.reserve(LUT.size() + LUT.size());
        LUT2.insert(LUT2.end(), LUT.begin(), LUT.end());
        LUT2.insert(LUT2.end(), LUT.begin(), LUT.end());

        NativeInteger dq{q << 1};
        // raise the modulus of ct1 : q -> 2q
        ct1->GetA().SetModulus(dq);

        auto ct2 = std::make_shared<LWECiphertextImpl>(*ct1);
        LWEscheme->EvalAddConstEq(ct2, beta);
        // this is 1/4q_small or -1/4q_small mod q
        auto f0 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            if (x < (q >> 1))
                return Q - (q >> 2);
            else
                return (q >> 2);
        };
        auto ct3 = BootstrapFunc(params, EK, ct2, f0, dq);
        LWEscheme->EvalSubEq2(ct1, ct3);
        LWEscheme->EvalAddConstEq(ct3, beta);
        LWEscheme->EvalSubConstEq(ct3, q >> 1);

        // Now the input is within the range [0, q/2).
        // Note that for non-periodic function, the input q is boosted up to 2q
        auto fLUT2 = [LUT2](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            if (x < (q >> 1))
                return LUT2[x.ConvertToInt()];
            else
                return Q - LUT2[x.ConvertToInt() - q.ConvertToInt() / 2];
        };
        auto ct4 = BootstrapFunc(params, EK, ct3, fLUT2, dq);
        ct4->SetModulus(q);
        return ct4;
    }
    std::cout << "WARNING: periodic function for sign-canceling like FDFB\n";
    // NOTE: this case is a little unnatural... to evaluate this we need q=2N, but for arbitrary function evaluation, q is always N

    // Else it's periodic function so we evaluate directly
    LWEscheme->EvalAddConstEq(ct1, beta);
    // this is 1/4q_small or -1/4q_small mod q
    auto f0 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < (q >> 1))
            return Q - (q >> 2);
        else
            return (q >> 2);
    };
    auto ct2 = BootstrapFunc(params, EK, ct1, f0, q);
    LWEscheme->EvalSubEq2(ct, ct2);
    LWEscheme->EvalAddConstEq(ct2, beta);
    LWEscheme->EvalSubConstEq(ct2, q >> 2);

    // Now the input is within the range [0, q/2).
    // Note that for non-periodic function, the input q is boosted up to 2q
    auto fLUT1 = [LUT](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < (q >> 1))
            return LUT[x.ConvertToInt()];
        else
            return Q - LUT[x.ConvertToInt() - q.ConvertToInt() / 2];
    };
    return BootstrapFunc(params, EK, ct2, fLUT1, q);
}
LWECiphertext BinFHEScheme::EvalFuncTest(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                         ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                         const NativeInteger beta, double deltain, double deltaout, NativeInteger qout,
                                         double (*f)(double m)) const {
    auto& LWEParams = params->GetLWEParams();
    auto Q          = LWEParams->GetQ();

    auto ct1 = std::make_shared<LWECiphertextImpl>(*ct);
    // Get what time of function it is
    NativeInteger q = ct->GetModulus();
    if (f != nullptr) {
        LWEscheme->EvalAddConstEq(ct1, q / 2);  // move (-q/2,q/2) to (0,q)
        auto dq = q << 1;
        ct1->SetModulus(dq);
        auto fLUTsgn = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            if (x < q / 2)         // here q = 2 * actual q
                return Q - q / 4;  // -actual q / 2
            else
                return q / 4;
        };
        auto ct2 = BootstrapFunc(params, EK, ct1, fLUTsgn, dq);
        LWEscheme->EvalAddConstEq(ct2, q / 2);
        LWEscheme->EvalSubEq(ct1, ct2);
        // now ct1 is in [0,q] in Z_2q (approximately)
        // NOTE: overflow may occur if input message is too close to \pm q/2
        auto fLUThalf = [f, deltain, deltaout, qout](NativeInteger x, NativeInteger q,
                                                     NativeInteger Q) -> NativeInteger {
            if (x < q / 2) {  // here q = 2 * actual q
                int64_t xin = x.ConvertToInt();
                xin -= int64_t((q / 4).ConvertToInt());  // - actual q / 2
                int64_t fval = std::round(f(xin / deltain) * deltaout * Q.ConvertToDouble() / qout.ConvertToDouble());
                fval %= int64_t(Q.ConvertToInt());
                if (fval < 0)
                    fval += int64_t(Q.ConvertToInt());
                return fval;
            }
            else
                OPENFHE_THROW(openfhe_error, "this branch should not have been reached");
        };
        auto fLUTfull = [fLUThalf](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            if (x < q / 2)
                return fLUThalf(x, q, Q);
            else
                return (Q - fLUThalf(x - q / 2, q, Q)).Mod(Q);
        };
        auto ct_res = BootstrapFunc(params, EK, ct1, fLUTfull, Q, false, false);
        return LWEscheme->ModSwitch(qout, ct_res);
        // TODO: test
    }

    // now the function to evaluate is a Z_p to Z_p mapping
    usint p = LUT.size();
    if (p & 1) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p must be even");
    }
    usint half_gap = (q.ConvertToInt() + p) / (2 * p);
    if (half_gap <= beta) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p too large");
    }
    uint32_t N = LWEParams->GetN();
    if (q > N) {  // need q to be at most = N for arbitary function
        std::string errMsg =
            "ERROR: ciphertext modulus q needs to be <= ring dimension for arbitrary function evaluation";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    NativeInteger dq = q << 1;
    // raise the modulus of ct1 : q -> 2q
    ct1->GetA().SetModulus(dq);
    auto ct2 = std::make_shared<LWECiphertextImpl>(*ct1);
    LWEscheme->EvalAddConstEq(ct2, half_gap);
    // this is 1/4q_small or -1/4q_small mod q
    auto f0 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 2)
            return Q - q / 4;
        else
            return q / 4;
    };
    auto ct3 = BootstrapFunc(params, EK, ct2, f0, dq);
    LWEscheme->EvalSubEq2(ct1, ct3);
    LWEscheme->EvalAddConstEq(ct3, half_gap);
    LWEscheme->EvalSubConstEq(ct3, q >> 1);

    // Now the input is within the range [0, q/2).
    // Note that for non-periodic function, the input q is boosted up to 2q
    auto fLUT = [LUT, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 2)
            return (LUT[(x * 2 * p / q).ConvertToInt()] * Q / 2 + p / 2) / p;  // input q/2->p, output p->Q/2
        else
            return (Q - (LUT[((x - q / 2) * 2 * p / q).ConvertToInt()] * Q / 2 + p / 2) / p).Mod(Q);
    };
    auto ct4 = BootstrapFunc(params, EK, ct3, fLUT, dq);
    ct4->SetModulus(q);
    return ct4;
}

// for EvalFunc, size of LUT = modulus of ct
// but here, for EvalFuncCompress, EvalFuncCancelSign, EvalFuncSelect, we treat LUT as a p-sized array representing a Z_p to Z_p mapping (if f is nullptr)
// when f is not nullptr, we ignore LUT and compute CKKS function
LWECiphertext BinFHEScheme::EvalFuncCompress(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                             ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                             const NativeInteger beta, double deltain, double deltaout,
                                             NativeInteger qout, double (*f)(double m), bool is_signed) const {
    // always full range
    // auto& LWEParams = params->GetLWEParams();
    auto ct1 = std::make_shared<LWECiphertextImpl>(*ct);

    NativeInteger q = ct->GetModulus();
    if (f != nullptr)   {
        NativeInteger Q = params->GetLWEParams()->GetQ();
        if (qout == 0)
            qout = q;  // when output modulus is not given, use the same as input modulus
        // compression: map 0 to beta, q/2-1 to q/4 - beta
        // f(x) = slope * x + beta for 0<=x<q/2, f(x) = q - slope * (x-q/2) - beta for q/2<=x<q
        double slope = (q / 4 - 2 * beta).ConvertToDouble() / (q / 2 - 1).ConvertToDouble();
        auto fLUTc   = [beta, slope](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            if (x < q / 2)
                return static_cast<uint64_t>(slope * x.ConvertToDouble() + beta.ConvertToDouble());
            else
                return (Q - static_cast<uint64_t>(slope * (x - q / 2).ConvertToDouble() + beta.ConvertToDouble()))
                    .Mod(Q);
        };
        auto ct_c = BootstrapFunc(params, EK, ct1, fLUTc, q);
        // evaluate LUT
        auto fLUThalf = [f, beta, slope, deltain, deltaout, qout, is_signed](NativeInteger x, NativeInteger q,
                                                                             NativeInteger Q) -> NativeInteger {
            if (x < q / 4) {
                double xin;
                if (x <= beta)
                    xin = 0;
                else if (x >= q / 4 - beta)
                    xin = q.ConvertToDouble() / 2 - 1;
                else
                    xin = (x - beta).ConvertToDouble() / slope;
                auto tmp = static_cast<int64_t>(
                    std::round(f(xin / deltain) * deltaout * Q.ConvertToDouble() / qout.ConvertToDouble()));
                tmp %= Q.ConvertToInt();
                if (tmp < 0)
                    tmp += Q.ConvertToInt();
                return static_cast<uint64_t>(tmp);
            }
            else if (x >= 3 * q / 4) {
                // NOTE: (q-x-beta) / slope + q/2 = input x, however, since input x has MSB=1, we need to interpret it as a signed number
                //  i.e. actual x = input x - q = (q-x-beta)/slope - q/2
                double xin;
                if (x <= 3 * q / 4 + beta)
                    xin = -1;  // q-1
                else if (x >= q - beta)
                    xin = -(q.ConvertToDouble()) / 2;  // q/2 - q
                else
                    xin = (q - x - beta).ConvertToDouble() / slope - q.ConvertToDouble() / 2;
                if (!is_signed)
                    xin += q.ConvertToDouble();
                auto tmp = static_cast<int64_t>(
                    std::round(f(xin / deltain) * deltaout * Q.ConvertToDouble() / qout.ConvertToDouble()));
                tmp %= Q.ConvertToInt();
                if (tmp < 0)
                    tmp += Q.ConvertToInt();
                return static_cast<uint64_t>(tmp);
            }
            else
                OPENFHE_THROW(openfhe_error, "this branch should not have been reached");
        };
        auto fLUTfull = [fLUThalf](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            if (x < q / 4 || x >= 3 * q / 4)
                return fLUThalf(x, q, Q);
            else
                return (Q - fLUThalf((x + q / 2).Mod(q), q, Q)).Mod(Q);
        };
        auto ct_ans = BootstrapFunc(params, EK, ct_c, fLUTfull, Q, false, false);  // return unscaled ciphertext
        return LWEscheme->ModSwitch(qout, ct_ans);
    }

    // now the function to evaluate is a Z_p to Z_p mapping
    usint p = LUT.size();
    if (p & 1) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p must be even");
    }
    usint half_gap = (q.ConvertToInt() + p) / (2 * p);
    if (half_gap <= beta) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p too large");
    }
    // NOTE: we assume that the input function is not negacyclic
    // NOTE: non power-of-2 p will NOT lead to rounding errors, because the preparation of fLUT is similar to decryption floor(x*p/Q)
    // uint32_t functionProperty = checkInputFunction(LUT, p);  // NOTE: use p here
    // if (functionProperty == 0) {                             // negacyclic function only needs one bootstrap
    //     // TODO: warn on large p
    //     // generate fLUT of q entries: fLUT[i] = round( LUT_p[ceil(i*p/q)] * Q/p )
    //     auto fLUT = [LUT, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
    //         return ((LUT[(x * p / q).ConvertToInt()] * Q + p / 2) / p).Mod(Q);
    //     };
    //     LWEscheme->EvalAddConstEq(ct1, half_gap);  // NOTE: half gap here
    //     return BootstrapFunc(params, EK, ct1, fLUT, q);
    // }

    // arbitary funciton
    // find the amplification factor alpha
    // the two margins are (alpha/2 - B) and (q/4 - (p-1)alpha/2 - B), if they are equal, alpha = q / (2p)
    usint alpha = ((q + p) / (2 * p)).ConvertToInt();  // round(q/2p)

    alpha += (alpha & 1);
    if ((alpha / 2 < beta) || (q / 4 - (p - 1) * alpha / 2 < beta)) {
        alpha -= 2;
        if ((alpha / 2 < beta) || (q / 4 - (p - 1) * alpha / 2 < beta))
            OPENFHE_THROW(openfhe_error, "plaintext modulus p too large, compression cannot be done");
    }

    // computation
    // make the error positive
    LWEscheme->EvalAddConstEq(ct1, half_gap);
    // compression
    auto fc = [alpha, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        usint xp = (x * p / q).ConvertToInt();
        if (xp < p / 2)
            return alpha * xp + alpha / 2;
        else
            return Q - alpha * (xp - p / 2) - alpha / 2;
    };
    auto ct2 = BootstrapFunc(params, EK, ct1, fc, q);  // alpha-amplified message

    // the non-negacyclic LUT, defined on [0,q/4) & [3q/4,q)
    auto halfLUT = [LUT, alpha, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 4) {
            if (x >= (p / 2 - 1) * alpha)
                return (LUT[p / 2 - 1] * Q + p / 2) / p;
            return (LUT[x.ConvertToInt() / alpha] * Q + p / 2) / p;
        }
        else if (x >= 3 * q / 4) {
            usint minus_part = (q - x).ConvertToInt() - 1;  // again in [0,3q/4)
            if (minus_part >= (p / 2 - 1) * alpha)
                return (LUT[p - 1] * Q + p / 2) / p;
            return (LUT[minus_part / alpha + p / 2] * Q + p / 2) / p;
        }
        else
            OPENFHE_THROW(openfhe_error, "this branch should never be reached");
    };
    // no more negacyclicity constraint
    auto fLUT = [halfLUT](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 4 || x >= 3 * q / 4)
            return halfLUT(x, q, Q);
        else
            return (Q - halfLUT((x + q / 2).Mod(q), q, Q)).Mod(Q);
    };

    return BootstrapFunc(params, EK, ct2, fLUT, q);
}

LWECiphertext BinFHEScheme::EvalFuncCancelSign(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                               ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                               const NativeInteger beta, double deltain, double deltaout,
                                               NativeInteger qout, double (*f)(double m)) const {
    // two versions, one for modraise and cancel, one for periodic (like in EvalFunc)
    auto LWEParams  = params->GetLWEParams();
    auto RGSWParams = params->GetRingGSWParams();
    uint32_t N      = LWEParams->GetN();

    auto ct1 = std::make_shared<LWECiphertextImpl>(*ct);
    // Get what time of function it is
    NativeInteger q = ct->GetModulus();

    if (f != nullptr) {
        NativeInteger Q = LWEParams->GetQ();
        if (qout == 0)
            qout = q;
        auto dq = q << 1;
        ct1->SetModulus(dq);
        auto fLUThalf = [f, deltain, deltaout, qout](NativeInteger x, NativeInteger q,
                                                     NativeInteger Q) -> NativeInteger {
            int64_t q_u = static_cast<int64_t>(q.ConvertToInt());
            if (x < q / 2) {
                int64_t xin = x.ConvertToInt();
                if (xin >= q_u / 4)
                    xin -= q_u / 2;
                int64_t fval = static_cast<int64_t>(
                    std::round(f(xin / deltain) * deltaout / qout.ConvertToDouble() * Q.ConvertToDouble()));
                fval %= Q.ConvertToInt();
                if (fval < 0)
                    fval += Q.ConvertToInt();
                return fval;
            }
            else
                OPENFHE_THROW(openfhe_error, "this branch should not have been reached");
        };
        auto fLUTfull = [fLUThalf](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            if (x < q / 2)
                return fLUThalf(x, q, Q);
            else
                return (Q - fLUThalf((x + q / 2).Mod(q), q, Q)).Mod(Q);
        };
        auto ct2    = BootstrapFunc(params, EK, ct1, fLUTfull, Q, true);  // get raw ciphertext
        auto ct_sel = FunctionalKeySwitch(params, EK.PKkey_full, N, {std::make_pair(ct2, N + 1)});
        return BootstrapCtxt(params, EK, ct1, ct_sel, qout);
    }
    // now the function to evaluate is a Z_p to Z_p mapping
    usint p = LUT.size();
    if (p & 1) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p must be even");
    }
    usint half_gap = (q.ConvertToInt() + p) / (2 * p);
    if (half_gap <= beta) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p too large");
    }
    // uint32_t functionProperty = checkInputFunction(LUT, p);  // NOTE: change to p here
    // if (functionProperty == 0) {                             // negacyclic function only needs one bootstrap
    //     // TODO: warn on large p
    //     // generate fLUT of q entries: fLUT[i] = round( LUT_p[ceil(i*p/q)] * Q/p )
    //     auto fLUT = [LUT, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
    //         return ((LUT[(x * p / q).ConvertToInt()] * Q + p / 2) / p).Mod(Q);
    //     };
    //     LWEscheme->EvalAddConstEq(ct1, half_gap);  // NOTE: half gap here
    //     return BootstrapFunc(params, EK, ct1, fLUT, q);
    // }
    // arbitary funciton
    NativeInteger qfrom = RGSWParams->GetQfrom();

    if (q > N) {  // need q to be at most = N for arbitary function
        std::string errMsg =
            "ERROR: ciphertext modulus q needs to be <= ring dimension for arbitrary function evaluation";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    auto fLUT = [LUT, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 2)
            return (LUT[(2 * x * p / q).ConvertToInt()] * Q / 2 + p / 2) /
                   p;  // input decoding(q/2 -> p), output encoding(p -> Q/2)
        else
            return (Q - (LUT[(2 * (x - q / 2) * p / q).ConvertToInt()] * Q / 2 + p / 2) / p).Mod(Q);
    };

    LWEscheme->EvalAddConstEq(ct1, half_gap);
    // raise the modulus of ct1 : q -> 2q
    NativeInteger dq = q << 1;
    ct1->GetA().SetModulus(dq);  // B is simply a NativeInteger without a modulus, so only A is handled here
    // evaluate the function anyway, yielding (-1)^beta*f(m)
    auto ct2 =
        LWEscheme->ModSwitch(qfrom, BootstrapFunc(params, EK, ct1, fLUT, dq, true));  // NOTE: return raw ciphertext

    // let ct be the encryption of (-1)^beta*f(m)
    // we need to set TV = -(-1)^beta*f(m) * (1+X+...+X^(N-1)), which corresponds to +: ct_pos, -: ct_neg
    auto packed = FunctionalKeySwitch(params, EK.PKkey_full, N, {std::make_pair(ct2, size_t(N + 1))});

    auto ct3 = BootstrapCtxt(params, EK, ct1, packed, dq);
    ct3->SetModulus(q);
    return ct3;
}

LWECiphertext BinFHEScheme::EvalFuncSelect(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                           ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                           const NativeInteger beta, double deltain, double deltaout,
                                           NativeInteger qout, double (*f)(double m), const RingGSWBTKey& EK_small,
                                           uint32_t baseG_small) const {
    // always full range
    auto LWEParams   = params->GetLWEParams();
    auto RGSWparams  = params->GetRingGSWParams();
    auto Q           = LWEParams->GetQ();
    auto N           = LWEParams->GetN();
    auto qKS         = LWEParams->GetqKS();
    auto baseGMV     = RGSWparams->GetBaseGMV();
    auto polyparams  = params->GetRingGSWParams()->GetPolyParams();
    bool multithread = params->GetMultithread();

    auto ct1                 = std::make_shared<LWECiphertextImpl>(*ct);
    bool use_multi_value_bts = baseGMV > 0;

    NativeInteger q = ct->GetModulus();
    if (f !=
        nullptr) {  // NOTE: for CKKS-extracted LWE ciphertext, we do not use multi-value bootstrap to accelerate it, since the error analysis is quite tricky and function dependant
        if (use_multi_value_bts)
            OPENFHE_THROW(
                openfhe_error,
                "using multi-value bootstrap to accelerate FDFB-Select on CKKS-extracted ciphertexts is not supported");
        if (qout == 0)
            qout = q;

        auto fLUTpos = [f, deltain, deltaout, qout](NativeInteger x, NativeInteger q,
                                                    NativeInteger Q) -> NativeInteger {
            if (x < q / 2) {
                int64_t xin  = x.ConvertToInt();
                int64_t fval = static_cast<int64_t>(
                    std::round(f(xin / deltain) * deltaout / qout.ConvertToDouble() * Q.ConvertToDouble()));
                fval %= Q.ConvertToInt();
                if (fval < 0)
                    fval += Q.ConvertToInt();
                return fval;
            }
            else
                OPENFHE_THROW(openfhe_error, "this branch should not have been reached");
        };
        auto fLUTneg = [f, deltain, deltaout, qout](NativeInteger x, NativeInteger q,
                                                    NativeInteger Q) -> NativeInteger {
            if (x >= q / 2) {
                int64_t xin  = x.ConvertToInt() - q.ConvertToInt();
                int64_t fval = static_cast<int64_t>(
                    std::round(f(xin / deltain) * deltaout / qout.ConvertToDouble() * Q.ConvertToDouble()));
                fval %= Q.ConvertToInt();
                if (fval < 0)
                    fval += Q.ConvertToInt();
                return fval;
            }
            else
                OPENFHE_THROW(openfhe_error, "this branch should not have been reached");
        };
        auto fLUTposfull = [fLUTpos](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            if (x < q / 2)
                return fLUTpos(x, q, Q);
            else
                return (Q - fLUTpos((x + q / 2).Mod(q), q, Q)).Mod(Q);
        };
        auto fLUTnegfull = [fLUTneg](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            if (x >= q / 2)
                return fLUTneg(x, q, Q);
            else
                return (Q - fLUTneg((x + q / 2).Mod(q), q, Q)).Mod(Q);
        };
        auto fLUTsgn = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            if (x < q / 2)
                return Q / 8;
            else
                return Q - Q / 8;
        };
        LWECiphertext ct_pos, ct_neg, ct_sgn;
        if (multithread) {
#pragma omp parallel for num_threads(3)
            for (size_t i = 0; i < 3; i++) {
                if (i == 0)
                    ct_pos = BootstrapFunc(params, EK, ct, fLUTposfull, Q, true);
                else if (i == 1)
                    ct_neg = BootstrapFunc(params, EK, ct, fLUTnegfull, Q, true);
                else
                    ct_sgn = BootstrapFunc(params, EK, ct, fLUTsgn, q);
            }
        }
        else {
            ct_pos = BootstrapFunc(params, EK, ct, fLUTposfull, Q, true);
            ct_neg = BootstrapFunc(params, EK, ct, fLUTnegfull, Q, true);
            ct_sgn = BootstrapFunc(params, EK, ct, fLUTsgn, q);
        }
        auto packed_tv =
            FunctionalKeySwitch(params, EK.PKkey_half, N / 2,
                                {std::make_pair(ct_pos, size_t(3 * N / 2)), std::make_pair(ct_neg, size_t(0))});
        auto ct_sel = BootstrapCtxt(params, EK, ct_sgn, packed_tv, q, false, false);
        return LWEscheme->ModSwitch(qout, ct_sel);
    }

    // now the function to evaluate is a Z_p to Z_p mapping
    usint p = LUT.size();
    if (p & 1) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p must be even");
    }
    usint half_gap = (q.ConvertToInt() + p) / (2 * p);
    if (half_gap <= beta) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p too large");
    }

    LWEscheme->EvalAddConstEq(ct1, half_gap);

    // NOTE: we don't choose to output Q - LUT[xxx] for negative values, because tv1's can either be viewed modulo Q or modulo p
    //  if we output p - LUT[xxx], the value of fLUT's will lie in [0,p-1]
    //  if we output Q - LUT[xxx], the value of fLUT's will iie in [-p+1,p-1], doubling the std of noise
    // NOTE: the third param is not used, its only usage is to fit into BootstrapFunc's API
    auto fLUTpos = [LUT, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 2)
            return LUT[(x * p / q).ConvertToInt()];
        else
            return (p - LUT[((x - q / 2) * p / q).ConvertToInt()]).Mod(p);
    };
    auto fLUTneg = [LUT, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x >= q / 2)
            return LUT[(x * p / q).ConvertToInt()];
        else
            return (p - LUT[((x + q / 2) * p / q).ConvertToInt()]).Mod(p);
    };
    auto fLUTsgn = [p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x <
            q / 2)  // NOTE: what if 8 does not divide p? A: some more error in the evaluated sign, but won't affect the correctness of FDFB-Select
            return p / 8;
        else
            return p - p / 8;
    };

    LWECiphertext ct_pos, ct_neg, ct_sgn;

    if (use_multi_value_bts) {
        auto rlwe_prime = PrepareRLWEPrime(params, EK, ct1, beta, p, false);  // NOTE: beta here

        NativeVector tv1_pos(N, p);
        NativeVector tv1_neg(N, p);
        NativeVector tv1_sgn(N, p);
        for (size_t i = 0, dN = 2 * N; i < N; i++) {
            auto tmp   = NativeInteger(0).ModSub(i, dN);
            tv1_pos[i] = fLUTpos(tmp, dN, p);
            tv1_neg[i] = fLUTneg(tmp, dN, p);
            tv1_sgn[i] = fLUTsgn(tmp, dN, p);
        }
        // TODO: directly find the transition points rather than compute the difference? but the overhead here is negligible compared to blind rotation
        tv1_pos = ComputeTV1(tv1_pos);
        tv1_neg = ComputeTV1(tv1_neg);
        tv1_sgn = ComputeTV1(tv1_sgn);
        tv1_pos.SwitchModulus(Q);
        tv1_neg.SwitchModulus(Q);
        tv1_sgn.SwitchModulus(Q);
        NativePoly poly_pos(polyparams), poly_neg(polyparams), poly_sgn(polyparams);
        poly_pos.SetValues(tv1_pos, Format::COEFFICIENT);
        poly_neg.SetValues(tv1_neg, Format::COEFFICIENT);
        poly_sgn.SetValues(tv1_sgn, Format::COEFFICIENT);

        auto acc_pos = InnerProduct(rlwe_prime, SignedDecomp(params, poly_pos, 2 * p, baseGMV)),
             acc_neg = InnerProduct(rlwe_prime, SignedDecomp(params, poly_neg, 2 * p, baseGMV)),
             acc_sgn = InnerProduct(rlwe_prime, SignedDecomp(params, poly_sgn, 2 * p, baseGMV));

        // extract LWE ciphertext
        ct_pos = ExtractACC(acc_pos);
        ct_neg = ExtractACC(acc_neg);
        ct_sgn = ExtractACC(acc_sgn);
        // bring ct_sgn to (q,n,sk) so that it can be used as the selector for next bootstrapping
        ct_sgn = LWEscheme->ModSwitch(qKS, ct_sgn);
        ct_sgn = LWEscheme->KeySwitch(LWEParams, EK.KSkey, ct_sgn);
        ct_sgn = LWEscheme->ModSwitch(q, ct_sgn);  // ct_sgn is in (-3q/4, 0) when msb = 1, and in (0, 4/q) when msb = 0
    }
    else {
        if (multithread) {
#pragma omp parallel for num_threads(3)
            for (size_t i = 0; i < 3; i++) {
                if (i == 0)
                    ct_pos = BootstrapFunc(params, EK, ct1, fLUTpos, p, true);
                else if (i == 1)
                    ct_neg = BootstrapFunc(params, EK, ct1, fLUTneg, p, true);
                else
                    ct_sgn = BootstrapFunc(params, EK, ct1, fLUTsgn, p, true);
            }
        }
        else {
            ct_pos = BootstrapFunc(params, EK, ct1, fLUTpos, p, true);
            ct_neg = BootstrapFunc(params, EK, ct1, fLUTneg, p, true);
            ct_sgn = BootstrapFunc(params, EK, ct1, fLUTsgn, p, true);
        }
        ct_sgn = LWEscheme->ModSwitch(qKS, ct_sgn);
        ct_sgn = LWEscheme->KeySwitch(LWEParams, EK.KSkey, ct_sgn);
        ct_sgn = LWEscheme->ModSwitch(q, ct_sgn);  // ct_sgn is in (-3q/4, 0) when msb = 1, and in (0, 4/q) when msb = 0
    }
    // functional KS
    auto packed_tv =
        FunctionalKeySwitch(params, EK.PKkey_half, N / 2,
                            {std::make_pair(ct_pos, size_t(3 * N / 2 + 1)), std::make_pair(ct_neg, size_t(1))});
    auto baseG_bak = RGSWparams->GetBaseG();
    RGSWparams->Change_BaseG(baseG_small);
    auto ct_sel = BootstrapCtxt(params, EK_small, ct_sgn, packed_tv, q);
    RGSWparams->Change_BaseG(baseG_bak);
    return ct_sel;
}

LWECiphertext BinFHEScheme::EvalFuncSelectAlt(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                              ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                              const NativeInteger beta, double deltain, double deltaout,
                                              NativeInteger qout, double (*f)(double m), const RingGSWBTKey& EK_small,
                                              uint32_t baseG_small) const {
    // always full range
    auto LWEParams   = params->GetLWEParams();
    auto RGSWparams  = params->GetRingGSWParams();
    auto Q           = LWEParams->GetQ();
    auto N           = LWEParams->GetN();
    auto qKS         = LWEParams->GetqKS();
    auto baseGMV     = RGSWparams->GetBaseGMV();
    auto polyparams  = params->GetRingGSWParams()->GetPolyParams();
    bool multithread = params->GetMultithread();

    auto ct1                 = std::make_shared<LWECiphertextImpl>(*ct);
    bool use_multi_value_bts = baseGMV > 0;

    NativeInteger q = ct->GetModulus();
    if (f !=
        nullptr) {  // NOTE: for CKKS-extracted LWE ciphertext, we do not use multi-value bootstrap to accelerate it, since the error analysis is quite tricky and function dependant
        if (use_multi_value_bts)
            OPENFHE_THROW(
                openfhe_error,
                "using multi-value bootstrap to accelerate FDFB-Select on CKKS-extracted ciphertexts is not supported");
        if (qout == 0)
            qout = q;

        auto fLUTpos = [f, deltain, deltaout, qout](NativeInteger x, NativeInteger q,
                                                    NativeInteger Q) -> NativeInteger {
            if (x < q / 2) {
                int64_t xin  = x.ConvertToInt();
                int64_t fval = static_cast<int64_t>(
                    std::round(f(xin / deltain) * deltaout / qout.ConvertToDouble() * Q.ConvertToDouble()));
                fval %= Q.ConvertToInt();
                if (fval < 0)
                    fval += Q.ConvertToInt();
                return fval;
            }
            else
                OPENFHE_THROW(openfhe_error, "this branch should not have been reached");
        };
        auto fLUTneg = [f, deltain, deltaout, qout](NativeInteger x, NativeInteger q,
                                                    NativeInteger Q) -> NativeInteger {
            if (x >= q / 2) {
                int64_t xin  = x.ConvertToInt() - q.ConvertToInt();
                int64_t fval = static_cast<int64_t>(
                    std::round(f(xin / deltain) * deltaout / qout.ConvertToDouble() * Q.ConvertToDouble()));
                fval %= Q.ConvertToInt();
                if (fval < 0)
                    fval += Q.ConvertToInt();
                return fval;
            }
            else
                OPENFHE_THROW(openfhe_error, "this branch should not have been reached");
        };
        auto fLUTposfull = [fLUTpos](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            if (x < q / 2)
                return fLUTpos(x, q, Q);
            else
                return (Q - fLUTpos((x + q / 2).Mod(q), q, Q)).Mod(Q);
        };
        auto fLUTnegfull = [fLUTneg](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            if (x >= q / 2)
                return fLUTneg(x, q, Q);
            else
                return (Q - fLUTneg((x + q / 2).Mod(q), q, Q)).Mod(Q);
        };
        // XXX: try new
        // (TVneg - TVpos)/2
        // auto fLUThalfdiff = [fLUTposfull, fLUTnegfull](NativeInteger x, NativeInteger q,
        //                                                NativeInteger Q) -> NativeInteger {
        //     return fLUTnegfull(x, q, Q).ModSubFast(fLUTposfull(x, q, Q), Q) >> 1;
        // };

        NativePoly tv_hdiff(polyparams, Format::COEFFICIENT, true), tv_hsum(polyparams, Format::COEFFICIENT, true);
        NativePoly dummy_1(polyparams, Format::COEFFICIENT, true), dummy_2(polyparams, Format::COEFFICIENT, true);
        for(size_t i = 0; i < N; i++){
            NativeInteger tmp = NativeInteger(0).ModSubFast(i, q);
            int64_t pos_coeff = fLUTposfull(tmp, q, Q).ConvertToInt(), neg_coeff = fLUTnegfull(tmp, q, Q).ConvertToInt();
            int64_t hdiff_coeff = (neg_coeff - pos_coeff) / 2, hsum_coeff = (neg_coeff + pos_coeff) / 2;
            if(hdiff_coeff < 0)
                hdiff_coeff += Q.ConvertToInt();
            tv_hdiff[i] = hdiff_coeff;
            tv_hsum[i] = hsum_coeff;
        }

        LWECiphertext ct_hdiff, ct_hsum;
        ct_hdiff = BootstrapCtxt(params, EK, ct, std::make_shared<RLWECiphertextImpl>(std::vector<NativePoly>{dummy_1, tv_hdiff}), 0, true);
        ct_hsum = BootstrapCtxt(params, EK, ct, std::make_shared<RLWECiphertextImpl>(std::vector<NativePoly>{dummy_2, tv_hsum}), 0, true);

        auto packed_tv = FunctionalKeySwitch(params, EK.PKkey_full, N, {std::make_pair(ct_hdiff, N + 1)});
        auto ct_sgn_hdiff = BootstrapCtxt(params, EK, ct, packed_tv, 0, true);
        LWEscheme->EvalSubEq(ct_hsum, ct_sgn_hdiff);
        // postprocessing
        ct_hsum = LWEscheme->ModSwitch(qKS, ct_hsum);
        ct_hsum = LWEscheme->KeySwitch(LWEParams, EK.KSkey, ct_hsum);
        return LWEscheme->ModSwitch(qout, ct_hsum);

        //         LWECiphertext ct_pos, ct_diff;
        //         if (multithread) {
        // #pragma omp parallel for num_threads(2)
        //             for (size_t i = 0; i < 2; i++) {
        //                 if (i == 0)
        //                     ct_pos = BootstrapFunc(params, EK, ct, fLUTposfull, Q, true);
        //                 else if (i == 1)
        //                     ct_diff = BootstrapFunc(params, EK, ct, fLUThalfdiff, Q, true);
        //             }
        //         }
        //         else {
        //             ct_pos  = BootstrapFunc(params, EK, ct, fLUTposfull, Q, true);
        //             ct_diff = BootstrapFunc(params, EK, ct, fLUThalfdiff, Q, true);
        //         }
        //         auto packed_tv  = FunctionalKeySwitch(params, EK.PKkey_full, N, {std::make_pair(ct_diff, N + 1)});
        //         auto ct_sgndiff = BootstrapCtxt(params, EK, ct, packed_tv, q, true);
        //         LWEscheme->EvalSubEq(ct_diff, ct_sgndiff);
        //         LWEscheme->EvalAddEq(ct_diff, ct_pos);
        // postprocessing
        // ct_diff = LWEscheme->ModSwitch(qKS, ct_diff);
        // ct_diff = LWEscheme->KeySwitch(LWEParams, EK.KSkey, ct_diff);
        // return LWEscheme->ModSwitch(qout, ct_diff);
    }
    // now the function to evaluate is a Z_p to Z_p mapping
    usint p = LUT.size();
    if (p & 1) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p must be even");
    }
    usint half_gap = (q.ConvertToInt() + p) / (2 * p);
    if (half_gap <= beta) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p too large");
    }

    LWEscheme->EvalAddConstEq(ct1, half_gap);

    // NOTE: we don't choose to output Q - LUT[xxx] for negative values, because tv1's can either be viewed modulo Q or modulo p
    //  if we output p - LUT[xxx], the value of fLUT's will lie in [0,p-1]
    //  if we output Q - LUT[xxx], the value of fLUT's will iie in [-p+1,p-1], doubling the std of noise
    // NOTE: the third param is not used, its only usage is to fit into BootstrapFunc's API
    auto fLUTpos = [LUT, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 2)
            return LUT[(x * p / q).ConvertToInt()];
        else
            return (p - LUT[((x - q / 2) * p / q).ConvertToInt()]).Mod(p);
    };
    auto fLUTneg = [LUT, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x >= q / 2)
            return LUT[(x * p / q).ConvertToInt()];
        else
            return (p - LUT[((x + q / 2) * p / q).ConvertToInt()]).Mod(p);
    };
    auto fLUThalfdiff = [fLUTpos, fLUTneg, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        return fLUTneg(x, q, Q).ModSubFast(fLUTpos(x, q, Q), p);
    };

    LWECiphertext ct_pos, ct_diff;

    if (use_multi_value_bts) {
        // set baseGMV >= 4p for this work... TODO: update API?
        // NOTE: generate Q/4p*(1+X+...)*X^m * {(1-sgn) * (TV1neg - TV1pos) or 2TV1pos}
        auto rlwe_prime = PrepareRLWEPrime(params, EK, ct1, beta, 2 * p, false);

        NativeVector tv1_pos(N, p);
        NativeVector tv1_diff(N, p);
        for (size_t i = 0, dN = 2 * N; i < N; i++) {
            auto tmp    = NativeInteger(0).ModSub(i, dN);
            tv1_pos[i]  = fLUTpos(tmp, dN, 0);
            tv1_diff[i] = fLUThalfdiff(tmp, dN, 0);
        }
        // TODO: directly find the transition points rather than compute the difference? but the overhead here is negligible compared to blind rotation
        tv1_pos  = ComputeTV1(tv1_pos);
        tv1_diff = ComputeTV1(tv1_diff);
        tv1_pos.SetModulus(Q);
        tv1_diff.SetModulus(Q);
        NativePoly poly_pos(polyparams), poly_diff(polyparams);
        poly_pos.SetValues(tv1_pos, Format::COEFFICIENT);
        poly_diff.SetValues(tv1_diff, Format::COEFFICIENT);

        auto acc_pos =
                 InnerProduct(rlwe_prime, SignedDecomp(params, poly_pos, 2 * p, 2 * p)),  // NOTE: no decomp here...
            acc_diff = InnerProduct(rlwe_prime, SignedDecomp(params, poly_diff, 2 * p, 2 * p));

        // extract LWE ciphertext
        ct_pos  = ExtractACC(acc_pos);
        ct_diff = ExtractACC(acc_diff);
        LWEscheme->EvalMultConstEq(ct_pos, 2);  // 2 TVpos
    }
    else {
        if (multithread) {
#pragma omp parallel for num_threads(2)
            for (size_t i = 0; i < 2; i++) {
                if (i == 0)
                    ct_pos = BootstrapFunc(params, EK, ct1, fLUTpos, p, true);
                else if (i == 1)
                    ct_diff = BootstrapFunc(params, EK, ct1, fLUThalfdiff, 2 * p, true);
            }
        }
        else {
            ct_pos  = BootstrapFunc(params, EK, ct1, fLUTpos, p, true);
            ct_diff = BootstrapFunc(params, EK, ct1, fLUThalfdiff, 2 * p, true);
        }
    }
    // functional KS
    auto packed_tv = FunctionalKeySwitch(params, EK.PKkey_full, N, {std::make_pair(ct_diff, N + 1)});
    auto baseG_bak = RGSWparams->GetBaseG();
    RGSWparams->Change_BaseG(baseG_small);
    auto ct_sgndiff = BootstrapCtxt(params, EK_small, ct1, packed_tv, q, true);
    RGSWparams->Change_BaseG(baseG_bak);
    LWEscheme->EvalSubEq(ct_diff, ct_sgndiff);
    LWEscheme->EvalAddEq(ct_diff, ct_pos);
    // postprocessing
    ct_diff = LWEscheme->ModSwitch(qKS, ct_diff);
    ct_diff = LWEscheme->KeySwitch(LWEParams, EK.KSkey, ct_diff);
    return LWEscheme->ModSwitch(q, ct_diff);
}

LWECiphertext BinFHEScheme::EvalFuncPreSelect(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                              ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                              const NativeInteger beta, double deltain, double deltaout,
                                              NativeInteger qout, double (*f)(double m), NativeInteger p_mid) const {
    auto LWEParams   = params->GetLWEParams();
    auto RGSWparams  = params->GetRingGSWParams();
    uint32_t N       = LWEParams->GetN();
    uint32_t baseG0  = RGSWparams->GetBaseG0();
    NativeInteger Q  = LWEParams->GetQ();
    auto polyparams  = RGSWparams->GetPolyParams();
    bool multithread = params->GetMultithread();

    auto ct1 = std::make_shared<LWECiphertextImpl>(*ct);
    // Get what time of function it is
    NativeInteger q = ct->GetModulus();
    if (f != nullptr) {
        if (qout == 0)
            qout = q;
        if (p_mid == 0)
            p_mid = q;
        size_t d_G0 = static_cast<size_t>(std::ceil(log(p_mid.ConvertToDouble()) / log(double(baseG0))));
        std::vector<std::pair<NativeInteger, NativeInteger>> pn_values(d_G0);
        uint128_t Q_128 = static_cast<uint128_t>(Q.ConvertToInt()),
                  p_128 = static_cast<uint128_t>(p_mid.ConvertToInt());
        uint128_t power = 1;
        for (size_t i = 0; i < d_G0; i++, power *= baseG0) {  // generate (MSB==1)*Q/p*B^i
            pn_values[i].first  = 0;
            pn_values[i].second = static_cast<uint64_t>((Q_128 * power + p_128 / 2) / p_128);
        }
        auto batch_sel_res = BatchSelect(params, EK, ct1, beta, pn_values);
        std::vector<RLWECiphertext> rlwe_prime(d_G0);
        if (multithread) {
            omp_set_nested(1);  // NOTE: enable nested parallelism for FunctionalKS
#pragma omp parallel for num_threads(d_G0)
            for (
                size_t i = 0; i < d_G0;
                i++) {  // generate (MSB==1)*Q/p*B^i // NOTE: we can also use TV0*TV1 decomposition and generate (MSB==1)*Q/2p*B^i*(1+X+...+X^{N-1})
                rlwe_prime[i] = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(batch_sel_res[i], 0)});
                rlwe_prime[i]->SetFormat(Format::EVALUATION);
            }
        }
        else {
            for (size_t i = 0; i < d_G0; i++) {  // generate (MSB==1)*Q/p*B^i
                rlwe_prime[i] = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(batch_sel_res[i], 0)});
                rlwe_prime[i]->SetFormat(Format::EVALUATION);
            }
        }

        // poly x RLWE' multiplication: [MSB==1] * ((poly_neg - poly_pos) mod p) + poly_pos
        auto fLUTpos = [p_mid, f, deltain, deltaout, qout](NativeInteger x, NativeInteger q) -> NativeInteger {
            if (x < q / 2) {
                int64_t fval = std::round(f(x.ConvertToDouble() / deltain) * deltaout * p_mid.ConvertToDouble() /
                                          qout.ConvertToDouble());
                fval %= p_mid.ConvertToInt();
                if (fval < 0)
                    fval += p_mid.ConvertToInt();
                return fval;
            }
            else {
                OPENFHE_THROW(openfhe_error, "this branch should not have been reached");
            }
        };
        auto fLUTneg = [p_mid, f, deltain, deltaout, qout](NativeInteger x, NativeInteger q) -> NativeInteger {
            if (x >= q / 2) {
                // NOTE: use x - q here, because x represents a negative value
                int64_t fval = std::round(f((x.ConvertToDouble() - q.ConvertToDouble()) / deltain) * deltaout *
                                          p_mid.ConvertToDouble() / qout.ConvertToDouble());
                fval %= p_mid.ConvertToInt();
                if (fval < 0)
                    fval += p_mid.ConvertToInt();
                return fval;
            }
            else {
                OPENFHE_THROW(openfhe_error, "this branch should not have been reached");
            }
        };
        auto fLUTpos_full = [fLUTpos, p_mid](NativeInteger x, NativeInteger q) -> NativeInteger {
            if (x < q / 2)
                return fLUTpos(x, q);
            else
                return (p_mid - fLUTpos((x + q / 2).Mod(q), q)).Mod(p_mid);
        };
        auto fLUTneg_full = [fLUTneg, p_mid](NativeInteger x, NativeInteger q) -> NativeInteger {
            if (x >= q / 2)
                return fLUTneg(x, q);
            else
                return (p_mid - fLUTneg((x + q / 2).Mod(q), q)).Mod(p_mid);
        };

        NativePoly poly_pos(polyparams, Format::COEFFICIENT, true), poly_neg(polyparams, Format::COEFFICIENT, true);
        for (size_t i = 0, dN = N * 2; i < N; i++) {
            poly_pos[i] = fLUTpos_full(NativeInteger(0).ModSub(i, dN), dN);
            poly_neg[i] = fLUTneg_full(NativeInteger(0).ModSub(i, dN), dN);
        }

        auto poly_diff = poly_neg - poly_pos;
        for (size_t i = 0; i < N; i++) {
            // reduce to [-pmid/2, pmid/2-1]
            if (poly_diff[i] < Q - p_mid / 2)
                poly_diff[i].ModAddFastEq(p_mid, Q);
            else if (poly_diff[i] >= p_mid / 2)
                poly_diff[i].ModSubFastEq(p_mid, Q);
        }

        auto decomp_poly_diff = SignedDecomp(params, poly_diff, p_mid.ConvertToInt(), baseG0);

        // mult
        RLWECiphertext ct_prod = InnerProduct(rlwe_prime, decomp_poly_diff);
        ct_prod->GetElements()[0].SetFormat(Format::COEFFICIENT);
        ct_prod->GetElements()[1].SetFormat(Format::COEFFICIENT);

        NativeVector vec_pos = poly_pos.GetValues();
        vec_pos.SetModulus(p_mid);
        NativePoly scaled_poly_pos(polyparams);
        scaled_poly_pos.SetValues(ModSwitch(Q, vec_pos), Format::COEFFICIENT);
        ct_prod->GetElements()[1] += scaled_poly_pos;
        // blind rotate
        return BootstrapCtxt(params, EK, ct1, ct_prod, qout);
    }

    // now the function to evaluate is a Z_p to Z_p mapping
    usint p = LUT.size();
    if (p & 1) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p must be even");
    }
    usint half_gap = (q.ConvertToInt() + p) / (2 * p);
    if (half_gap <= beta) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p too large");
    }
    // arbitary funciton
    // Phase preprocessing
    // 1. bts([m]) -> [sgn]
    // 2. prepare packed poly of {0,1}*Q/p*B^i, for i = 0, 1, ..., d_G0 - 1
    // 3. bts([sgn]) -> multiple LWE ciphertexts encrypting (MSB==1)*Q/p*B^i
    // 4. LWE to RLWE packing (only constant term) -> RLWE' ciphertext encrypting {(MSB==1)*Q/p*B^i}
    // Phase online
    // 5. Decomp(poly) x RLWE' -> selected ciphertext [TV*]
    // 6. bts([TV*]) -> [f(m)]

    LWEscheme->EvalAddConstEq(ct1, half_gap);
    size_t d_G0 = static_cast<size_t>(std::ceil(log(double(2 * p)) / log(double(baseG0))));
    std::vector<std::pair<NativeInteger, NativeInteger>> pn_values(d_G0);
    uint128_t Q_128 = static_cast<uint128_t>(Q.ConvertToInt()), p_128 = static_cast<uint128_t>(p),
              dp_128 = static_cast<uint128_t>(2 * p);
    uint128_t power  = 1;
    for (size_t i = 0; i < d_G0; i++, power *= baseG0) {  // generate (MSB==1)*Q/2p*B^i
        pn_values[i].first  = 0;
        pn_values[i].second = static_cast<uint64_t>((Q_128 * power + p_128) / dp_128);
    }
    auto batch_sel_res = BatchSelect(params, EK, ct1, beta, pn_values);  // NOTE: here beta is the precise beta
    std::vector<RLWECiphertext> rlwe_prime(d_G0);
    if (multithread) {
        omp_set_nested(1);  // NOTE: enable nested parallelism for FunctionalKS
#pragma omp parallel for num_threads(d_G0)
        for (size_t i = 0; i < d_G0; i++) {  // generate (MSB==1)*Q/2p*B^i*(1+X+X^2+...+X^(N-1))
            rlwe_prime[i] = FunctionalKeySwitch(params, EK.PKkey_full, N, {std::make_pair(batch_sel_res[i], 0)});
            rlwe_prime[i]->SetFormat(Format::EVALUATION);
        }
    }
    else {
        for (size_t i = 0; i < d_G0; i++) {  // generate (MSB==1)*Q/2p*B^i*(1+X+X^2+...+X^(N-1))
            rlwe_prime[i] = FunctionalKeySwitch(params, EK.PKkey_full, N, {std::make_pair(batch_sel_res[i], 0)});
            rlwe_prime[i]->SetFormat(Format::EVALUATION);
        }
    }
    // poly x RLWE' multiplication: [MSB==1] * ((poly_neg - poly_pos) mod 2p) + poly_pos
    auto fLUT_pos = [LUT, p](NativeInteger x, NativeInteger q) -> NativeInteger {
        if (x < q / 2)
            return LUT[(x * p / q).ConvertToInt()];
        else
            return (p - LUT[((x - q / 2) * p / q).ConvertToInt()]).Mod(p);
    };
    auto fLUT_neg = [LUT, p](NativeInteger x, NativeInteger q) -> NativeInteger {
        if (x >= q / 2)
            return LUT[(x * p / q).ConvertToInt()];
        else
            return (p - LUT[((x + q / 2) * p / q).ConvertToInt()]).Mod(p);
    };
    NativeVector tv1_pos(N, p), tv1_neg(N, p);
    for (size_t i = 0, dN = N * 2; i < N; i++) {
        tv1_pos[i] = fLUT_pos(NativeInteger(0).ModSub(i, dN), dN);
        tv1_neg[i] = fLUT_neg(NativeInteger(0).ModSub(i, dN), dN);
    }
    NativeVector vec_pos  = tv1_pos;
    tv1_pos               = ComputeTV1(tv1_pos);
    tv1_neg               = ComputeTV1(tv1_neg);
    NativeVector tv1_diff = tv1_neg - tv1_pos;
    tv1_diff.SetModulus(Q);
    NativePoly poly_diff(polyparams);
    poly_diff.SetValues(tv1_diff, Format::COEFFICIENT);

    // NativePoly poly_pos(polyparams, Format::COEFFICIENT, true), poly_neg(polyparams, Format::COEFFICIENT, true);
    // for (size_t i = 0, dN = N * 2; i < N; i++) {
    //     poly_pos[i] = fLUT_pos(NativeInteger(0).ModSub(i, dN), dN);
    //     poly_neg[i] = fLUT_neg(NativeInteger(0).ModSub(i, dN), dN);
    // }
    // NativeVector vec_pos = poly_pos.GetValues();
    // vec_pos.SetModulus(p);

    // poly_pos -= poly_pos.ShiftRightNegacyclic(1);
    // poly_neg -= poly_neg.ShiftRightNegacyclic(1);
    // auto decomp_poly_diff = SignedDecomp(params, poly_neg - poly_pos, 2 * p, baseG0);
    auto decomp_poly_diff = SignedDecomp(params, poly_diff, 2 * p, baseG0);

    // mult
    RLWECiphertext ct_prod = InnerProduct(rlwe_prime, decomp_poly_diff);
    ct_prod->GetElements()[0].SetFormat(Format::COEFFICIENT);
    ct_prod->GetElements()[1].SetFormat(Format::COEFFICIENT);

    NativePoly scaled_poly_pos(polyparams);
    scaled_poly_pos.SetValues(ModSwitch(Q, vec_pos), Format::COEFFICIENT);
    ct_prod->GetElements()[1] += scaled_poly_pos;
    // blind rotate
    return BootstrapCtxt(params, EK, ct1, ct_prod, q);
}

// NOTE: copied from EvalFuncPreselec
LWECiphertext BinFHEScheme::EvalFuncKS21(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                         ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                         const NativeInteger beta, double deltain, double deltaout, NativeInteger qout,
                                         double (*f)(double m)) const {
    auto LWEParams   = params->GetLWEParams();
    auto RGSWparams  = params->GetRingGSWParams();
    uint32_t N       = LWEParams->GetN();
    uint32_t baseG0  = RGSWparams->GetBaseG0();
    NativeInteger Q  = LWEParams->GetQ();
    auto polyparams  = RGSWparams->GetPolyParams();
    bool multithread = params->GetMultithread();

    auto ct1 = std::make_shared<LWECiphertextImpl>(*ct);
    // Get what time of function it is
    NativeInteger q = ct->GetModulus();
    if (f != nullptr) {
        if (qout == 0)
            qout = q;
        size_t d_G0 = static_cast<size_t>(std::ceil(log(Q.ConvertToDouble()) / log(double(baseG0))));
        std::vector<std::pair<NativeInteger, NativeInteger>> pn_values(d_G0);
        // uint128_t Q_128 = static_cast<uint128_t>(Q.ConvertToInt()), p_128 = static_cast<uint128_t>(p),
        //           dp_128 = static_cast<uint128_t>(2 * p);
        std::vector<RLWECiphertext> rlwe_prime(d_G0);
        std::vector<uint128_t> powers_Bg0(d_G0);
        uint128_t tmp_power = 1;
        for (size_t i = 0; i < d_G0; i++, tmp_power *= baseG0)
            powers_Bg0[i] = tmp_power;
        if (multithread) {
            omp_set_nested(1);  // NOTE: enable nested parallelism for FunctionalKS
#pragma omp parallel for num_threads(d_G0)
            for (size_t i = 0; i < d_G0; i++) {
                // first compute SGN*B^i/2
                // then compute MSB*B^i = (1-SGN)*B^i/2
                // the use KS to compute SGN*B^i
                NativePoly tmp_tv(polyparams, Format::COEFFICIENT, true);
                NativePoly dummy_a(polyparams, Format::COEFFICIENT, true);
                NativeInteger tmp_coeff     = powers_Bg0[i] / 2;
                NativeInteger tmp_coeff_neg = -tmp_coeff;
                tmp_tv[0]                   = tmp_coeff_neg;
                for (size_t j = 1; j < N; j++)  // MSB=0 -> -B^i/2; MSB=1 -> B^i/2
                    tmp_tv[j] = tmp_coeff;
                auto tmp_ctxt = BootstrapCtxt(
                    params, EK, ct1, std::make_shared<RLWECiphertextImpl>(std::vector<NativePoly>{dummy_a, tmp_tv}), Q,
                    true);
                LWEscheme->EvalAddConstEq(tmp_ctxt, tmp_coeff);
                rlwe_prime[i] = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(tmp_ctxt, 0)});
                rlwe_prime[i]->SetFormat(Format::EVALUATION);
            }
        }
        else {
            for (size_t i = 0; i < d_G0; i++) {  // generate (MSB==1)*B^i/2
                // first compute SGN*B^i/2
                // then compute MSB*B^i = (1-SGN)*B^i/2
                // the use KS to compute SGN*B^i
                NativePoly tmp_tv(polyparams, Format::COEFFICIENT, true);
                NativePoly dummy_a(polyparams, Format::COEFFICIENT, true);
                NativeInteger tmp_coeff     = powers_Bg0[i] / 2;
                NativeInteger tmp_coeff_neg = -tmp_coeff;
                tmp_tv[0]                   = tmp_coeff_neg;
                for (size_t j = 1; j < N; j++)  // MSB=0 -> -B^i/2; MSB=1 -> B^i/2
                    tmp_tv[j] = tmp_coeff;
                auto tmp_ctxt = BootstrapCtxt(
                    params, EK, ct1, std::make_shared<RLWECiphertextImpl>(std::vector<NativePoly>{dummy_a, tmp_tv}), Q,
                    true);
                LWEscheme->EvalAddConstEq(tmp_ctxt, tmp_coeff);
                rlwe_prime[i] = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(tmp_ctxt, 0)});
                rlwe_prime[i]->SetFormat(Format::EVALUATION);
            }
        }

        // poly x RLWE' multiplication: [MSB==1] * ((poly_neg - poly_pos) mod p) + poly_pos
        auto fLUTpos = [Q, f, deltain, deltaout, qout](NativeInteger x, NativeInteger q) -> NativeInteger {
            if (x < q / 2) {
                int64_t fval = std::round(f(x.ConvertToDouble() / deltain) * deltaout * Q.ConvertToDouble() /
                                          qout.ConvertToDouble());
                fval %= Q.ConvertToInt();
                if (fval < 0)
                    fval += Q.ConvertToInt();
                return fval;
            }
            else {
                OPENFHE_THROW(openfhe_error, "this branch should not have been reached");
            }
        };
        auto fLUTneg = [Q, f, deltain, deltaout, qout](NativeInteger x, NativeInteger q) -> NativeInteger {
            if (x >= q / 2) {
                // NOTE: use x - q here, because x represents a negative value
                int64_t fval = std::round(f((x.ConvertToDouble() - q.ConvertToDouble()) / deltain) * deltaout *
                                          Q.ConvertToDouble() / qout.ConvertToDouble());
                fval %= Q.ConvertToInt();
                if (fval < 0)
                    fval += Q.ConvertToInt();
                return fval;
            }
            else {
                OPENFHE_THROW(openfhe_error, "this branch should not have been reached");
            }
        };
        auto fLUTpos_full = [fLUTpos, Q](NativeInteger x, NativeInteger q) -> NativeInteger {
            if (x < q / 2)
                return fLUTpos(x, q);
            else
                return (Q - fLUTpos((x + q / 2).Mod(q), q)).Mod(Q);
        };
        auto fLUTneg_full = [fLUTneg, Q](NativeInteger x, NativeInteger q) -> NativeInteger {
            if (x >= q / 2)
                return fLUTneg(x, q);
            else
                return (Q - fLUTneg((x + q / 2).Mod(q), q)).Mod(Q);
        };

        NativePoly poly_pos(polyparams, Format::COEFFICIENT, true), poly_neg(polyparams, Format::COEFFICIENT, true);
        for (size_t i = 0, dN = N * 2; i < N; i++) {
            poly_pos[i] = fLUTpos_full(NativeInteger(0).ModSub(i, dN), dN);
            poly_neg[i] = fLUTneg_full(NativeInteger(0).ModSub(i, dN), dN);
        }

        auto poly_diff = poly_neg - poly_pos;

        auto decomp_poly_diff = SignedDecomp(params, poly_diff, Q.ConvertToInt(), baseG0);

        // mult
        RLWECiphertext ct_prod = InnerProduct(rlwe_prime, decomp_poly_diff);
        ct_prod->GetElements()[0].SetFormat(Format::COEFFICIENT);
        ct_prod->GetElements()[1].SetFormat(Format::COEFFICIENT);
        ct_prod->GetElements()[1] += poly_pos;
        // blind rotate
        auto ct_res = BootstrapCtxt(params, EK, ct1, ct_prod, Q, false, false);
        return LWEscheme->ModSwitch(qout, ct_res);
        // TODO: test
    }

    // now the function to evaluate is a Z_p to Z_p mapping
    usint p = LUT.size();
    if (p & 1) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p must be even");
    }
    usint half_gap = (q.ConvertToInt() + p) / (2 * p);
    if (half_gap <= beta) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p too large");
    }
    // arbitary funciton
    // Phase preprocessing
    // 1. bts([m]) -> [sgn]
    // 2. prepare packed poly of {0,1}*Q/p*B^i, for i = 0, 1, ..., d_G0 - 1
    // 3. bts([sgn]) -> multiple LWE ciphertexts encrypting (MSB==1)*Q/p*B^i
    // 4. LWE to RLWE packing (only constant term) -> RLWE' ciphertext encrypting {(MSB==1)*Q/p*B^i}
    // Phase online
    // 5. Decomp(poly) x RLWE' -> selected ciphertext [TV*]
    // 6. bts([TV*]) -> [f(m)]

    LWEscheme->EvalAddConstEq(ct1, half_gap);
    size_t d_G0 = static_cast<size_t>(std::ceil(log(Q.ConvertToDouble()) / log(double(baseG0))));
    // uint128_t Q_128 = static_cast<uint128_t>(Q.ConvertToInt()), p_128 = static_cast<uint128_t>(p),
    //           dp_128 = static_cast<uint128_t>(2 * p);
    std::vector<RLWECiphertext> rlwe_prime(d_G0);
    std::vector<uint128_t> powers_Bg0(d_G0);
    uint128_t tmp_power = 1;
    for (size_t i = 0; i < d_G0; i++, tmp_power *= baseG0)
        powers_Bg0[i] = tmp_power;
    if (multithread) {
        omp_set_nested(1);  // NOTE: enable nested parallelism for FunctionalKS
#pragma omp parallel for num_threads(d_G0)
        for (size_t i = 0; i < d_G0; i++) {
            // first compute SGN*B^i/2
            // then compute MSB*B^i = (1-SGN)*B^i/2
            // the use KS to compute SGN*B^i
            NativePoly tmp_tv(polyparams, Format::COEFFICIENT, true);
            NativePoly dummy_a(polyparams, Format::COEFFICIENT, true);
            NativeInteger tmp_coeff     = powers_Bg0[i] / 2;
            NativeInteger tmp_coeff_neg = -tmp_coeff;
            tmp_tv[0]                   = tmp_coeff_neg;
            for (size_t j = 1; j < N; j++)  // MSB=0 -> -B^i/2; MSB=1 -> B^i/2
                tmp_tv[j] = tmp_coeff;
            auto tmp_ctxt =
                BootstrapCtxt(params, EK, ct1,
                              std::make_shared<RLWECiphertextImpl>(std::vector<NativePoly>{dummy_a, tmp_tv}), Q, true);
            LWEscheme->EvalAddConstEq(tmp_ctxt, tmp_coeff);
            rlwe_prime[i] = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(tmp_ctxt, 0)});
            rlwe_prime[i]->SetFormat(Format::EVALUATION);
        }
    }
    else {
        for (size_t i = 0; i < d_G0; i++) {  // generate (MSB==1)*B^i/2
            // first compute SGN*B^i/2
            // then compute MSB*B^i = (1-SGN)*B^i/2
            // the use KS to compute SGN*B^i
            NativePoly tmp_tv(polyparams, Format::COEFFICIENT, true);
            NativePoly dummy_a(polyparams, Format::COEFFICIENT, true);
            NativeInteger tmp_coeff     = powers_Bg0[i] / 2;
            NativeInteger tmp_coeff_neg = -tmp_coeff;
            tmp_tv[0]                   = tmp_coeff_neg;
            for (size_t j = 1; j < N; j++)  // MSB=0 -> -B^i/2; MSB=1 -> B^i/2
                tmp_tv[j] = tmp_coeff;
            auto tmp_ctxt =
                BootstrapCtxt(params, EK, ct1,
                              std::make_shared<RLWECiphertextImpl>(std::vector<NativePoly>{dummy_a, tmp_tv}), Q, true);
            LWEscheme->EvalAddConstEq(tmp_ctxt, tmp_coeff);
            rlwe_prime[i] = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(tmp_ctxt, 0)});
            rlwe_prime[i]->SetFormat(Format::EVALUATION);
        }
    }
    // poly x RLWE' multiplication: [MSB==1] * ((poly_neg - poly_pos) mod 2p) + poly_pos
    auto fLUT_pos = [LUT, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 2)
            return (LUT[(x * p / q).ConvertToInt()] * Q + p / 2) / p;
        else
            return ((p - LUT[((x - q / 2) * p / q).ConvertToInt()]).Mod(p) * Q + p / 2) / p;
    };
    auto fLUT_neg = [LUT, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x >= q / 2)
            return (LUT[(x * p / q).ConvertToInt()] * Q + p / 2) / p;
        else
            return ((p - LUT[((x + q / 2) * p / q).ConvertToInt()]).Mod(p) * Q + p / 2) / p;
    };
    NativePoly poly_pos(polyparams, Format::COEFFICIENT, true), poly_neg(polyparams, Format::COEFFICIENT, true);
    for (size_t i = 0, dN = N * 2; i < N; i++) {
        poly_pos[i] = fLUT_pos(NativeInteger(0).ModSub(i, dN), dN, Q);
        poly_neg[i] = fLUT_neg(NativeInteger(0).ModSub(i, dN), dN, Q);
    }
    NativePoly poly_diff = poly_neg - poly_pos;

    auto decomp_poly_diff = SignedDecomp(params, poly_diff, Q.ConvertToInt(), baseG0);

    // mult
    RLWECiphertext ct_prod = InnerProduct(rlwe_prime, decomp_poly_diff);
    ct_prod->GetElements()[0].SetFormat(Format::COEFFICIENT);
    ct_prod->GetElements()[1].SetFormat(Format::COEFFICIENT);

    ct_prod->GetElements()[1] += poly_pos;
    // blind rotate
    return BootstrapCtxt(params, EK, ct1, ct_prod, q);
}

LWECiphertext BinFHEScheme::EvalFuncComp(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                         ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                         const NativeInteger beta, double deltain, double deltaout, NativeInteger qout,
                                         double (*f)(double m), uint32_t f_property, double shift,
                                         const RingGSWBTKey& EK_small, uint32_t baseG_small) const {
    auto LWEParams   = params->GetLWEParams();
    auto RGSWParams  = params->GetRingGSWParams();
    auto baseGMV     = RGSWParams->GetBaseGMV();
    auto N           = LWEParams->GetN();
    auto Q           = LWEParams->GetQ();
    auto polyParams  = RGSWParams->GetPolyParams();
    auto qKS         = LWEParams->GetqKS();
    bool multithread = params->GetMultithread();

    bool use_multi_value_bts = baseGMV > 0;

    auto q = ct->GetModulus().ConvertToInt();
    if (f != nullptr) {
        // f_property: 0 = none, 1 = odd, 2 = even
        bool enable_odd = f_property != 2, enable_even = f_property != 1;
        // start computation
        auto ct1 = std::make_shared<LWECiphertextImpl>(*ct);
        // LWEscheme->EvalSubConstEq(ct1, (Q + 2 * q) / (4 * q));
        LWECiphertext ct_pso, ct_pse;
        // for pso:
        // 0 -> beta, q/2-1 -> q/2-beta;
        // q/2 -> q - beta, q-1 -> q/2+beta
        // for pse:
        // 0 -> q/4+beta, q/2-1 -> 3q/4-beta
        // q/2 -> 3q/4-beta, q-1 -> q/4+beta
        double slope = (q / 2 - 2 * beta.ConvertToDouble()) / (q / 2 - 1);
        if (enable_odd) {
            auto fpso_pre = [beta, slope](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
                if (x < q / 2)
                    return uint64_t(std::round(x.ConvertToDouble() * slope + beta.ConvertToDouble()));
                else
                    return (q - uint64_t(std::round((x - q / 2).ConvertToDouble() * slope + beta.ConvertToDouble())))
                        .Mod(q);
            };
            auto ct_pso_pre    = BootstrapFunc(params, EK, ct1, fpso_pre, q);
            auto fpso_lut_half = [deltain, deltaout, beta, slope, f, qout](NativeInteger x, NativeInteger q,
                                                                           NativeInteger Q) -> NativeInteger {
                if (x >= q / 2)
                    OPENFHE_THROW(openfhe_error, "this branch should not reached");
                double xin = x.ConvertToDouble();
                xin        = (xin - beta.ConvertToDouble()) / slope;
                if (xin < 0)
                    xin = 0;
                xin += 0.5;  // compensate for the difference between pseudo-odd and real-odd functions
                int64_t fval = std::round((f(xin / deltain) - f(-xin / deltain)) / 2 * deltaout * Q.ConvertToDouble() /
                                          qout.ConvertToDouble());
                int64_t Qs   = Q.ConvertToInt();
                fval %= Qs;
                if (fval < 0)
                    fval += Qs;
                return fval;
            };
            auto fpso_lut_full = [fpso_lut_half](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
                if (x < q / 2)
                    return fpso_lut_half(x, q, Q);
                else
                    return (Q - fpso_lut_half(x - q / 2, q, Q)).Mod(Q);
            };
            ct_pso = BootstrapFunc(params, EK, ct_pso_pre, fpso_lut_full, Q, true);
        }
        if (enable_even) {
            auto fpse_pre = [beta, slope](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
                if (x < q / 2)
                    return uint64_t(
                        std::round(x.ConvertToDouble() * slope + q.ConvertToDouble() / 4 + beta.ConvertToDouble()));
                else
                    return (q - uint64_t(std::round((x - q / 2).ConvertToDouble() * slope + q.ConvertToDouble() / 4 +
                                                    beta.ConvertToDouble())))
                        .Mod(q);
            };
            auto ct_pse_pre = BootstrapFunc(params, EK, ct1, fpse_pre, q);  // in [q/4, 3q/4-1]
            LWEscheme->EvalSubConstEq(ct_pse_pre, q / 4);                   // in [0,q/2-1]
            auto fpse_lut_half = [deltain, deltaout, beta, slope, f, qout](NativeInteger x, NativeInteger q,
                                                                           NativeInteger Q) -> NativeInteger {
                if (x >= q / 2)
                    OPENFHE_THROW(openfhe_error, "this branch should not reached");
                double xin = x.ConvertToDouble();
                xin        = (xin - beta.ConvertToDouble()) / slope;
                if (xin < 0)
                    xin = 0;
                xin += 0.5;
                int64_t fval = std::round((f(xin / deltain) + f(-xin / deltain)) / 2 * deltaout * Q.ConvertToDouble() /
                                          qout.ConvertToDouble());
                int64_t Qs   = Q.ConvertToInt();
                fval %= Qs;
                if (fval < 0)
                    fval += Qs;
                return fval;
            };
            auto fpse_lut_full = [fpse_lut_half](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
                if (x < q / 2)
                    return fpse_lut_half(x, q, Q);
                else
                    return (Q - fpse_lut_half(x - q / 2, q, Q)).Mod(Q);
            };
            ct_pse = BootstrapFunc(params, EK, ct_pse_pre, fpse_lut_full, Q, true);
        }
        LWECiphertext ct_res;
        if (enable_odd) {
            ct_res = ct_pso;
            if (enable_even)
                LWEscheme->EvalAddEq(ct_res, ct_pse);
        }
        else
            ct_res = ct_pse;
        LWEscheme->EvalAddConstEq(
            ct_res, uint64_t(std::round(Q.ConvertToDouble() / qout.ConvertToDouble() * deltaout * shift)));
        // bring ct_res back to normal form
        ct_res = LWEscheme->ModSwitch(qKS, ct_res);
        ct_res = LWEscheme->KeySwitch(LWEParams, EK.KSkey, ct_res);
        return LWEscheme->ModSwitch(qout, ct_res);
        // TODO: test
    }
    // now the function to evaluate is Zp -> Zp
    size_t p          = LUT.size();
    uint64_t half_gap = (q + p) / (2 * p);
    auto ct1          = std::make_shared<LWECiphertextImpl>(*ct);
    LWEscheme->EvalAddConstEq(ct1, half_gap);  // make the error positive
    // preprocessing for pseudo-odd and pseudo-even. NOTE: Q is not used, output modulus is 2p
    auto fpso_pre = [p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        size_t x_p = (x * p / q).ConvertToInt();
        if (x < q / 2)  // (x_p + 1/2) * 2
            return NativeInteger(x_p * 2 + 1).Mod(2 * p);
        else  // (-x_p + p/2 - 1/2) * 2
            return NativeInteger((p - x_p) * 2 + p - 1).Mod(2 * p);
    };
    auto fpse_pre = [p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        size_t x_p = (x * p / q).ConvertToInt();
        if (x < q / 2)  // (x_p + p/4 + 1/2) * 2
            return NativeInteger(2 * x_p + p / 2 + 1).Mod(2 * p);
        else  // (-x_p + p/4 - 1/2) * 2
            return NativeInteger((p - x_p) * 2 + p / 2 - 1).Mod(2 * p);
    };
    LWECiphertext ct_pso_pre, ct_pse_pre;
    if (use_multi_value_bts) {
        auto rlwe_prime = PrepareRLWEPrime(params, EK, ct1, beta, 2 * p, false);  // ptxt space is 2p
        NativeVector tv1_pso(N, 2 * p), tv1_pse(N, 2 * p);
        for (size_t i = 0, dN = 2 * N; i < N; i++) {
            auto tmp   = NativeInteger(0).ModSub(i, dN);
            tv1_pso[i] = fpso_pre(tmp, dN, 2 * p);
            tv1_pse[i] = fpse_pre(tmp, dN, 2 * p);
        }
        // tv1_pso = tv1_pso - tv1_pso.ShiftRightNegacyclic(1);
        // tv1_pse = tv1_pse - tv1_pse.ShiftRightNegacyclic(1);
        tv1_pso = ComputeTV1(tv1_pso);
        tv1_pse = ComputeTV1(tv1_pse);
        tv1_pso.SetModulus(Q);
        tv1_pse.SetModulus(Q);
        NativePoly poly_pso(polyParams), poly_pse(polyParams);
        poly_pso.SetValues(tv1_pso, Format::COEFFICIENT);
        poly_pse.SetValues(tv1_pse, Format::COEFFICIENT);

        auto acc_pso = InnerProduct(rlwe_prime, SignedDecomp(params, poly_pso, 4 * p, baseGMV)),  // ptxt space is 2p
            acc_pse  = InnerProduct(rlwe_prime, SignedDecomp(params, poly_pse, 4 * p, baseGMV));
        ct_pso_pre   = ExtractACC(acc_pso);
        ct_pse_pre   = ExtractACC(acc_pse);
    }
    else {
        if (multithread) {
#pragma omp parallel for num_threads(2)
            for (size_t i = 0; i < 2; i++) {
                if (i == 0)
                    ct_pso_pre = BootstrapFunc(params, EK, ct1, fpso_pre, 2 * p, true);
                else
                    ct_pse_pre = BootstrapFunc(params, EK, ct1, fpse_pre, 2 * p, true);
            }
        }
        else {
            ct_pso_pre = BootstrapFunc(params, EK, ct1, fpso_pre, 2 * p, true);
            ct_pse_pre = BootstrapFunc(params, EK, ct1, fpse_pre, 2 * p, true);
        }
    }
    // convert back to mod p
    LWEscheme->EvalSubConstEq(ct_pso_pre, (Q + p) / (2 * p));          // -1/2 mod p
    LWEscheme->EvalSubConstEq(ct_pse_pre, Q / 4 + (Q + p) / (2 * p));  // -(p/4+1/2) mod p
    // MS and KS
    ct_pso_pre =
        LWEscheme->ModSwitch(2 * N, LWEscheme->KeySwitch(LWEParams, EK.KSkey, LWEscheme->ModSwitch(qKS, ct_pso_pre)));
    ct_pse_pre =
        LWEscheme->ModSwitch(2 * N, LWEscheme->KeySwitch(LWEParams, EK.KSkey, LWEscheme->ModSwitch(qKS, ct_pse_pre)));
    LWEscheme->EvalAddConstEq(ct_pso_pre, half_gap);
    LWEscheme->EvalAddConstEq(ct_pse_pre, half_gap);
    // now the pre-pso and pre-pse ctxts are ready, prepare for actual LUT.
    // NOTE: the actual LUT is also modulo 2p
    auto fLUT_pso = [LUT, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        // (f(i) - f(p-1-i)) / 2
        uint32_t x_p = (x * p / q).ConvertToInt();
        if (x < q / 2)
            return LUT[x_p].ModSubFast(LUT[p - 1 - x_p], 2 * p);
        else
            return LUT[p - 1 - (x_p - p / 2)].ModSubFast(LUT[x_p - p / 2], 2 * p);
    };
    auto fLUT_pse = [LUT, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        // (f(i) + f(p-1-i)) / 2
        uint32_t x_p = (x * p / q).ConvertToInt();
        if (x < q / 2)
            return LUT[x_p].ModAddFast(LUT[p - 1 - x_p], 2 * p);
        else
            return NativeInteger(0).ModSubFast(LUT[x_p - p / 2].ModAddFast(LUT[p - 1 - (x_p - p / 2)], 2 * p), 2 * p);
    };
    auto baseG_bak = RGSWParams->GetBaseG();
    RGSWParams->Change_BaseG(baseG_small);
    LWECiphertext ct_pso, ct_pse;
    if (multithread) {
#pragma omp parallel for num_threads(2)
        for (size_t i = 0; i < 2; i++) {
            if (i == 0)
                ct_pso = BootstrapFunc(params, EK_small, ct_pso_pre, fLUT_pso, 2 * p, true);
            else
                ct_pse = BootstrapFunc(params, EK_small, ct_pse_pre, fLUT_pse, 2 * p, true);
        }
    }
    else {
        ct_pso = BootstrapFunc(params, EK_small, ct_pso_pre, fLUT_pso, 2 * p, true);
        ct_pse = BootstrapFunc(params, EK_small, ct_pse_pre, fLUT_pse, 2 * p, true);
    }
    LWEscheme->EvalAddEq(ct_pso, ct_pse);
    auto ct_res = LWEscheme->ModSwitch(q, LWEscheme->KeySwitch(LWEParams, EK.KSkey, LWEscheme->ModSwitch(qKS, ct_pso)));
    RGSWParams->Change_BaseG(baseG_bak);
    return ct_res;
}

// 2 pieces
LWECiphertext BinFHEScheme::EvalFuncBFV(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                        ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                        const NativeInteger beta, double deltain, double deltaout, NativeInteger qout,
                                        double (*f)(double m)) const {
    auto LWEParams   = params->GetLWEParams();
    auto RGSWparams  = params->GetRingGSWParams();
    auto Q           = LWEParams->GetQ();
    auto N           = LWEParams->GetN();
    auto qKS         = LWEParams->GetqKS();
    auto baseGMV     = RGSWparams->GetBaseGMV();
    auto polyparams  = params->GetRingGSWParams()->GetPolyParams();
    bool multithread = params->GetMultithread();

    auto ct1                 = std::make_shared<LWECiphertextImpl>(*ct);
    bool use_multi_value_bts = baseGMV > 0;

    NativeInteger q = ct->GetModulus();
    if (f != nullptr) {
        OPENFHE_THROW(openfhe_error, "CLOT21 for ckks ciphertexts is not implemented");
    }

    // now the function to evaluate is a Z_p to Z_p mapping
    usint p = LUT.size();
    if (p & 1) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p must be even");
    }
    usint half_gap = (q.ConvertToInt() + p) / (2 * p);
    if (half_gap <= beta) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p too large");
    }

    LWEscheme->EvalAddConstEq(ct1, half_gap);

    // NOTE: we don't choose to output Q - LUT[xxx] for negative values, because tv1's can either be viewed modulo Q or modulo p
    //  if we output p - LUT[xxx], the value of fLUT's will lie in [0,p-1]
    //  if we output Q - LUT[xxx], the value of fLUT's will iie in [-p+1,p-1], doubling the std of noise
    // NOTE: the third param is not used, its only usage is to fit into BootstrapFunc's API
    auto fLUTpos = [LUT, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 2)
            return LUT[(x * p / q).ConvertToInt()];
        else
            return (p - LUT[((x - q / 2) * p / q).ConvertToInt()]).Mod(p);
    };
    auto fLUTneg = [LUT, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x >= q / 2)
            return LUT[(x * p / q).ConvertToInt()];
        else
            return (p - LUT[((x + q / 2) * p / q).ConvertToInt()]).Mod(p);
    };
    auto fLUTdiff = [fLUTpos, fLUTneg, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        return fLUTneg(x, q, Q).ModSubFastEq(fLUTpos(x, q, Q), p);
    };
    auto fLUTsgn = [p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        // NOTE: different from fLUTsgn in EvalFuncSelect
        if (x < q / 2)
            return 2 * p - 1;  // modulo 2p
        else
            return 1;
    };
    // evaluate MSB*(m_neg - m_pos) + m_pos = MSB*m_diff + m_pos
    // first obtain LWE ciphertexts
    LWECiphertext ct_pos, ct_diff, ct_sgn;
    if (use_multi_value_bts) {
        auto rlwe_prime =
            PrepareRLWEPrime(params, EK, ct1, beta, 2 * p, false);  // NOTE: ptxt space is 2p (as required by sgn)

        NativeVector tv1_pos(N, 2 * p);
        NativeVector tv1_diff(N, 2 * p);
        NativeVector tv1_sgn(N, 2 * p);
        for (size_t i = 0, dN = 2 * N; i < N; i++) {
            auto tmp = NativeInteger(0).ModSub(i, dN);
            // mult by 2 to convert from Z_p to Z_2p
            tv1_pos[i]  = 2 * fLUTpos(tmp, dN, 0);
            tv1_diff[i] = 2 * fLUTdiff(tmp, dN, 0);
            // fLUTsgn is already in Z_2p
            tv1_sgn[i] = fLUTsgn(tmp, dN, 0);
        }
        // TODO: directly find the transition points rather than compute the difference? but the overhead here is negligible compared to blind rotation
        tv1_pos  = ComputeTV1(tv1_pos);
        tv1_diff = ComputeTV1(tv1_diff);
        tv1_sgn  = ComputeTV1(tv1_sgn);
        tv1_pos.SwitchModulus(Q);
        tv1_diff.SwitchModulus(Q);
        tv1_sgn.SwitchModulus(Q);
        NativePoly poly_pos(polyparams), poly_diff(polyparams), poly_sgn(polyparams);
        poly_pos.SetValues(tv1_pos, Format::COEFFICIENT);
        poly_diff.SetValues(tv1_diff, Format::COEFFICIENT);
        poly_sgn.SetValues(tv1_sgn, Format::COEFFICIENT);

        auto acc_pos = InnerProduct(rlwe_prime, SignedDecomp(params, poly_pos, 4 * p,
                                                             baseGMV)),  // NOTE: 4p here, because ptxt space is 2p
            acc_diff = InnerProduct(rlwe_prime, SignedDecomp(params, poly_diff, 4 * p, baseGMV)),
             acc_sgn = InnerProduct(rlwe_prime, SignedDecomp(params, poly_sgn, 4 * p, baseGMV));

        // extract LWE ciphertext
        ct_pos  = ExtractACC(acc_pos);
        ct_diff = ExtractACC(acc_diff);
        ct_sgn  = ExtractACC(acc_sgn);
        LWEscheme->EvalAddConstEq(ct_sgn, (Q + p) / (2 * p));  // convert (sgn mod 2p) to (msb mod p)
    }
    else {
        if (multithread) {
#pragma omp parallel for num_threads(3)
            for (size_t i = 0; i < 3; i++) {
                if (i == 0)
                    ct_pos = BootstrapFunc(params, EK, ct1, fLUTpos, p, true);
                else if (i == 1)
                    ct_diff = BootstrapFunc(params, EK, ct1, fLUTdiff, p, true);
                else
                    ct_sgn = BootstrapFunc(params, EK, ct1, fLUTsgn, 2 * p, true);
            }
        }
        else {
            ct_pos  = BootstrapFunc(params, EK, ct1, fLUTpos, p, true);
            ct_diff = BootstrapFunc(params, EK, ct1, fLUTdiff, p, true);
            ct_sgn  = BootstrapFunc(params, EK, ct1, fLUTsgn, 2 * p, true);
        }
        LWEscheme->EvalAddConstEq(ct_sgn, (Q + p) / (2 * p));
    }

    // use packing to convert to BFV ciphertexts
    RLWECiphertext rlwe_diff, rlwe_sgn;
    if (multithread) {
#pragma omp parallel for num_threads(2)
        for (size_t i = 0; i < 2; i++) {
            if (i == 0)
                rlwe_diff = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(ct_diff, 0)});
            else
                rlwe_sgn = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(ct_sgn, 0)});
        }
    }
    else {
        rlwe_diff = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(ct_diff, 0)});
        rlwe_sgn  = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(ct_sgn, 0)});
    }
    // use BFV multiplication to select
    // NOTE: put rlwe_sgn as ct1, and rlwe_diff as ct2 to get smaller noise growth
    auto prod    = BFVMult(params, EK, rlwe_sgn, rlwe_diff, p);
    auto ct_prod = ManualExtract(prod, 0);

    LWEscheme->EvalAddEq(ct_prod, ct_pos);
    // now bring the ctxt back to s,n,q
    ct_prod = LWEscheme->ModSwitch(qKS, ct_prod);
    ct_prod = LWEscheme->KeySwitch(LWEParams, EK.KSkey, ct_prod);
    return LWEscheme->ModSwitch(q, ct_prod);
}

// NOTE: copied from EvalFuncBFV
LWECiphertext BinFHEScheme::EvalFuncWoPPBS2(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                            ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                            const NativeInteger beta, double deltain, double deltaout,
                                            NativeInteger qout, double (*f)(double m)) const {
    auto LWEParams   = params->GetLWEParams();
    auto RGSWparams  = params->GetRingGSWParams();
    auto Q           = LWEParams->GetQ();
    auto N           = LWEParams->GetN();
    auto qKS         = LWEParams->GetqKS();
    auto baseGMV     = RGSWparams->GetBaseGMV();
    auto polyparams  = params->GetRingGSWParams()->GetPolyParams();
    bool multithread = params->GetMultithread();

    auto ct1                 = std::make_shared<LWECiphertextImpl>(*ct);
    bool use_multi_value_bts = baseGMV > 0;

    NativeInteger q = ct->GetModulus();
    if (f != nullptr) {
        OPENFHE_THROW(openfhe_error, "CLOT21 for ckks ciphertexts is not implemented");
    }

    // now the function to evaluate is a Z_p to Z_p mapping
    usint p = LUT.size();
    if (p & 1) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p must be even");
    }
    usint half_gap = (q.ConvertToInt() + p) / (2 * p);
    if (half_gap <= beta) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p too large");
    }

    LWEscheme->EvalAddConstEq(ct1, half_gap);

    // NOTE: we don't choose to output Q - LUT[xxx] for negative values, because tv1's can either be viewed modulo Q or modulo p
    //  if we output p - LUT[xxx], the value of fLUT's will lie in [0,p-1]
    //  if we output Q - LUT[xxx], the value of fLUT's will iie in [-p+1,p-1], doubling the std of noise
    // NOTE: the third param is not used, its only usage is to fit into BootstrapFunc's API
    auto fLUTpos = [LUT, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 2)
            return LUT[(x * p / q).ConvertToInt()];
        else
            return (p - LUT[((x - q / 2) * p / q).ConvertToInt()]).Mod(p);
    };
    auto fLUTneg = [LUT, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x >= q / 2)
            return LUT[(x * p / q).ConvertToInt()];
        else
            return (p - LUT[((x + q / 2) * p / q).ConvertToInt()]).Mod(p);
    };
    auto fLUTsgn = [p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        // NOTE: different from fLUTsgn in EvalFuncSelect
        if (x < q / 2)
            return 2 * p - 1;  // modulo 2p
        else
            return 1;
    };
    // evaluate MSB*(m_neg - m_pos) + m_pos = MSB*m_diff + m_pos
    // first obtain LWE ciphertexts
    LWECiphertext ct_pos, ct_neg, ct_sgn;
    if (use_multi_value_bts) {
        auto rlwe_prime =
            PrepareRLWEPrime(params, EK, ct1, beta, 2 * p, false);  // NOTE: ptxt space is 2p (as required by sgn)

        NativeVector tv1_pos(N, 2 * p);
        NativeVector tv1_neg(N, 2 * p);
        NativeVector tv1_sgn(N, 2 * p);
        for (size_t i = 0, dN = 2 * N; i < N; i++) {
            auto tmp = NativeInteger(0).ModSub(i, dN);
            // mult by 2 to convert from Z_p to Z_2p
            tv1_pos[i] = 2 * fLUTpos(tmp, dN, 0);
            tv1_neg[i] = 2 * fLUTneg(tmp, dN, 0);
            // fLUTsgn is already in Z_2p
            tv1_sgn[i] = fLUTsgn(tmp, dN, 0);
        }
        // TODO: directly find the transition points rather than compute the difference? but the overhead here is negligible compared to blind rotation
        tv1_pos = ComputeTV1(tv1_pos);
        tv1_neg = ComputeTV1(tv1_neg);
        tv1_sgn = ComputeTV1(tv1_sgn);
        tv1_pos.SwitchModulus(Q);
        tv1_neg.SwitchModulus(Q);
        tv1_sgn.SwitchModulus(Q);
        NativePoly poly_pos(polyparams), poly_neg(polyparams), poly_sgn(polyparams);
        poly_pos.SetValues(tv1_pos, Format::COEFFICIENT);
        poly_neg.SetValues(tv1_neg, Format::COEFFICIENT);
        poly_sgn.SetValues(tv1_sgn, Format::COEFFICIENT);

        auto acc_pos = InnerProduct(rlwe_prime, SignedDecomp(params, poly_pos, 4 * p,
                                                             baseGMV)),  // NOTE: 4p here, because ptxt space is 2p
            acc_neg  = InnerProduct(rlwe_prime, SignedDecomp(params, poly_neg, 4 * p, baseGMV)),
             acc_sgn = InnerProduct(rlwe_prime, SignedDecomp(params, poly_sgn, 4 * p, baseGMV));

        // extract LWE ciphertext
        ct_pos = ExtractACC(acc_pos);
        ct_neg = ExtractACC(acc_neg);
        ct_sgn = ExtractACC(acc_sgn);
        LWEscheme->EvalAddConstEq(ct_sgn, (Q + p) / (2 * p));  // convert (sgn mod 2p) to (msb mod p)
    }
    else {
        if (multithread) {
#pragma omp parallel for num_threads(3)
            for (size_t i = 0; i < 3; i++) {
                if (i == 0)
                    ct_pos = BootstrapFunc(params, EK, ct1, fLUTpos, p, true);
                else if (i == 1)
                    ct_neg = BootstrapFunc(params, EK, ct1, fLUTneg, p, true);
                else
                    ct_sgn = BootstrapFunc(params, EK, ct1, fLUTsgn, 2 * p, true);
            }
        }
        else {
            ct_pos = BootstrapFunc(params, EK, ct1, fLUTpos, p, true);
            ct_neg = BootstrapFunc(params, EK, ct1, fLUTneg, p, true);
            ct_sgn = BootstrapFunc(params, EK, ct1, fLUTsgn, 2 * p, true);
        }
        LWEscheme->EvalAddConstEq(ct_sgn, (Q + p) / (2 * p));
    }

    // use packing to convert to BFV ciphertexts
    RLWECiphertext rlwe_pos, rlwe_neg, rlwe_sgn;
    if (multithread) {
#pragma omp parallel for num_threads(3)
        for (size_t i = 0; i < 3; i++) {
            if (i == 0)
                rlwe_pos = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(ct_pos, 0)});
            else if (i == 1)
                rlwe_neg = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(ct_neg, 0)});
            else
                rlwe_sgn = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(ct_sgn, 0)});
        }
    }
    else {
        rlwe_pos = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(ct_pos, 0)});
        rlwe_neg = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(ct_neg, 0)});
        rlwe_sgn = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(ct_sgn, 0)});
    }
    // use BFV multiplication to select
    // NOTE: put rlwe_sgn as ct1, and rlwe_diff as ct2 to get smaller noise growth
    auto prod = BFVMult(params, EK, rlwe_sgn, rlwe_neg, p);
    // obtain (Q/p - MSB) and mult with rlwe_pos
    rlwe_sgn->GetElements()[0] = -rlwe_sgn->GetElements()[0];
    rlwe_sgn->GetElements()[1] = -rlwe_sgn->GetElements()[1];
    rlwe_sgn->GetElements()[1][0].ModAddFastEq((Q + p / 2) / p, Q);
    auto prod_pos = BFVMult(params, EK, rlwe_sgn, rlwe_pos, p);
    auto ct_prod  = ManualExtract(prod, 0);
    LWEscheme->EvalAddEq(ct_prod, ManualExtract(prod_pos, 0));
    // now bring the ctxt back to s,n,q
    ct_prod = LWEscheme->ModSwitch(qKS, ct_prod);
    ct_prod = LWEscheme->KeySwitch(LWEParams, EK.KSkey, ct_prod);
    return LWEscheme->ModSwitch(q, ct_prod);
}

// NOTE: copied from EvalFuncBFV
LWECiphertext BinFHEScheme::EvalFuncWoPPBS1(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                            ConstLWECiphertext ct, const std::vector<NativeInteger>& LUT,
                                            const NativeInteger beta, double deltain, double deltaout,
                                            NativeInteger qout, double (*f)(double m)) const {
    auto LWEParams   = params->GetLWEParams();
    auto RGSWparams  = params->GetRingGSWParams();
    auto Q           = LWEParams->GetQ();
    auto N           = LWEParams->GetN();
    auto qKS         = LWEParams->GetqKS();
    auto baseGMV     = RGSWparams->GetBaseGMV();
    auto polyparams  = params->GetRingGSWParams()->GetPolyParams();
    bool multithread = params->GetMultithread();

    auto ct1                 = std::make_shared<LWECiphertextImpl>(*ct);
    bool use_multi_value_bts = baseGMV > 0;

    NativeInteger q = ct->GetModulus();
    if (f != nullptr) {
        OPENFHE_THROW(openfhe_error, "CLOT21 for ckks ciphertexts is not implemented");
    }

    // now the function to evaluate is a Z_p to Z_p mapping
    usint p = LUT.size();
    if (p & 1) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p must be even");
    }
    usint half_gap = (q.ConvertToInt() + p) / (2 * p);
    if (half_gap <= beta) {
        OPENFHE_THROW(openfhe_error, "plaintext modulus p too large");
    }

    LWEscheme->EvalAddConstEq(ct1, half_gap);
    auto dq = q << 1;
    ct1->SetModulus(dq);

    // NOTE: the third param is not used, its only usage is to fit into BootstrapFunc's API
    auto fLUT = [LUT, p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 2)
            return LUT[(x * 2 * p / q).ConvertToInt()];
        else
            return (p - LUT[((x - q / 2) * 2 * p / q).ConvertToInt()]).Mod(p);
    };
    auto fLUTsgn = [p](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 2)
            return 1;  // modulo p
        else
            return p - 1;
    };
    // first obtain LWE ciphertexts
    LWECiphertext ct_lut, ct_sgn;
    if (use_multi_value_bts) {
        auto rlwe_prime =
            PrepareRLWEPrime(params, EK, ct1, beta, p, false);  // NOTE: ptxt space is 2p (as required by sgn)

        NativeVector tv1_lut(N, p);
        NativeVector tv1_sgn(N, p);
        for (size_t i = 0, dN = 2 * N; i < N; i++) {
            auto tmp   = NativeInteger(0).ModSub(i, dN);
            tv1_lut[i] = fLUT(tmp, dN, 0);
            tv1_sgn[i] = fLUTsgn(tmp, dN, 0);
        }
        // TODO: directly find the transition points rather than compute the difference? but the overhead here is negligible compared to blind rotation
        tv1_lut = ComputeTV1(tv1_lut);
        tv1_sgn = ComputeTV1(tv1_sgn);
        tv1_lut.SwitchModulus(Q);
        tv1_sgn.SwitchModulus(Q);
        NativePoly poly_lut(polyparams), poly_sgn(polyparams);
        poly_lut.SetValues(tv1_lut, Format::COEFFICIENT);
        poly_sgn.SetValues(tv1_sgn, Format::COEFFICIENT);

        auto acc_lut = InnerProduct(rlwe_prime, SignedDecomp(params, poly_lut, 2 * p, baseGMV)),
             acc_sgn = InnerProduct(rlwe_prime, SignedDecomp(params, poly_sgn, 2 * p, baseGMV));

        // extract LWE ciphertext
        ct_lut = ExtractACC(acc_lut);
        ct_sgn = ExtractACC(acc_sgn);
    }
    else {
        if (multithread) {
#pragma omp parallel for num_threads(2)
            for (size_t i = 0; i < 2; i++) {
                if (i == 0)
                    ct_lut = BootstrapFunc(params, EK, ct1, fLUT, p, true);
                else
                    ct_sgn = BootstrapFunc(params, EK, ct1, fLUTsgn, p, true);
            }
        }
        else {
            ct_lut = BootstrapFunc(params, EK, ct1, fLUT, p, true);
            ct_sgn = BootstrapFunc(params, EK, ct1, fLUTsgn, p, true);
        }
    }

    // use packing to convert to BFV ciphertexts
    RLWECiphertext rlwe_lut, rlwe_sgn;
    if (multithread) {
#pragma omp parallel for num_threads(2)
        for (size_t i = 0; i < 2; i++) {
            if (i == 0)
                rlwe_lut = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(ct_lut, 0)});
            else
                rlwe_sgn = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(ct_sgn, 0)});
        }
    }
    else {
        rlwe_lut = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(ct_lut, 0)});
        rlwe_sgn = FunctionalKeySwitch(params, EK.PKkey_const, 1, {std::make_pair(ct_sgn, 0)});
    }
    // use BFV multiplication to select
    // NOTE: put rlwe_sgn as ct1, and rlwe_diff as ct2 to get smaller noise growth
    auto prod    = BFVMult(params, EK, rlwe_sgn, rlwe_lut, p);
    auto ct_prod = ManualExtract(prod, 0);
    // now bring the ctxt back to s,n,q
    ct_prod = LWEscheme->ModSwitch(qKS, ct_prod);
    ct_prod = LWEscheme->KeySwitch(LWEParams, EK.KSkey, ct_prod);
    return LWEscheme->ModSwitch(q, ct_prod);
}

LWECiphertext BinFHEScheme::EvalReLU(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK_sgn,
                                     uint32_t baseG_sgn, const RingGSWBTKey& EK_sel, uint32_t baseG_sel,
                                     ConstLWECiphertext ct, ConstLWECiphertext ct_msd, size_t beta) const {
    auto LWEparams  = params->GetLWEParams();
    auto RGSWparams = params->GetRingGSWParams();
    auto N          = LWEparams->GetN();

    auto baseG_bak = RGSWparams->GetBaseG();

    auto ct1 = std::make_shared<LWECiphertextImpl>(*ct_msd);
    LWEscheme->EvalAddConstEq(ct1, beta);  // add half_gap to make error positive
    auto fLUTsgn = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 2)
            return Q / 8;
        else
            return Q - Q / 8;
    };
    RGSWparams->Change_BaseG(baseG_sgn);
    auto ct_sgn = BootstrapFunc(params, EK_sgn, ct1, fLUTsgn, 2 * N);
    // NOTE: use trans PKkey here
    auto packed = FunctionalKeySwitch(params, EK_sgn.PKKey_half_trans, N / 2, {std::make_pair(ct, 3 * N / 2 + 1)});
    RGSWparams->Change_BaseG(baseG_sel);
    auto ct_res = BootstrapCtxt(params, EK_sel, ct_sgn, packed, 0, false, false);  // return modulus in q_ks

    RGSWparams->Change_BaseG(baseG_bak);
    return ct_res;
}
// Evaluate Homomorphic Flooring
LWECiphertext BinFHEScheme::EvalFloor(const std::shared_ptr<BinFHECryptoParams>& params, const RingGSWBTKey& EK,
                                      ConstLWECiphertext& ct, const NativeInteger& beta, uint32_t roundbits) const {
    const auto& LWEParams = params->GetLWEParams();
    NativeInteger q{roundbits == 0 ? LWEParams->Getq() : beta * (1 << (roundbits + 1))};
    NativeInteger mod{ct->GetModulus()};

    auto ct1 = std::make_shared<LWECiphertextImpl>(*ct);
    LWEscheme->EvalAddConstEq(ct1, beta);

    auto ct1Modq = std::make_shared<LWECiphertextImpl>(*ct1);
    ct1Modq->SetModulus(q);
    // this is 1/4q_small or -1/4q_small mod q
    auto f1 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < (q >> 1))
            return Q - (q >> 2);
        else
            return (q >> 2);
    };
    auto ct2 = BootstrapFunc(params, EK, ct1Modq, f1, mod);
    LWEscheme->EvalSubEq(ct1, ct2);

    auto ct2Modq = std::make_shared<LWECiphertextImpl>(*ct1);
    ct2Modq->SetModulus(q);

    // now the input is only within the range [0, q/2)
    auto f2 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < (q >> 2))
            return Q - (q >> 1) - x;
        else if (((q >> 2) <= x) && (x < 3 * (q >> 2)))
            return x;
        else
            return Q + (q >> 1) - x;
    };
    auto ct3 = BootstrapFunc(params, EK, ct2Modq, f2, mod);
    LWEscheme->EvalSubEq(ct1, ct3);

    return ct1;
}

// Evaluate large-precision sign
LWECiphertext BinFHEScheme::EvalSign(const std::shared_ptr<BinFHECryptoParams>& params,
                                     const std::map<uint32_t, RingGSWBTKey>& EKs, ConstLWECiphertext& ct,
                                     const NativeInteger& beta, bool schemeSwitch) const {
    auto mod{ct->GetModulus()};
    const auto& LWEParams = params->GetLWEParams();
    auto q{LWEParams->Getq()};
    if (mod <= q) {
        std::string errMsg =
            "ERROR: EvalSign is only for large precision. For small precision, please use bootstrapping directly";
        OPENFHE_THROW(errMsg);
    }

    const auto& RGSWParams = params->GetRingGSWParams();
    const auto curBase     = RGSWParams->GetBaseG();
    auto search            = EKs.find(curBase);
    if (search == EKs.end()) {
        std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
        OPENFHE_THROW(errMsg);
    }
    RingGSWBTKey curEK(search->second);

    auto cttmp = std::make_shared<LWECiphertextImpl>(*ct);
    while (mod > q) {
        cttmp = EvalFloor(params, curEK, cttmp, beta);
        // round Q to 2betaQ/q
        //  mod   = mod / q * 2 * beta;
        mod   = (mod << 1) * beta / q;
        cttmp = LWEscheme->ModSwitch(mod, cttmp);

        // if dynamic
        if (EKs.size() > 1) {  // if dynamic
            // TODO: use GetMSB()?
            uint32_t binLog = static_cast<uint32_t>(ceil(GetMSB(mod.ConvertToInt()) - 1));
            uint32_t base{0};
            if (binLog <= static_cast<uint32_t>(17))
                base = static_cast<uint32_t>(1) << 27;
            else if (binLog <= static_cast<uint32_t>(26))
                base = static_cast<uint32_t>(1) << 18;

            if (0 != base) {  // if base is to change ...
                RGSWParams->Change_BaseG(base);

                auto search = EKs.find(base);
                if (search == EKs.end()) {
                    std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
                    OPENFHE_THROW(errMsg);
                }
                curEK = search->second;
            }
        }
    }
    LWEscheme->EvalAddConstEq(cttmp, beta);

    if (!schemeSwitch) {
        // if the ended q is smaller than q, we need to change the param for the final boostrapping
        auto f3 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            return (x < q / 2) ? (Q / 4) : (Q - Q / 4);
        };
        cttmp = BootstrapFunc(params, curEK, cttmp, f3, q);  // this is 1/4q_small or -1/4q_small mod q
        LWEscheme->EvalSubConstEq(cttmp, q >> 2);
    }
    else {  // return the negated f3 and do not subtract q/4 for a more natural encoding in scheme switching
        // if the ended q is smaller than q, we need to change the param for the final boostrapping
        auto f3 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
            return (x < q / 2) ? (Q - Q / 4) : (Q / 4);
        };
        cttmp = BootstrapFunc(params, curEK, cttmp, f3, q);  // this is 1/4q_small or -1/4q_small mod q
    }
    RGSWParams->Change_BaseG(curBase);
    return cttmp;
}

std::vector<LWECiphertext> BinFHEScheme::EvalDecomp(const std::shared_ptr<BinFHECryptoParams> params,
                                                    const std::map<uint32_t, RingGSWBTKey>& EKs, ConstLWECiphertext ct,
                                                    const NativeInteger beta, bool CKKS) const {
    auto mod         = ct->GetModulus();
    auto& LWEParams  = params->GetLWEParams();
    auto& RGSWParams = params->GetRingGSWParams();

    NativeInteger q = LWEParams->Getq();
    if (mod <= q) {
        std::string errMsg =
            "ERROR: EvalDecomp is only for large precision. For small precision, please use bootstrapping directly";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    const auto curBase = RGSWParams->GetBaseG();
    auto search        = EKs.find(curBase);
    if (search == EKs.end()) {
        std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
        OPENFHE_THROW(openfhe_error, errMsg);
    }
    RingGSWBTKey curEK(search->second);

    auto cttmp = std::make_shared<LWECiphertextImpl>(*ct);
    std::vector<LWECiphertext> ret;
    while (mod > q) {
        auto ctq = std::make_shared<LWECiphertextImpl>(*cttmp);
        ctq->SetModulus(q);
        ret.push_back(std::move(ctq));

        // Floor the input sequentially to obtain the most significant bit
        if (CKKS) {  // CKKS only affects the 1st iteration
            cttmp = EvalFloor(params, curEK, cttmp, 0);
            CKKS  = false;
        }
        else
            cttmp = EvalFloor(params, curEK, cttmp, beta);
        mod = mod / q * 2 * beta;
        // round Q to 2betaQ/q
        cttmp = LWEscheme->ModSwitch(mod, cttmp);

        if (EKs.size() > 1) {  // if dynamic
            uint32_t binLog = static_cast<uint32_t>(ceil(log2(mod.ConvertToInt())));
            uint32_t base   = 0;
            if (binLog < static_cast<uint32_t>(17))
                base = static_cast<uint32_t>(1) << 27;
            else if (binLog < static_cast<uint32_t>(26))
                base = static_cast<uint32_t>(1) << 18;

            if (0 != base) {  // if base is to change ...
                RGSWParams->Change_BaseG(base);

                auto search = EKs.find(base);
                if (search == EKs.end()) {
                    std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
                    OPENFHE_THROW(openfhe_error, errMsg);
                }
                curEK = search->second;
            }
        }
    }
    // LWEscheme->EvalAddConstEq(cttmp, beta);

    // FIXME: what are they doing here? this is decomp, not sign
    // auto f3 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
    //     return (x < q / 2) ? (Q / 4) : (Q - Q / 4);
    // };
    // cttmp = BootstrapFunc(params, curEK, cttmp, f3, q);  // this is 1/4q_small or -1/4q_small mod q
    RGSWParams->Change_BaseG(curBase);
    // LWEscheme->EvalSubConstEq(cttmp, q >> 2);
    ret.push_back(std::move(cttmp));
    return ret;
}

// alt
// Evaluate Homomorphic Flooring
// NOTE: EvalFloorAlt assumes the input ctxt in CKKS-style
LWECiphertext BinFHEScheme::EvalFloorAlt(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                         ConstLWECiphertext ct, const NativeInteger beta, uint32_t roundbits) const {
    auto& LWEParams   = params->GetLWEParams();
    NativeInteger q   = roundbits == 0 ? LWEParams->Getq() : beta * 2 * (1 << roundbits);
    NativeInteger mod = ct->GetModulus();

    auto ct1 = std::make_shared<LWECiphertextImpl>(*ct);
    LWEscheme->EvalAddConstEq(ct1, beta);  // NOTE: always add beta

    auto ct1Modq = std::make_shared<LWECiphertextImpl>(*ct1);
    ct1Modq->SetModulus(q);
    // this is 1/4q_small or -1/4q_small mod q
    auto fx = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 4)
            return Q - q / 4;
        else if (q / 2 <= x && x < q * 3 / 4)
            return q / 4;
        else
            return 0;
    };
    auto ct2 = BootstrapFunc(params, EK, ct1Modq, fx, mod);
    LWEscheme->EvalSubEq(ct1, ct2);
    LWEscheme->EvalSubConstEq(ct1, q / 8);

    auto ct2Modq = std::make_shared<LWECiphertextImpl>(*ct1);
    ct2Modq->SetModulus(q);

    // now the input is in [q/8,3q/8) U [5q/8,7q/8)
    auto f0 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 2)
            return Q - q / 4;
        else
            return q / 4;
    };
    auto ct3 = BootstrapFunc(params, EK, ct2Modq, f0, mod);
    LWEscheme->EvalSubEq(ct1, ct3);

    auto ct3Modq = std::make_shared<LWECiphertextImpl>(*ct1);
    ct3Modq->SetModulus(q);

    // now the input is only within the range [3/8q, 5q/8)
    auto f2 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 4)
            return Q - q / 2 - x;
        else if ((q / 4 <= x) && (x < 3 * q / 4))
            return x;
        else
            return Q + q / 2 - x;
    };
    auto ct4 = BootstrapFunc(params, EK, ct3Modq, f2, mod);
    LWEscheme->EvalSubEq(ct1, ct4);

    return ct1;
}


// Evaluate large-precision sign
LWECiphertext BinFHEScheme::EvalSignAlt(const std::shared_ptr<BinFHECryptoParams> params,
                                        const std::map<uint32_t, RingGSWBTKey>& EKs, ConstLWECiphertext ct,
                                        const NativeInteger beta, bool fast, bool CKKS) const {
    auto mod         = ct->GetModulus();
    auto& LWEParams  = params->GetLWEParams();
    auto& RGSWParams = params->GetRingGSWParams();

    NativeInteger q = LWEParams->Getq();

    if (mod <= q) {
        std::string errMsg =
            "ERROR: EvalSign is only for large precision. For small precision, please use bootstrapping directly";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    const auto curBase = RGSWParams->GetBaseG();
    auto search        = EKs.find(curBase);
    if (search == EKs.end()) {
        std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
        OPENFHE_THROW(openfhe_error, errMsg);
    }
    RingGSWBTKey curEK(search->second);

    // add initial beta to ct iff CKKS is false
    auto cttmp = std::make_shared<LWECiphertextImpl>(*ct);
    if (!CKKS)
        LWEscheme->EvalAddConstEq(cttmp, beta);
    bool first_iter = true;
    while (mod > q) {
        if (first_iter)  // first iter always operates on CKKS-like ctxt
            cttmp = EvalFloorAlt(params, curEK, cttmp, beta);
        else if (!fast) {
            LWEscheme->EvalAddConstEq(cttmp, beta / 2);  // alpha = 2^7 = beta
            cttmp = EvalFloorAlt(params, curEK, cttmp, beta);
        }
        else {                                       // fast
            LWEscheme->EvalAddConstEq(cttmp, beta);  // alpha = 2^8 = 2 beta
            cttmp = EvalFloor(params, curEK, cttmp, beta);
        }
        // if fast is true, we cannot reduce 5 bits at first iter, otherwise the noise will be too large for HomFloor. so we reduce 4 bits per iter
        if (fast)
            mod = mod / q * 2 * beta;  // 4 bits per iter
        else
            mod = mod / q * beta;  // 5 bits per iter
        // round Q to mod
        cttmp      = LWEscheme->ModSwitch(mod, cttmp);
        first_iter = false;

        if (EKs.size() > 1) {  // if dynamic
            uint32_t binLog = static_cast<uint32_t>(ceil(log2(mod.ConvertToInt())));
            uint32_t base   = 0;
            if (binLog <= static_cast<uint32_t>(17))
                base = static_cast<uint32_t>(1) << 27;
            else if (binLog <= static_cast<uint32_t>(26))
                base = static_cast<uint32_t>(1) << 18;

            if (0 != base) {  // if base is to change ...
                RGSWParams->Change_BaseG(base);

                auto search = EKs.find(base);
                if (search == EKs.end()) {
                    std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
                    OPENFHE_THROW(openfhe_error, errMsg);
                }
                curEK = search->second;
            }
        }
    }
    if (fast)
        LWEscheme->EvalAddConstEq(cttmp, beta);
    else
        LWEscheme->EvalAddConstEq(cttmp, beta / 2);

    // if the ended q is smaller than q, we need to change the param for the final boostrapping
    auto f3 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        return (x < q / 2) ? (Q / 4) : (Q - Q / 4);
    };
    cttmp = BootstrapFunc(params, curEK, cttmp, f3, q);  // this is 1/4q_small or -1/4q_small mod q
    RGSWParams->Change_BaseG(curBase);
    LWEscheme->EvalSubConstEq(cttmp, q >> 2);
    return cttmp;
}

// Evaluate Ciphertext Decomposition
std::vector<LWECiphertext> BinFHEScheme::EvalDecompAlt(const std::shared_ptr<BinFHECryptoParams> params,
                                                       const std::map<uint32_t, RingGSWBTKey>& EKs,
                                                       ConstLWECiphertext ct, const NativeInteger beta,
                                                       bool CKKS) const {
    auto mod         = ct->GetModulus();
    auto& LWEParams  = params->GetLWEParams();
    auto& RGSWParams = params->GetRingGSWParams();

    NativeInteger q = LWEParams->Getq();
    if (mod <= q) {
        std::string errMsg =
            "ERROR: EvalDecomp is only for large precision. For small precision, please use bootstrapping directly";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    const auto curBase = RGSWParams->GetBaseG();
    auto search        = EKs.find(curBase);
    if (search == EKs.end()) {
        std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
        OPENFHE_THROW(openfhe_error, errMsg);
    }
    RingGSWBTKey curEK(search->second);

    auto cttmp = std::make_shared<LWECiphertextImpl>(*ct);
    std::vector<LWECiphertext> ret;
    while (mod > q) {
        auto ctq = std::make_shared<LWECiphertextImpl>(*cttmp);
        ctq->SetModulus(q);
        ret.push_back(std::move(ctq));

        // Floor the input sequentially to obtain the most significant bit
        if (CKKS) {
            cttmp = EvalFloorAlt(params, curEK, cttmp, 0);
            CKKS  = false;
        }
        else
            cttmp = EvalFloorAlt(params, curEK, cttmp, beta);
        mod = mod / 32;  // 5 bits per iter
        // round Q to mod
        cttmp = LWEscheme->ModSwitch(mod, cttmp);

        if (EKs.size() > 1) {  // if dynamic
            uint32_t binLog = static_cast<uint32_t>(ceil(log2(mod.ConvertToInt())));
            uint32_t base   = 0;
            if (binLog < static_cast<uint32_t>(20))
                base = static_cast<uint32_t>(1) << 27;
            else if (binLog < static_cast<uint32_t>(28))
                base = static_cast<uint32_t>(1) << 18;

            if (0 != base) {  // if base is to change ...
                RGSWParams->Change_BaseG(base);

                auto search = EKs.find(base);
                if (search == EKs.end()) {
                    std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
                    OPENFHE_THROW(openfhe_error, errMsg);
                }
                curEK = search->second;
            }
        }
    }
    // LWEscheme->EvalAddConstEq(cttmp, beta);

    // auto f3 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
    //     return (x < q / 2) ? (Q / 4) : (Q - Q / 4);
    // };
    // cttmp = BootstrapFunc(params, curEK, cttmp, f3, q);  // this is 1/4q_small or -1/4q_small mod q
    RGSWParams->Change_BaseG(curBase);
    // LWEscheme->EvalSubConstEq(cttmp, q >> 2);
    ret.push_back(std::move(cttmp));
    return ret;
}

// new

// Evaluate Homomorphic Flooring
LWECiphertext BinFHEScheme::EvalFloorNew(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                         ConstLWECiphertext ct, const NativeInteger beta, uint32_t roundbits) const {
    auto& LWEParams   = params->GetLWEParams();
    NativeInteger q   = roundbits == 0 ? LWEParams->Getq() : beta * 2 * (1 << roundbits);
    NativeInteger mod = ct->GetModulus();

    auto ct1 = std::make_shared<LWECiphertextImpl>(*ct);
    LWEscheme->EvalAddConstEq(ct1, beta);

    auto ct1Modq = std::make_shared<LWECiphertextImpl>(*ct1);
    ct1Modq->SetModulus(q);
    // this is 1/4q_small or -1/4q_small mod q
    auto f1 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 2)
            return Q - q / 4;
        else
            return q / 4;
    };
    auto ct2 = BootstrapFunc(params, EK, ct1Modq, f1, mod);
    LWEscheme->EvalSubEq(ct1, ct2);
    // now the lower q of ct1 is centered at q/2 with error = e_bt
    // re-center at 0 by subtracting q/2
    LWEscheme->EvalSubConstEq(ct1, q / 2);
    // old noise <= bound(e_bt) = 128
    // new noise <= q/4 + bound(e_bt) = 1024+128 < 2048 = q/2

    // auto ct2Modq = std::make_shared<LWECiphertextImpl>(*ct1);
    // ct2Modq->SetModulus(q);

    // // now the input is only within the range [0, q/2)
    // auto f2 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
    //     if (x < q / 4)
    //         return Q - q / 2 - x;
    //     else if ((q / 4 <= x) && (x < 3 * q / 4))
    //         return x;
    //     else
    //         return Q + q / 2 - x;
    // };
    // auto ct3 = BootstrapFunc(params, EK, ct2Modq, f2, mod);
    // LWEscheme->EvalSubEq(ct1, ct3);

    return ct1;
}

// Evaluate large-precision sign
LWECiphertext BinFHEScheme::EvalSignNew(const std::shared_ptr<BinFHECryptoParams> params,
                                        const std::map<uint32_t, RingGSWBTKey>& EKs, ConstLWECiphertext ct,
                                        const NativeInteger beta) const {
    auto mod         = ct->GetModulus();
    auto& LWEParams  = params->GetLWEParams();
    auto& RGSWParams = params->GetRingGSWParams();

    NativeInteger q = LWEParams->Getq();

    if (mod <= q) {
        std::string errMsg =
            "ERROR: EvalSign is only for large precision. For small precision, please use bootstrapping directly";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    const auto curBase = RGSWParams->GetBaseG();
    auto search        = EKs.find(curBase);
    if (search == EKs.end()) {
        std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
        OPENFHE_THROW(openfhe_error, errMsg);
    }
    RingGSWBTKey curEK(search->second);

    auto cttmp = std::make_shared<LWECiphertextImpl>(*ct);
    while (mod > q) {
        cttmp = EvalFloorNew(params, curEK, cttmp, beta);
        mod   = mod / q * 2 * beta;
        // round Q to 2betaQ/q
        cttmp = LWEscheme->ModSwitch(mod, cttmp);
        // old noise = 2^-4 * e_bt + e_ms, bound = 54.46
        // new noise = 2^-4 * e_bt + e_ms + 2^-4 * q/4, bound = 64 + 54.46 < 128 = beta

        if (EKs.size() > 1) {  // if dynamic
            uint32_t binLog = static_cast<uint32_t>(ceil(log2(mod.ConvertToInt())));
            uint32_t base   = 0;
            if (binLog <= static_cast<uint32_t>(20))
                base = static_cast<uint32_t>(1) << 27;
            else
                base = static_cast<uint32_t>(1) << 18;

            if (0 != base) {  // if base is to change ...
                RGSWParams->Change_BaseG(base);

                auto search = EKs.find(base);
                if (search == EKs.end()) {
                    std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
                    OPENFHE_THROW(openfhe_error, errMsg);
                }
                curEK = search->second;
            }
        }
    }
    LWEscheme->EvalAddConstEq(cttmp, beta);

    // if the ended q is smaller than q, we need to change the param for the final boostrapping
    auto f3 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        return (x < q / 2) ? (Q / 4) : (Q - Q / 4);
    };
    cttmp = BootstrapFunc(params, curEK, cttmp, f3, q);  // this is 1/4q_small or -1/4q_small mod q
    RGSWParams->Change_BaseG(curBase);
    LWEscheme->EvalSubConstEq(cttmp, q >> 2);
    return cttmp;
}

// Evaluate Ciphertext Decomposition
std::vector<LWECiphertext> BinFHEScheme::EvalDecompNew(const std::shared_ptr<BinFHECryptoParams> params,
                                                       const std::map<uint32_t, RingGSWBTKey>& EKs,
                                                       ConstLWECiphertext ct, const NativeInteger beta,
                                                       bool CKKS) const {
    auto mod         = ct->GetModulus();
    auto& LWEParams  = params->GetLWEParams();
    auto& RGSWParams = params->GetRingGSWParams();

    NativeInteger q = LWEParams->Getq();
    if (mod <= q) {
        std::string errMsg =
            "ERROR: EvalDecomp is only for large precision. For small precision, please use bootstrapping directly";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    const auto curBase = RGSWParams->GetBaseG();
    auto search        = EKs.find(curBase);
    if (search == EKs.end()) {
        std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
        OPENFHE_THROW(openfhe_error, errMsg);
    }
    RingGSWBTKey curEK(search->second);

    auto cttmp = std::make_shared<LWECiphertextImpl>(*ct);
    std::vector<LWECiphertext> ret;
    while (mod > q) {
        auto ctq = std::make_shared<LWECiphertextImpl>(*cttmp);
        ctq->SetModulus(q);
        ret.push_back(std::move(ctq));

        // Floor the input sequentially to obtain the most significant bit
        if (CKKS) {
            cttmp = EvalFloorNew(params, curEK, cttmp, 0);
            CKKS  = false;
        }
        else
            cttmp = EvalFloorNew(params, curEK, cttmp, beta);
        mod   = mod / 16;  // 4 bits
        cttmp = LWEscheme->ModSwitch(mod, cttmp);

        if (EKs.size() > 1) {  // if dynamic
            uint32_t binLog = static_cast<uint32_t>(ceil(log2(mod.ConvertToInt())));
            uint32_t base   = 0;
            if (binLog < static_cast<uint32_t>(20))
                base = static_cast<uint32_t>(1) << 27;
            else if (binLog < static_cast<uint32_t>(29))
                base = static_cast<uint32_t>(1) << 18;

            if (0 != base) {  // if base is to change ...
                RGSWParams->Change_BaseG(base);

                auto search = EKs.find(base);
                if (search == EKs.end()) {
                    std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
                    OPENFHE_THROW(openfhe_error, errMsg);
                }
                curEK = search->second;
            }
        }
    }
    // LWEscheme->EvalAddConstEq(cttmp, beta);

    // auto f3 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
    //     return (x < q / 2) ? (Q / 4) : (Q - Q / 4);
    // };
    // cttmp = BootstrapFunc(params, curEK, cttmp, f3, q);  // this is 1/4q_small or -1/4q_small mod q
    RGSWParams->Change_BaseG(curBase);
    // LWEscheme->EvalSubConstEq(cttmp, q >> 2);
    ret.push_back(std::move(cttmp));
    return ret;
}
LWECiphertext BinFHEScheme::EvalFloorCompress(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                              ConstLWECiphertext ct, const NativeInteger beta,
                                              const NativeInteger precise_beta, uint32_t roundbits) const {
    auto& LWEParams   = params->GetLWEParams();
    NativeInteger q   = roundbits == 0 ? LWEParams->Getq() : beta * 2 * (1 << roundbits);
    NativeInteger mod = ct->GetModulus();

    auto ct1 = std::make_shared<LWECiphertextImpl>(*ct);
    LWEscheme->EvalAddConstEq(ct1, beta);

    auto ct1Modq = std::make_shared<LWECiphertextImpl>(*ct1);
    ct1Modq->SetModulus(q);
    // use COMPRESS to remove the lower bits
    double (*f_id)(double) = [](double x) -> double {
        return x;
    };
    auto ct2 =
        EvalFuncCompress(params, EK, ct1Modq, {}, precise_beta, 1, 1, mod, f_id, false);  // interpret input as unsigned
    LWEscheme->EvalSubEq(ct1, ct2);
    // now the lower bits are cleared
    return ct1;
}
LWECiphertext BinFHEScheme::EvalSignCompress(const std::shared_ptr<BinFHECryptoParams> params,
                                             const std::map<uint32_t, RingGSWBTKey>& EKs, ConstLWECiphertext ct,
                                             const NativeInteger beta, const NativeInteger precise_beta) const {
    auto mod         = ct->GetModulus();
    auto& LWEParams  = params->GetLWEParams();
    auto& RGSWParams = params->GetRingGSWParams();

    NativeInteger q = LWEParams->Getq();

    if (mod <= q) {
        std::string errMsg =
            "ERROR: EvalSign is only for large precision. For small precision, please use bootstrapping directly";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    const auto curBase = RGSWParams->GetBaseG();
    auto search        = EKs.find(curBase);
    if (search == EKs.end()) {
        std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
        OPENFHE_THROW(openfhe_error, errMsg);
    }
    RingGSWBTKey curEK(search->second);

    auto cttmp = std::make_shared<LWECiphertextImpl>(*ct);
    while (mod > q) {
        cttmp = EvalFloorCompress(params, curEK, cttmp, beta, precise_beta);
        mod   = mod / 32;  // 5 bits
        cttmp = LWEscheme->ModSwitch(mod, cttmp);

        // faster
        if (EKs.size() > 1) {  // if dynamic
            uint32_t binLog = static_cast<uint32_t>(ceil(log2(mod.ConvertToInt())));
            uint32_t base   = 0;
            if (binLog <= static_cast<uint32_t>(21))
                base = static_cast<uint32_t>(1) << 27;
            else
                base = static_cast<uint32_t>(1) << 18;

            if (0 != base) {  // if base is to change ...
                RGSWParams->Change_BaseG(base);

                auto search = EKs.find(base);
                if (search == EKs.end()) {
                    std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
                    OPENFHE_THROW(openfhe_error, errMsg);
                }
                curEK = search->second;
            }
        }
    }
    LWEscheme->EvalAddConstEq(cttmp, beta);

    // if the ended q is smaller than q, we need to change the param for the final boostrapping
    auto f3 = [](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        return (x < q / 2) ? (Q / 4) : (Q - Q / 4);
    };
    cttmp = BootstrapFunc(params, curEK, cttmp, f3, q);  // this is 1/4q_small or -1/4q_small mod q
    RGSWParams->Change_BaseG(curBase);
    LWEscheme->EvalSubConstEq(cttmp, q >> 2);
    return cttmp;
}
std::vector<LWECiphertext> BinFHEScheme::EvalDecompCompress(const std::shared_ptr<BinFHECryptoParams> params,
                                                            const std::map<uint32_t, RingGSWBTKey>& EKs,
                                                            ConstLWECiphertext ct, const NativeInteger beta,
                                                            const NativeInteger precise_beta, bool CKKS) const {
    auto mod         = ct->GetModulus();
    auto& LWEParams  = params->GetLWEParams();
    auto& RGSWParams = params->GetRingGSWParams();

    NativeInteger q = LWEParams->Getq();
    if (mod <= q) {
        std::string errMsg =
            "ERROR: EvalDecomp is only for large precision. For small precision, please use bootstrapping directly";
        OPENFHE_THROW(not_implemented_error, errMsg);
    }

    const auto curBase = RGSWParams->GetBaseG();
    auto search        = EKs.find(curBase);
    if (search == EKs.end()) {
        std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
        OPENFHE_THROW(openfhe_error, errMsg);
    }
    RingGSWBTKey curEK(search->second);

    auto cttmp = std::make_shared<LWECiphertextImpl>(*ct);
    std::vector<LWECiphertext> ret;
    while (mod > q) {
        auto ctq = std::make_shared<LWECiphertextImpl>(*cttmp);
        ctq->SetModulus(q);
        ret.push_back(std::move(ctq));

        // Floor the input sequentially to obtain the most significant bit
        if (CKKS) {
            cttmp = EvalFloorCompress(params, curEK, cttmp, 0, precise_beta);
            CKKS  = false;
        }
        else
            cttmp = EvalFloorCompress(params, curEK, cttmp, beta, precise_beta);
        mod   = mod / 32;  // 5 bits
        cttmp = LWEscheme->ModSwitch(mod, cttmp);

        if (EKs.size() > 1) {  // if dynamic
            uint32_t binLog = static_cast<uint32_t>(ceil(log2(mod.ConvertToInt())));
            uint32_t base   = 0;
            if (binLog < static_cast<uint32_t>(21))
                base = static_cast<uint32_t>(1) << 27;
            else if (binLog < static_cast<uint32_t>(30))
                base = static_cast<uint32_t>(1) << 18;

            if (0 != base) {  // if base is to change ...
                RGSWParams->Change_BaseG(base);

                auto search = EKs.find(base);
                if (search == EKs.end()) {
                    std::string errMsg("ERROR: No key [" + std::to_string(curBase) + "] found in the map");
                    OPENFHE_THROW(openfhe_error, errMsg);
                }
                curEK = search->second;
            }
        }
    }
    RGSWParams->Change_BaseG(curBase);
    ret.push_back(std::move(cttmp));
    return ret;
}
// private:

RLWECiphertext BinFHEScheme::BootstrapGateCore(const std::shared_ptr<BinFHECryptoParams>& params, BINGATE gate,
                                               ConstRingGSWACCKey& ek, ConstLWECiphertext& ct) const {
    if (ek == nullptr) {
        std::string errMsg =
            "Bootstrapping keys have not been generated. Please call BTKeyGen "
            "before calling bootstrapping.";
        OPENFHE_THROW(errMsg);
    }

    auto& LWEParams  = params->GetLWEParams();
    auto& RGSWParams = params->GetRingGSWParams();
    auto polyParams  = RGSWParams->GetPolyParams();

    // Specifies the range [q1,q2) that will be used for mapping
    NativeInteger p  = ct->GetptModulus();
    NativeInteger q  = ct->GetModulus();
    uint32_t qHalf   = q.ConvertToInt() >> 1;
    NativeInteger q1 = RGSWParams->GetGateConst()[static_cast<size_t>(gate)];
    NativeInteger q2 = q1.ModAddFast(NativeInteger(qHalf), q);

    // depending on whether the value is the range, it will be set
    // to either Q/8 or -Q/8 to match binary arithmetic
    NativeInteger Q      = LWEParams->GetQ();
    NativeInteger Q2p    = Q / NativeInteger(2 * p) + 1;
    NativeInteger Q2pNeg = Q - Q2p;

    uint32_t N = LWEParams->GetN();
    NativeVector m(N, Q);
    // Since q | (2*N), we deal with a sparse embedding of Z_Q[x]/(X^{q/2}+1) to
    // Z_Q[x]/(X^N+1)
    uint32_t factor = (2 * N / q.ConvertToInt());

    const NativeInteger& b = ct->GetB();
    for (size_t j = 0; j < qHalf; ++j) {
        NativeInteger temp = b.ModSub(j, q);
        if (q1 < q2)
            m[j * factor] = ((temp >= q1) && (temp < q2)) ? Q2pNeg : Q2p;
        else
            m[j * factor] = ((temp >= q2) && (temp < q1)) ? Q2p : Q2pNeg;
    }
    std::vector<NativePoly> res(2);
    // no need to do NTT as all coefficients of this poly are zero
    res[0] = NativePoly(polyParams, Format::EVALUATION, true);
    res[1] = NativePoly(polyParams, Format::COEFFICIENT, false);
    res[1].SetValues(std::move(m), Format::COEFFICIENT);
    res[1].SetFormat(Format::EVALUATION);

    // main accumulation computation
    // the following loop is the bottleneck of bootstrapping/binary gate
    // evaluation
    auto acc = std::make_shared<RLWECiphertextImpl>(std::move(res));
    ACCscheme->EvalAcc(RGSWParams, ek, acc, ct->GetA());
    return acc;
}

// Functions below are for large-precision sign evaluation,
// flooring, homomorphic digit decomposition, and arbitrary
// funciton evaluation, from https://eprint.iacr.org/2021/1337
template <typename Func>
RLWECiphertext BinFHEScheme::BootstrapFuncCore(const std::shared_ptr<BinFHECryptoParams>& params,
                                               ConstRingGSWACCKey& ek, ConstLWECiphertext& ct, const Func f,
                                               const NativeInteger& fmod) const {
    if (ek == nullptr) {
        std::string errMsg =
            "Bootstrapping keys have not been generated. Please call BTKeyGen before calling bootstrapping.";
        OPENFHE_THROW(errMsg);
    }

    auto& LWEParams  = params->GetLWEParams();
    auto& RGSWParams = params->GetRingGSWParams();
    auto polyParams  = RGSWParams->GetPolyParams();

    NativeInteger Q = LWEParams->GetQ();
    uint32_t N      = LWEParams->GetN();
    NativeVector m(N, Q);
    // For specific function evaluation instead of general bootstrapping
    NativeInteger ctMod    = ct->GetModulus();
    uint32_t factor        = (2 * N / ctMod.ConvertToInt());
    const NativeInteger& b = ct->GetB();
    for (size_t j = 0; j < (ctMod >> 1); ++j) {
        NativeInteger temp = b.ModSub(j, ctMod);
        m[j * factor]      = Q.ConvertToInt() / fmod.ConvertToInt() * f(temp, ctMod, fmod);
    }
    std::vector<NativePoly> res(2);
    // no need to do NTT as all coefficients of this poly are zero
    res[0] = NativePoly(polyParams, Format::EVALUATION, true);
    res[1] = NativePoly(polyParams, Format::COEFFICIENT, false);
    res[1].SetValues(std::move(m), Format::COEFFICIENT);
    res[1].SetFormat(Format::EVALUATION);

    // main accumulation computation
    // the following loop is the bottleneck of bootstrapping/binary gate
    // evaluation
    auto acc = std::make_shared<RLWECiphertextImpl>(std::move(res));
    ACCscheme->EvalAcc(RGSWParams, ek, acc, ct->GetA());
    return acc;
}

template <typename Func>
LWECiphertext BinFHEScheme::BootstrapFunc(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                          ConstLWECiphertext ct, const Func f, const NativeInteger fmod, bool raw,
                                          bool ms) const {
    auto acc = BootstrapFuncCore(params, EK.BSkey, ct, f, fmod);

    std::vector<NativePoly>& accVec = acc->GetElements();
    // the accumulator result is encrypted w.r.t. the transposed secret key
    // we can transpose "a" to get an encryption under the original secret key
    accVec[0] = accVec[0].Transpose();
    accVec[0].SetFormat(Format::COEFFICIENT);
    accVec[1].SetFormat(Format::COEFFICIENT);

    auto ctExt = std::make_shared<LWECiphertextImpl>(std::move(accVec[0].GetValues()), std::move(accVec[1][0]));
    if (raw)
        return ctExt;

    auto& LWEParams = params->GetLWEParams();
    // Modulus switching to a middle step Q'
    auto ctMS = LWEscheme->ModSwitch(LWEParams->GetqKS(), ctExt);
    // Key switching
    auto ctKS = LWEscheme->KeySwitch(LWEParams, EK.KSkey, ctMS);
    if (!ms)
        return ctKS;
    // Modulus switching
    return LWEscheme->ModSwitch(fmod, ctKS);
}

RLWECiphertext BinFHEScheme::BootstrapCtxtCore(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWACCKey ek,
                                               ConstLWECiphertext ct, ConstRLWECiphertext tv) const {
    // auto t_start = std::chrono::steady_clock::now();
    if (ek == nullptr) {
        std::string errMsg =
            "Bootstrapping keys have not been generated. Please call BTKeyGen before calling bootstrapping.";
        OPENFHE_THROW(config_error, errMsg);
    }

    auto& LWEParams  = params->GetLWEParams();
    auto& RGSWParams = params->GetRingGSWParams();
    auto polyParams  = RGSWParams->GetPolyParams();

    NativeInteger Q = LWEParams->GetQ();
    uint32_t N      = LWEParams->GetN();
    NativeVector m(N, Q);

    auto acc = std::make_shared<RLWECiphertextImpl>(*tv);
    auto b   = ct->GetB().ConvertToInt();
    for (auto& ele : acc->GetElements()) {
        // EvalAcc evaluates Tv*X^(b-as)=Tv*X^m
        ele.SetFormat(Format::COEFFICIENT);
        ele = ele.ShiftRightNegacyclic(b);
        ele.SetFormat(Format::EVALUATION);
    }
    // main accumulation computation
    // the following loop is the bottleneck of bootstrapping/binary gate
    // evaluation
    ACCscheme->EvalAcc(RGSWParams, ek, acc, ct->GetA());

    // auto t_end = std::chrono::steady_clock::now();
    // std::cout << "time for btsCtxtCore: " << (t_end - t_start).count() << " ns\n";
    return acc;
}

// bootstrap a ctxt test vector
LWECiphertext BinFHEScheme::BootstrapCtxt(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                          ConstLWECiphertext ct, ConstRLWECiphertext tv, const NativeInteger fmod,
                                          bool raw, bool ms) const {
    auto acc = BootstrapCtxtCore(params, EK.BSkey, ct, tv);

    std::vector<NativePoly>& accVec = acc->GetElements();
    // the accumulator result is encrypted w.r.t. the transposed secret key
    // we can transpose "a" to get an encryption under the original secret key
    accVec[0] = accVec[0].Transpose();
    accVec[0].SetFormat(Format::COEFFICIENT);
    accVec[1].SetFormat(Format::COEFFICIENT);

    auto ctExt = std::make_shared<LWECiphertextImpl>(std::move(accVec[0].GetValues()), std::move(accVec[1][0]));
    if (raw)
        return ctExt;
    auto& LWEParams = params->GetLWEParams();
    // Modulus switching to a middle step Q'
    auto ctMS = LWEscheme->ModSwitch(LWEParams->GetqKS(), ctExt);
    // Key switching
    auto ctKS = LWEscheme->KeySwitch(LWEParams, EK.KSkey, ctMS);
    if (!ms)
        return ctKS;
    // Modulus switching
    return LWEscheme->ModSwitch(fmod, ctKS);
}

// we don't need NTT structure here, so we view polys as vecs to avoid possible troubles
NativeVector BinFHEScheme::ModSwitch(NativeInteger q, const NativeVector& polyQ) const {
    auto length  = polyQ.GetLength();
    double ratio = q.ConvertToDouble() / polyQ.GetModulus().ConvertToDouble();
    NativeVector polyq(length, q);
    for (usint i = 0; i < length; i++) {
        polyq[i] = NativeInteger(static_cast<uint64_t>(std::floor(0.5 + polyQ[i].ConvertToDouble() * ratio))).Mod(q);
    }
    return polyq;
}

// we don't need NTT structure here, so we view polys as vecs to avoid possible troubles
void BinFHEScheme::ModSwitchInplace(NativeInteger q, NativeVector& polyQ) const {
    auto length  = polyQ.GetLength();
    double ratio = q.ConvertToDouble() / polyQ.GetModulus().ConvertToDouble();
    for (usint i = 0; i < length; i++) {
        polyQ[i] = NativeInteger(static_cast<uint64_t>(std::floor(0.5 + polyQ[i].ConvertToDouble() * ratio))).Mod(q);
    }
    polyQ.SetModulus(q);
}

RLWECiphertext BinFHEScheme::vecs_to_RLWECiphertext(std::vector<NativeVector>&& vectors,
                                                    const std::shared_ptr<ILNativeParams> params) const {
    std::vector<NativePoly> polys;
    for (auto&& ele : vectors) {
        NativePoly tmp(params);
        tmp.SetValues(std::move(ele), Format::COEFFICIENT);
        polys.emplace_back(std::move(tmp));
    }
    return std::make_shared<RLWECiphertextImpl>(polys);
}

// here we need LWE(q,N) to RLWE(Q,N) key switching, where q | 2N is very small
// generate RLWE(round(Q/qfrom * svN[i]*j*basePK^k)*(1+X+...+X^(nOnes-1))), accessed as (A[i][j][k], B[i][j][k])
RLWESwitchingKey BinFHEScheme::FunctionalKeySwitchGen(const std::shared_ptr<BinFHECryptoParams> params,
                                                      ConstLWEPrivateKey sk, const NativePoly& skNTT,
                                                      usint nOnes) const {
    // Create local copies of main variables
    auto LWEparams  = params->GetLWEParams();
    auto RGSWparams = params->GetRingGSWParams();
    // uint32_t n          = LWEparams->Getn();
    uint32_t dim_in     = sk->GetLength();
    uint32_t N          = LWEparams->GetN();
    NativeInteger qPK   = LWEparams->GetQ();
    uint32_t basePK     = RGSWparams->GetBasePK();
    NativeInteger qfrom = RGSWparams->GetQfrom();
    auto polyparams     = RGSWparams->GetPolyParams();

    // Number of digits in representing numbers mod 2N
    uint32_t digitCount = (uint32_t)std::ceil(log(qfrom.ConvertToDouble()) / log(static_cast<double>(basePK)));
    std::vector<NativeInteger> digitsKS;
    // Populate digits
    NativeInteger value = 1;
    for (size_t i = 0; i < digitCount; ++i) {
        digitsKS.push_back(value);
        value *= basePK;
    }

    NativeVector sv = sk->GetElement();
    sv.SwitchModulus(qPK);

    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(qPK);

    // auto mu = qPK.ComputeMu();

    std::vector<std::vector<std::vector<NativeVector>>> resultVecA(dim_in);
    std::vector<std::vector<std::vector<NativeVector>>> resultVecB(dim_in);

    std::cout << "i j k = " << dim_in << ", " << basePK << ", " << digitCount << '\n';

#pragma omp parallel for
    for (size_t i = 0; i < dim_in; ++i) {
        std::vector<std::vector<NativeVector>> vector1A(basePK);
        std::vector<std::vector<NativeVector>> vector1B(basePK);
        for (size_t j = 1; j < basePK; ++j) {  // NOTE: skip j = 0
            std::vector<NativeVector> vector2A(digitCount);
            std::vector<NativeVector> vector2B(digitCount);
            for (size_t k = 0; k < digitCount; ++k) {
                // NOTE: if we generate RLWE encryptions modulo Q, then rescale them down to q_ks, the rescaling error is far larger than encryption error
                // so we have to generate RLWE encryptions modulo q_ks, which requires polynomial multiplication under non-NTT-friendly modulus
                NativePoly apoly(dug, polyparams, Format::COEFFICIENT);
                // NativeVector as = PolyMult(a, svN);
                // NativeVector as = FromZZpX(NTL::MulMod(ToZZpX(a), skN_ZZp, xn_1));
                NativePoly as(polyparams, Format::COEFFICIENT);
                as.SetValues(apoly.GetValues(), Format::COEFFICIENT);
                as.SetFormat(Format::EVALUATION);
                as *= skNTT;
                as.SetFormat(Format::COEFFICIENT);

                NativeVector b = RGSWparams->GetDgg().GenerateVector(N, qPK);
                b.ModAddEq(as.GetValues());

                NativeVector a = apoly.GetValues();

                // ModSwitchInplace(qPK, a);
                // ModSwitchInplace(qPK, b);

                // message is sv[i] * j * B^k * (1+X+X^2+...+X^(nOnes-1)) * qKS / qfrom
                // NOTE: need to convert sv[i] to signed form before converting to double
                //   static_cast a negative double to unsigned integer type is UB!
                //   the implementation of ModMul uses 128 bit integer to hold the product (or Barret reduction when 128-bit integer is not available)
                //   we assume 128-bit integers are available
                auto qPK_128      = static_cast<uint128_t>(qPK.ConvertToInt()),
                     qfrom_128    = static_cast<uint128_t>(qfrom.ConvertToInt());
                uint128_t svi_128 = static_cast<uint128_t>(sv[i].ConvertToInt());
                if (svi_128 != 0 && svi_128 != 1)
                    svi_128 = static_cast<uint128_t>(-1);
                // uint64_t msg = (svi_128 * static_cast<uint128_t>(j) *
                //                     static_cast<uint128_t>(digitsKS[k].ConvertToInt()) * qPK_128 +
                //                 qfrom_128 / 2) /
                //                qfrom_128;

                uint64_t d_msg;
                if (svi_128 == 0)
                    d_msg = 0;
                else {
                    d_msg = (static_cast<uint128_t>(j) * static_cast<uint128_t>(digitsKS[k].ConvertToInt()) * qPK_128 +
                             qfrom_128 / 2) /
                            qfrom_128;
                    if (svi_128 != 1)
                        d_msg = qPK.ConvertToInt() - d_msg;
                }
                // uint64_t expected =
                //     sv[i]
                //         .ModMulFast(j * digitsKS[k], qPK, mu)
                //         .ConvertToInt();
                // if (msg != expected) {
                //     std::cout << msg << " ### " << expected << '\n';
                // }
                for (usint t = 0; t < nOnes; t++)
                    b.ModAddAtIndexEq(t, d_msg);

                vector2A[k] = std::move(a);
                vector2B[k] = std::move(b);
            }
            vector1A[j] = std::move(vector2A);
            vector1B[j] = std::move(vector2B);
        }
        resultVecA[i] = std::move(vector1A);
        resultVecB[i] = std::move(vector1B);
    }

    return std::make_shared<RLWESwitchingKeyImpl>(RLWESwitchingKeyImpl(resultVecA, resultVecB));
}

// #define KS_BENCH
#define KS_PAR_N 16
// public functional key switching from (qfrom,N) to (Q,N)
RLWECiphertext BinFHEScheme::FunctionalKeySwitch(
    const std::shared_ptr<BinFHECryptoParams> params, ConstRLWESwitchingKey K, usint nOnes,
    const std::vector<std::pair<ConstLWECiphertext, size_t>>& messages) const {
    // NOTE: key switching from LWE(q,N) to LWE(q,n) takes approximately 20ms on that server
    // but key switching takes 70ms on this server, and RLWE packing takes 220ms for each input ciphertext

    auto LWEparams      = params->GetLWEParams();
    auto RGSWparams     = params->GetRingGSWParams();
    uint32_t N          = LWEparams->GetN();
    NativeInteger qPK   = LWEparams->GetQ();
    uint32_t basePK     = RGSWparams->GetBasePK();
    NativeInteger qfrom = RGSWparams->GetQfrom();
    auto polyparams     = RGSWparams->GetPolyParams();
    uint32_t digitCount = (uint32_t)std::ceil(log(qfrom.ConvertToDouble()) / log(static_cast<double>(basePK)));
    uint32_t dim_in     = messages[0].first->GetLength();
    bool multithread = false;  // params->GetMultithread(); // XXX: multithread only controls parallelism of bootstraps

    // sanity check
    auto n_msg     = messages.size();
    auto in_length = messages[0].first->GetLength();
    for (usint i = 1; i < n_msg; i++) {
        if (messages[i].first->GetLength() != in_length)
            OPENFHE_THROW(openfhe_error, "input params do not match in input ciphertexts");
    }
    // switch ctqn_pos and ctqn_neg's modulus to 2N
    std::vector<LWECiphertext> messages_ms(n_msg);
    for (usint i = 0; i < n_msg; i++) {
        if (messages[i].first->GetModulus() != qfrom)
            messages_ms[i] = LWEscheme->ModSwitch(qfrom, messages[i].first);
        else
            messages_ms[i] = std::make_shared<LWECiphertextImpl>(*messages[i].first);
    }

    // creates empty ciphertext
    NativeVector a(N, qPK);
    NativeVector b(N, qPK);

    auto qPK_128 = static_cast<uint128_t>(qPK.ConvertToInt()), qfrom_128 = static_cast<uint128_t>(qfrom.ConvertToInt());

    std::vector<NativeVector> a_msg_par(n_msg), b_msg_par(n_msg);
    for (size_t i = 0; i < n_msg; i++) {
        a_msg_par[i] = NativeVector(N, qPK);
        b_msg_par[i] = NativeVector(N, qPK);
    }
    uint64_t max_add_count       = uint64_t(-1) / (qPK.ConvertToInt() * digitCount);  // NOTE: worst case estimation
    NativeInteger max_sub_buffer = max_add_count * qPK * digitCount;
    omp_set_nested(1);
#pragma omp parallel for num_threads(n_msg)
    for (usint i = 0; i < n_msg; i++) {  // msg[i]
        size_t cur_shift = messages[i].second % (2 * N);

        auto cur_b = messages_ms[i]->GetB();
        NativeInteger cur_b_coeff =
            static_cast<uint64_t>((static_cast<uint128_t>(cur_b.ConvertToInt()) * qPK_128 + qfrom_128 / 2) / qfrom_128);
        for (usint j = 0; j < nOnes; j++)
            b_msg_par[i][j].ModAddFastEq(cur_b_coeff, qPK);

        auto& cur_A = messages_ms[i]->GetA();
#ifdef KS_BENCH
        // 8 -> 23ms
        // 16 -> 12ms
        // 32 -> 10~20ms
        if (multithread)
            std::cout << "number of threads set to " << KS_PAR_N << '\n';
        else
            std::cout << "multithreading is disabled\n";
        auto t_start = std::chrono::steady_clock::now();
#endif
        size_t n_threads = multithread ? KS_PAR_N : 1;
        // accelerate KS using map-reduce
        std::vector<NativeVector> a_par(n_threads), b_par(n_threads);
        NativeVector init_vec(N, qPK);
        for (size_t j = 0; j < N; j++)
            init_vec[j] = max_sub_buffer;
        for (size_t par = 0; par < n_threads; par++) {  // NOTE: fast arithmetic
            a_par[par] = init_vec;
            b_par[par] = init_vec;
        }
// map
#pragma omp parallel for num_threads(n_threads)
        for (size_t par = 0; par < n_threads; par++) {
            auto j_start = par * dim_in / n_threads, j_end = (par + 1) * dim_in / n_threads;
            // for i-th message, [j,digit,k]: s[j] * digit * basePK^k
            for (size_t j = j_start, add_ctr = 1; j < j_end; ++j, ++add_ctr) {  // s[j]
                NativeInteger atmp = cur_A[j];
                for (size_t k = 0; k < digitCount; ++k, atmp /= basePK) {
                    uint64_t digit = (atmp % basePK).ConvertToInt();
                    if (digit > 0) {  // NOTE: skip when digit = 0
                        // m[i]*(1+X+X^2+...+X^(nOnes/2))*X^shift
                        a_par[par].SubEq(K->GetElementsA()[j][digit][k]);
                        b_par[par].SubEq(K->GetElementsB()[j][digit][k]);
                        // NOTE: non-modular subtraction
                    }
                }
                if (add_ctr >= max_add_count) {  // NOTE: reduce
                    add_ctr = 0;
                    a_par[par].ModReduce();
                    b_par[par].ModReduce();
                    a_par[par].AddEq(max_sub_buffer - qPK);
                    b_par[par].AddEq(max_sub_buffer - qPK);
                }
            }
        }
        // reduce
        for (size_t par = 0; par < n_threads; par++) {
            a_par[par].ModReduce();
            b_par[par].ModReduce();
            a_msg_par[i].ModAddEq(a_par[par]);
            b_msg_par[i].ModAddEq(b_par[par]);
        }
        a_msg_par[i] = a_msg_par[i].ShiftRightNegacyclic(cur_shift);
        b_msg_par[i] = b_msg_par[i].ShiftRightNegacyclic(cur_shift);
#ifdef KS_BENCH
        auto t_end = std::chrono::steady_clock::now();
        std::cout << "RLWE Packing for each message takes " << (t_end - t_start).count() << " ns\n";
#endif
    }
    for (size_t i = 0; i < n_msg; i++) {
        a.ModAddEq(a_msg_par[i]);
        b.ModAddEq(b_msg_par[i]);
    }

    return vecs_to_RLWECiphertext({std::move(a), std::move(b)}, polyparams);
}

RLWECiphertext BinFHEScheme::FunctionalKeySwitchSimple(
    const std::shared_ptr<BinFHECryptoParams> params, ConstRLWESwitchingKey K, usint nOnes,
    const std::vector<std::pair<ConstLWECiphertext, size_t>>& messages) const {
    auto LWEparams      = params->GetLWEParams();
    auto RGSWparams     = params->GetRingGSWParams();
    uint32_t N          = LWEparams->GetN();
    NativeInteger qPK   = LWEparams->GetQ();
    uint32_t basePK     = RGSWparams->GetBasePK();
    NativeInteger qfrom = RGSWparams->GetQfrom();
    auto polyparams     = RGSWparams->GetPolyParams();
    uint32_t digitCount = (uint32_t)std::ceil(log(qfrom.ConvertToDouble()) / log(static_cast<double>(basePK)));
    uint32_t dim_in     = messages[0].first->GetLength();

    // sanity check
    auto n_msg     = messages.size();
    auto in_length = messages[0].first->GetLength();
    for (usint i = 1; i < n_msg; i++) {
        if (messages[i].first->GetLength() != in_length)
            OPENFHE_THROW(openfhe_error, "input params do not match in input ciphertexts");
    }
    // switch ctqn_pos and ctqn_neg's modulus to 2N
    std::vector<LWECiphertext> messages_ms(n_msg);
    for (usint i = 0; i < n_msg; i++) {
        if (messages[i].first->GetModulus() != qfrom)
            messages_ms[i] = LWEscheme->ModSwitch(qfrom, messages[i].first);
        else
            messages_ms[i] = std::make_shared<LWECiphertextImpl>(*messages[i].first);
    }

    // creates empty ciphertext
    NativeVector a(N, qPK);
    NativeVector b(N, qPK);

    auto qPK_128 = static_cast<uint128_t>(qPK.ConvertToInt()), qfrom_128 = static_cast<uint128_t>(qfrom.ConvertToInt());

    for (usint i = 0; i < n_msg; i++) {  // msg[i]

        auto cur_b = messages_ms[i]->GetB();
        NativeInteger cur_b_coeff =
            static_cast<uint64_t>((static_cast<uint128_t>(cur_b.ConvertToInt()) * qPK_128 + qfrom_128 / 2) / qfrom_128);
        for (usint j = 0; j < nOnes; j++)
            b[j].ModAddFastEq(cur_b_coeff, qPK);

        auto& cur_A = messages_ms[i]->GetA();

        // for i-th message, [j,digit,k]: s[j] * digit * basePK^k
        for (size_t j = 0; j < dim_in; ++j) {  // s[j]
            NativeInteger atmp = cur_A[j];
            for (size_t k = 0; k < digitCount; ++k, atmp /= basePK) {
                uint64_t digit = (atmp % basePK).ConvertToInt();
                if (digit > 0) {  // NOTE: skip when digit = 0
                    // m[i]*(1+X+X^2+...+X^(nOnes/2))*X^shift
                    a.ModSubEq(K->GetElementsA()[j][digit][k]);
                    b.ModSubEq(K->GetElementsB()[j][digit][k]);
                }
            }
        }
    }

    return vecs_to_RLWECiphertext({std::move(a), std::move(b)}, polyparams);
}

// NTL::ZZ_pX BinFHEScheme::ToZZpX(const NativeVector& vec) const {
//     // NTL::ZZ_p::init(NTL::ZZ(vec.GetModulus().ConvertToInt()));
//     NTL::ZZ_pX poly;
//     auto N = vec.GetLength();
//     poly.SetLength(N);
//     for (decltype(N) i = 0; i < N; i++)
//         poly[i] = vec[i].ConvertToInt();
//     return poly;
// }

// NativeVector BinFHEScheme::FromZZpX(const NTL::ZZ_pX& poly) const {
//     auto N       = poly.rep.length();
//     auto modulus = NTL::conv<uint64_t>(NTL::ZZ_p::modulus());
//     NativeVector vec(N, modulus);
//     for (decltype(N) i = 0; i < N; i++)
//         vec[i] = NativeInteger(NTL::conv<uint64_t, NTL::ZZ_p>(poly[i])).Mod(modulus);
//     return vec;
// }

/**
 * NOTE: this function is optimized for power of 2 modulus and ternary s
*/
NativeVector BinFHEScheme::PolyMult(const NativeVector& a, const NativeVector& s) const {
    if (a.GetLength() != s.GetLength() || a.GetModulus() != s.GetModulus())
        OPENFHE_THROW(openfhe_error, "mismatched params");
    auto N       = a.GetLength();
    auto modulus = a.GetModulus();
    NativeVector ans(N, modulus);
#pragma omp parallel for
    for (usint i = 0; i < N; i++) {
        if (s[i] > 0) {  // s[i] == 1
            for (usint j = 0; j < i; j++)
                ans[j] -= a[j - i + N];
            for (usint j = i; j < N; j++)
                ans[j] += a[j - i];
        }
        else if (s[i] < 0) {  // s[i] == -1
            for (usint j = 0; j < i; j++)
                ans[j] += a[j - i + N];
            for (usint j = i; j < N; j++)
                ans[j] -= a[j - i];
        }
        // s[i] == 0
    }
    for (usint i = 0; i < N; i++)
        ans[i].ModEq(modulus);
    return ans;
}

// std::vector<LWECiphertext> BinFHEScheme::ExtractMultipleMessages(ConstLWECiphertext ct,
//                                                                  const std::vector<std::pair<size_t, size_t>>& msg_info,
//                                                                  size_t padding) const {
//     return std::vector<LWECiphertext>();
// }

LWECiphertext BinFHEScheme::EvalNegate(ConstLWECiphertext ct) const {
    auto len     = ct->GetLength();
    auto modulus = ct->GetModulus();
    NativeVector a(len, modulus);
    a.ModSubEq(ct->GetA());
    NativeInteger b = 0;
    b.ModSubFastEq(ct->GetB(), modulus);
    return std::make_shared<LWECiphertextImpl>(a, b);
}

LWECiphertext BinFHEScheme::ExtractACC(RLWECiphertext acc) const {
    std::vector<NativePoly>& accVec = acc->GetElements();
    // the accumulator result is encrypted w.r.t. the transposed secret key
    // we can transpose "a" to get an encryption under the original secret key
    accVec[0] = accVec[0].Transpose();
    accVec[0].SetFormat(Format::COEFFICIENT);
    accVec[1].SetFormat(Format::COEFFICIENT);

    auto ctExt = std::make_shared<LWECiphertextImpl>(std::move(accVec[0].GetValues()), std::move(accVec[1][0]));
    return ctExt;
}

LWECiphertext BinFHEScheme::ManualExtract(ConstRLWECiphertext acc, size_t pos) const {
    if (acc->GetElements()[0].GetFormat() != Format::COEFFICIENT ||
        acc->GetElements()[1].GetFormat() != Format::COEFFICIENT)
        OPENFHE_THROW(openfhe_error, "can only extract LWE from RLWE in coefficient format");

    auto N = acc->GetElements()[0].GetLength();
    auto Q = acc->GetElements()[0].GetModulus();
    if (pos >= N)
        OPENFHE_THROW(openfhe_error, "index out of bound");
    NativeVector a(N, Q);
    NativeInteger b = acc->GetElements()[1][pos];
    auto& poly_a    = acc->GetElements()[0];

    for (size_t i = 0; i <= pos; i++)
        a[i] = poly_a[pos - i];
    for (size_t i = pos + 1; i < N; i++)
        a[i] = NativeInteger(0).ModSubFast(poly_a[pos + N - i], Q);

    return std::make_shared<LWECiphertextImpl>(std::move(a), std::move(b));
}

std::vector<RLWECiphertext> BinFHEScheme::PrepareRLWEPrime(const std::shared_ptr<BinFHECryptoParams> params,
                                                           const RingGSWBTKey& EK, ConstLWECiphertext ct,
                                                           NativeInteger beta, size_t p, bool FDFB) const {
    auto LWEparams   = params->GetLWEParams();
    auto RGSWparams  = params->GetRingGSWParams();
    size_t baseGMV   = RGSWparams->GetBaseGMV();
    auto polyparams  = RGSWparams->GetPolyParams();
    NativeInteger Q  = LWEparams->GetQ();
    auto N           = LWEparams->GetN();
    bool multithread = params->GetMultithread();

    size_t dMV = static_cast<size_t>(std::ceil(log(double(2 * p)) / log(double(baseGMV))));

    std::vector<RLWECiphertext> rlwe_prime;
    uint128_t Q_128 = static_cast<uint128_t>(Q.ConvertToInt()), baseGMV_128 = static_cast<uint128_t>(baseGMV),
              p_128 = static_cast<uint128_t>(p), dp_128 = static_cast<uint128_t>(p * 2);
    if (!FDFB)  // non full domain, generate RLWE ciphertexts encrypting Q/2p * TV_0 * X^m * B_i
        rlwe_prime.resize(dMV);
    else
        rlwe_prime.resize(
            dMV *
            2);  // full domain, generate RLWE ciphertexts encrypting Q/2p * TV_0 * X^m * B_i and Q/2p * sgn(m) * TV_0 * X^m * B^i
    uint128_t power_128 = 1;
    std::vector<NativeInteger> powers(dMV);
    for (size_t i = 0; i < dMV; i++, power_128 *= baseGMV_128)
        powers[i] = static_cast<uint64_t>((Q_128 * power_128 + p_128) / dp_128);  // round(Q/2p * B^i)
    if (multithread) {
#pragma omp parallel for num_threads(dMV)
        for (size_t i = 0; i < dMV; i++) {
            NativePoly a(polyparams, Format::COEFFICIENT, true), b(polyparams, Format::COEFFICIENT, true);
            for (size_t j = 0; j < N; j++)
                b[j] = powers[i];
            rlwe_prime[i] = BootstrapCtxtCore(params, EK.BSkey, ct,
                                              std::make_shared<RLWECiphertextImpl>(std::vector<NativePoly>{a, b}));
        }
    }
    else {
        for (size_t i = 0; i < dMV; i++) {
            NativePoly a(polyparams, Format::COEFFICIENT, true), b(polyparams, Format::COEFFICIENT, true);
            for (size_t j = 0; j < N; j++)
                b[j] = powers[i];
            rlwe_prime[i] = BootstrapCtxtCore(params, EK.BSkey, ct,
                                              std::make_shared<RLWECiphertextImpl>(std::vector<NativePoly>{a, b}));
        }
    }
    // FIXME: the following branch is not tested
    // TODO: multithreading
    if (FDFB) {  // now generate [sgn(m) * TV_0 * X^m * B^i]:(1) generate [sgn(m) * B^i * Q/2p]. (2) use RLWE packing with nOnes = 1. (3) bootstrap by ct
        std::vector<std::pair<NativeInteger, NativeInteger>> pn_values(dMV);
        for (size_t i = 0; i < dMV; i++) {
            pn_values[i].first  = 0;
            pn_values[i].second = powers[i];  // round(Q/2p * B^i)
        }
        auto extracted = BatchSelect(params, EK, ct, beta, pn_values);  // batch select
        for (size_t i = 0; i < dMV; i++)
            rlwe_prime[dMV + i] = BootstrapCtxtCore(
                params, EK.BSkey, ct,
                FunctionalKeySwitch(params, EK.PKkey_full, N, {std::make_pair(extracted[i], 0)}));  // mult by X^m
    }
    return rlwe_prime;
}

std::vector<LWECiphertext> BinFHEScheme::BatchSelect(
    const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK, ConstLWECiphertext ct, NativeInteger beta,
    const std::vector<std::pair<NativeInteger, NativeInteger>>& pn_values) const {
    auto LWEparams   = params->GetLWEParams();
    auto RGSWparams  = params->GetRingGSWParams();
    auto N           = LWEparams->GetN();
    NativeInteger Q  = LWEparams->GetQ();
    auto polyparams  = RGSWparams->GetPolyParams();
    bool multithread = params->GetMultithread();

    // (-beta \pm beta) 0 (beta \pm beta)
    size_t batch   = (N / (4 * beta)).ConvertToInt();  // each bts can handle selection of batch pairs
    auto half_step = 2 * beta.ConvertToInt();
    auto q         = ct->GetModulus();

    size_t n_pairs = pn_values.size();
    size_t n_tv    = (n_pairs + batch - 1) / batch;
    std::vector<LWECiphertext> ans(n_pairs);

    if (n_pairs == 0)
        OPENFHE_THROW(openfhe_error, "pn_values is empty");
    if (multithread) {  // if multithreading is enabled, directly obtain results using parallel BTS
#pragma omp parallel for num_threads(n_pairs)
        for (size_t i = 0; i < n_pairs; i++) {
            auto cur_pos = pn_values[i].first, cur_neg = pn_values[i].second;
            auto cur_middle = (cur_pos + cur_neg + 1) / 2;
            auto cur_bias   = cur_pos.ModSubFast(cur_middle, Q);
            // cur_pos = cur_middle + cur_bias, cur_neg = cur_middle - cur_bias
            auto fLUT = [cur_bias](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
                if (x < q / 2)  // pos
                    return cur_bias;
                else  // neg
                    return (Q - cur_bias).Mod(Q);
            };
            auto ct_bias = BootstrapFunc(params, EK, ct, fLUT, Q, true);  // raw ctxt
            LWEscheme->EvalAddConstEq(ct_bias, cur_middle);
            ans[i] = std::make_shared<LWECiphertextImpl>(std::move(*ct_bias));
        }
        return ans;
    }
    if (n_pairs <= 2) {  // no more than 2 values are needed, directly obtain them using BTS
        for (size_t i = 0; i < n_pairs; i++) {
            auto cur_pos = pn_values[i].first, cur_neg = pn_values[i].second;
            auto cur_middle = (cur_pos + cur_neg + 1) / 2;
            auto cur_bias   = cur_pos.ModSubFast(cur_middle, Q);
            // cur_pos = cur_middle + cur_bias, cur_neg = cur_middle - cur_bias
            auto fLUT = [cur_bias](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
                if (x < q / 2)  // pos
                    return cur_bias;
                else  // neg
                    return (Q - cur_bias).Mod(Q);
            };
            auto ct_bias = BootstrapFunc(params, EK, ct, fLUT, Q, true);  // raw ctxt
            LWEscheme->EvalAddConstEq(ct_bias, cur_middle);
            ans[i] = std::make_shared<LWECiphertextImpl>(std::move(*ct_bias));
        }
        return ans;
    }

    //  note that this optimization works only for plaintext TV
    auto fLUTsgn = [batch](NativeInteger x, NativeInteger q, NativeInteger Q) -> NativeInteger {
        if (x < q / 2)
            return Q / (8 * batch);
        else
            return Q - Q / (8 * batch);
    };
    auto ct_sgn = BootstrapFunc(params, EK, ct, fLUTsgn, q);

    size_t pairs_remaining = n_pairs;
    for (size_t i = 0; i < n_tv; i++, pairs_remaining -= batch) {  // i-th batch BTS
        // first prepare the packed tv
        NativePoly a(polyparams, Format::COEFFICIENT, true), b(polyparams, Format::COEFFICIENT, true);
        for (size_t j = 0, end = std::min(batch, pairs_remaining); j < end; j++) {  // j-th pair
            auto cur_pos = pn_values[i * batch + j].first, cur_neg = pn_values[i * batch + j].second;
            if (j == 0) {
                auto cur_pos_negate = NativeInteger(0).ModSubFast(cur_pos, Q);
                for (size_t k = 0; k < half_step; k++) {  // iterate coefficients with k
                    b[k]         = cur_neg;
                    b[N - 1 - k] = cur_pos_negate;
                }
            }
            else {
                for (size_t k = (2 * j - 1) * half_step; k < 2 * j * half_step; k++) {
                    b[k]             = cur_pos;
                    b[k + half_step] = cur_neg;
                }
            }
        }
        // bootstrap it
        auto ct_sel = BootstrapCtxtCore(params, EK.BSkey, ct_sgn,
                                        std::make_shared<RLWECiphertextImpl>(std::vector<NativePoly>{a, b}));
        ct_sel->SetFormat(Format::COEFFICIENT);
        // extract
        for (size_t j = 0, end = std::min(batch, pairs_remaining); j < end; j++) {  // j-th pair
            ans[i * batch + j] = ManualExtract(ct_sel, j * 2 * half_step);
        }
    }
    return ans;
}

std::vector<NativePoly> BinFHEScheme::SignedDecomp(const std::shared_ptr<BinFHECryptoParams> params,
                                                   const NativePoly& poly, size_t q, size_t B) const {
    if (poly.GetFormat() != Format::COEFFICIENT)
        OPENFHE_THROW(openfhe_error, "signed decomp expects input to be in coefficient form");

    auto RGSWparams = params->GetRingGSWParams();
    auto LWEparams  = params->GetLWEParams();

    auto polyparams = RGSWparams->GetPolyParams();
    auto Q          = LWEparams->GetQ();
    auto N          = LWEparams->GetN();

    size_t d = static_cast<size_t>(std::ceil(log(double(q)) / log(double(B))));

    std::vector<NativePoly> ans(d);
    for (size_t i = 0; i < d; i++) {
        ans[i] = NativePoly(polyparams, Format::COEFFICIENT, true);
    }
    int64_t half_Q = (Q.ConvertToInt() + 1) / 2, half_B = (B + 1) / 2,
            Q_signed = static_cast<int64_t>(Q.ConvertToInt());  // we use (q+1)/2 to conform with 2'complement
    for (size_t i = 0; i < N; i++) {
        int64_t tmp_coeff = poly[i].ConvertToInt();
        if (tmp_coeff >= half_Q)
            tmp_coeff -= Q_signed;
        for (size_t j = 0; j < d; j++) {
            int64_t rem = tmp_coeff % B;
            if (rem >= half_B)
                rem -= B;
            tmp_coeff -= rem;
            tmp_coeff /= B;
            if (rem < 0)
                rem += Q_signed;
            ans[j][i] = rem;
        }
    }
    for (size_t i = 0; i < d; i++)
        ans[i].SetFormat(Format::EVALUATION);
    return ans;
}

RLWECiphertext BinFHEScheme::InnerProduct(const std::vector<RLWECiphertext>& rlwe_prime,
                                          const std::vector<NativePoly>& decomposed) const {
    auto polyparams = decomposed[0].GetParams();
    NativePoly a(polyparams, Format::EVALUATION, true), b(polyparams, Format::EVALUATION, true);
    if (rlwe_prime.size() != decomposed.size())
        OPENFHE_THROW(openfhe_error, "length mismatch in inner product");
    size_t length = rlwe_prime.size();
    for (size_t i = 0; i < length; i++) {
        a += rlwe_prime[i]->GetElements()[0] * decomposed[i];
        b += rlwe_prime[i]->GetElements()[1] * decomposed[i];
    }
    return std::make_shared<RLWECiphertextImpl>(std::vector<NativePoly>{a, b});
}

// NOTE: we assume the input polynomials are in coefficient format (which is default format after LWE-to-RLWE packing)
// ct1 is directly extended, while ct2 is mod switched before expansion
// output ciphertext is in NTT domain
RLWECiphertext BinFHEScheme::BFVMult(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                     const RLWECiphertext& ct1, const RLWECiphertext& ct2, uint32_t p) const {
    auto LWEparams    = params->GetLWEParams();
    auto RGSWparams   = params->GetRingGSWParams();
    auto Q            = RGSWparams->GetQ();
    auto P            = RGSWparams->GetP();
    auto N            = RGSWparams->GetN();
    auto baseRL       = RGSWparams->GetBaseRL();
    auto polyparams_Q = RGSWparams->GetPolyParams();
    auto polyparams_P = RGSWparams->GetPolyParamsP();

    if (ct1->GetElements()[0].GetFormat() != Format::COEFFICIENT ||
        ct2->GetElements()[0].GetFormat() != Format::COEFFICIENT)
        OPENFHE_THROW(openfhe_error, "bfv mult expects input to be in coefficient format");

    // auto t_start = std::chrono::steady_clock::now();

    auto ct1_eles = ct1->GetElements(), ct2_eles = ct2->GetElements();
    // Basis extension
    std::vector<NativePoly> ct1_eles_QP[2],
        ct2_eles_QP[2];               // outer idx 0 = mod Q, 1 = mod P. inner idx = ctxt component component
    for (size_t i = 0; i < 2; i++) {  // Q,P idx
        ct1_eles_QP[i] = std::vector<NativePoly>(2);
        ct2_eles_QP[i] = std::vector<NativePoly>(2);
    }
    for (size_t j = 0; j < 2; j++) {  // ctxt component idx
        NativeVector tmp;
        // extend ct1 to P
        ct1_eles_QP[0][j] = ct1_eles[j];
        ct1_eles_QP[1][j] = NativePoly(polyparams_P);
        tmp               = ct1_eles[j].GetValues().Mod(P);
        tmp.SetModulus(P);
        ct1_eles_QP[1][j].SetValues(tmp, Format::COEFFICIENT);
        // mod switch ct2 to P, then extend it to Q
        ct2_eles_QP[1][j] = NativePoly(polyparams_P);
        ct2_eles_QP[1][j].SetValues(ModSwitch(P, ct2_eles[j].GetValues()), Format::COEFFICIENT);

        ct2_eles_QP[0][j] = NativePoly(polyparams_Q);
        tmp               = ct2_eles_QP[1][j].GetValues().Mod(Q);
        tmp.SetModulus(Q);
        ct2_eles_QP[0][j].SetValues(tmp, Format::COEFFICIENT);
        // set all to evaluation form
        ct1_eles_QP[0][j].SetFormat(Format::EVALUATION);
        ct1_eles_QP[1][j].SetFormat(Format::EVALUATION);
        ct2_eles_QP[0][j].SetFormat(Format::EVALUATION);
        ct2_eles_QP[1][j].SetFormat(Format::EVALUATION);
    }
    // tensor product
    std::vector<NativePoly> tensors[2];       // outer idx = Q,P idx, inner idx = ctxt component idx
    tensors[0] = std::vector<NativePoly>(3);  // 1, -s, s2 mod Q
    tensors[1] = std::vector<NativePoly>(3);  // 1, -s, s2 mod P
    for (size_t i = 0; i < 2; i++) {
        // input ctxt = (a,b) encrypts m = b - as
        // output ctxt = (b1b2, -a1b2-a2b1, a1a2)*(1,s,s^2) = (b1b2, a1b2+a2b1, a1a2)*(1,-s,s^2)
        // use karatsuba
        tensors[i][0] = ct1_eles_QP[i][1] * ct2_eles_QP[i][1];  // b1 * b2
        tensors[i][2] = ct1_eles_QP[i][0] * ct2_eles_QP[i][0];  // a1 * a2
        // (a1+b1)*(a2+b2) - a1*a2 - b1*b2
        tensors[i][1] = (ct1_eles_QP[i][0] + ct1_eles_QP[i][1]) * (ct2_eles_QP[i][0] + ct2_eles_QP[i][1]) -
                        tensors[i][0] - tensors[i][2];
    }
    // (QP)/(p^2)m1m2 + ...: scale down by p/P to get Q/p*m1m2
    // mult by p, convert to coefficient form
    for (size_t i = 0; i < 2; i++)
        for (size_t j = 0; j < 3; j++) {
            tensors[i][j] *= p;
            tensors[i][j].SetFormat(Format::COEFFICIENT);
        }
    // then rescale by P
    auto halfP     = P >> 1;
    auto invP_modQ = P.ModInverse(Q);
    for (size_t j = 0; j < 3; j++) {  // for each ctxt component...
        auto &cur_poly_Q = tensors[0][j], &cur_poly_P = tensors[1][j];
        for (size_t k = 0; k < N; k++) {
            // round to the nearest multiple of P
            if (cur_poly_P[k] <= halfP)  // NOTE: we can use ModSubFastEq instead of ModSubEq as long as halfP < Q
                cur_poly_Q[k].ModSubFastEq(cur_poly_P[k], Q);
            else
                cur_poly_Q[k].ModAddFastEq(P - cur_poly_P[k], Q);
        }
        cur_poly_Q *= invP_modQ;
    }
    // key switching
    tensors[0][2].SetFormat(Format::COEFFICIENT);
    auto relined_ctxt = InnerProduct(*EK.BFV_relin_keys, SignedDecomp(params, tensors[0][2], Q.ConvertToInt(), baseRL));
    relined_ctxt->SetFormat(Format::COEFFICIENT);
    relined_ctxt->GetElements()[0] += tensors[0][1];
    relined_ctxt->GetElements()[1] += tensors[0][0];

    // auto t_end = std::chrono::steady_clock::now();
    // std::cout << "BFV mult takes " << (t_end - t_start).count() << "ns\n";

    return relined_ctxt;
}

std::shared_ptr<std::vector<RLWECiphertext>> BinFHEScheme::GenBFVRelinKeys(
    const std::shared_ptr<BinFHECryptoParams> params, const NativePoly& skNTT) const {
    auto RGSWparams = params->GetRingGSWParams();
    auto baseRL     = RGSWparams->GetBaseRL();
    auto Q          = RGSWparams->GetQ();
    auto polyparams = RGSWparams->GetPolyParams();

    size_t dRL = (uint32_t)std::ceil(log(Q.ConvertToDouble()) / log(static_cast<double>(baseRL)));
    std::vector<RLWECiphertext> rlwe_prime(dRL);

    auto dug = DiscreteUniformGeneratorImpl<NativeVector>();
    dug.SetModulus(Q);

    // generate RLWE encryptions of sk^2*B_rl^i
    auto skNTT2          = skNTT * skNTT;
    NativeInteger powerB = 1;
    for (size_t i = 0; i < dRL; i++, powerB *= baseRL) {
        NativePoly apoly(dug, polyparams, Format::EVALUATION);  // directly sample in NTT domain
        NativePoly bpoly(RGSWparams->GetDgg(), polyparams, Format::COEFFICIENT);
        bpoly.SetFormat(Format::EVALUATION);
        bpoly += apoly * skNTT;
        bpoly += skNTT2 * powerB;  // b = as + e + sk^2*B_rl^i
        rlwe_prime[i] = std::make_shared<RLWECiphertextImpl>(std::vector<NativePoly>{apoly, bpoly});
    }
    return std::make_shared<std::vector<RLWECiphertext>>(rlwe_prime);
}

/**
 * Note that the representations of tv + Ip are equivalent
 * however under unsigned representation [0,p-1], the tv1 corresponding to [1,1,...,p-1,p-1] is [p,0...,p-2,...] instead of [0,...,-2,...]
 * as we use the two's complement representation here
*/
NativeVector BinFHEScheme::ComputeTV1(const NativeVector& tv) const {
    auto p          = tv.GetModulus();  // plaintext modulus
    auto N          = tv.GetLength();
    int64_t ps      = p.ConvertToInt();
    int64_t half_ps = ps >> 1, dps = ps << 1;
    NativeVector tv1(N, 2 * p);
    std::vector<int64_t> tv_signed(N);
    int64_t tmp;
    // reduce to two's complement form
    for (size_t i = 0; i < N; i++) {
        tmp          = tv[i].ConvertToInt();
        tv_signed[i] = (tmp >= half_ps) ? (tmp - ps) : tmp;
    }
    tmp = tv_signed[0] + tv_signed[N - 1];
    if (tmp < 0)
        tmp += dps;
    tv1[0] = tmp;
    for (size_t i = 1; i < N; i++) {
        tmp = tv_signed[i] - tv_signed[i - 1];
        if (tmp < 0)
            tmp += dps;
        tv1[i] = tmp;
    }
    return tv1;
}

void BinFHEScheme::inspect_lwe_ctxt(const std::shared_ptr<BinFHECryptoParams> params, const RingGSWBTKey& EK,
                                    uint32_t p, ConstLWECiphertext ct, std::string name) const {
    auto LWEParams = params->GetLWEParams();
    LWEPlaintext ptxt;
    LWEscheme->Decrypt(LWEParams, EK.skeyN, ct, &ptxt, ct->GetModulus().ConvertToInt());

    std::cout << name << " = " << ptxt
              << ", log2(noise) = " << std::log2(std::abs(inspect_lwe_ptxt(ptxt, p, ct->GetModulus()))) << '\n';
}

int64_t BinFHEScheme::inspect_lwe_ptxt(LWEPlaintext ptxt, uint32_t p, NativeInteger mod) const {
    uint64_t cur_mod       = mod.ConvertToInt();
    int64_t cur_mod_signed = cur_mod;
    auto msg               = ((ptxt * p + cur_mod / 2) / cur_mod) % p;  // round(p/Q * ptxt)
    auto msg_part          = ((msg * cur_mod + p / 2) / p) % cur_mod;   // round(Q/p * msg)
    auto noise             = NativeInteger(msg_part).ModSub(ptxt, cur_mod);
    int64_t signed_noise   = noise.ConvertToInt();
    if (signed_noise >= cur_mod_signed / 2)
        signed_noise -= cur_mod_signed;
    return signed_noise;
}

};  // namespace lbcrypto

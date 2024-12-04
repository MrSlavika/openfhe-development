#include "binfhecontext.h"
#include <benchmark/benchmark.h>

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
        if (qin > uint64_t(1) << 31)
            OPENFHE_THROW(openfhe_error, "max qin = 2^31");
        if (qin >= 1 << 28)
            return {1 << 14, 1 << 18, 1 << 27};
        if (qin >= 1 << 20)
            return {1 << 18, 1 << 27};
        return {1 << 27};
    case REDUCE:
        if (qin > uint64_t(1) << 31)
            OPENFHE_THROW(openfhe_error, "max qin = 2^31");
        if (qin >= 1 << 29)
            return {1 << 14, 1 << 18, 1 << 27};
        if (qin >= 1 << 20)
            return {1 << 18, 1 << 27};
        return {1 << 27};
    case COMPRESS:
        if (qin > uint64_t(1) << 33)
            OPENFHE_THROW(openfhe_error, "max qin = 2^33");
        if (qin >= 1 << 30)
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
    uint64_t qin = uint64_t(1) << st.range(0);
    int64_t param_idx = st.range(1);
    ParamSet param_set = param_sets[param_idx];

    std::vector<uint32_t> baseGs = get_bases(param_set.dec_type, qin);
    auto B_g = baseGs[0];
    if (param_idx != cur_param_set_id)
    {
        cur_param_set_id = param_idx;
        std::cout << "select param set = " << param_set.desc << '\n';
        cc = BinFHEContext();
        cc.GenerateBinFHEContext(param_set.n, param_set.N, param_set.q, param_set.Q, param_set.qKS, param_set.std,
                                 param_set.baseKS, B_g, param_set.baseR, 0, 0, 0, 0, 0, param_set.p, baseGs, 0, false, 0, 0, GINX);
        // Generate the secret key
        sk = cc.KeyGen();
        // Generate the bootstrapping keys (refresh and switching keys)
        cc.BTKeyGen(sk);
    }
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

    int factor = 1 << int(log2(qin) - log2(param_set.q.ConvertToInt())); // Q/q
    int p = cc.GetMaxPlaintextSpace().ConvertToInt() * factor;           // Obtain the maximum plaintext space
    std::cout << "log2(large p) = " << int(log2(p)) << '\n';

    // Sample Program: Step 2: Key Generation

    // Sample Program: Step 3: Extract the MSB and decrypt to check the result
    // Note that we check for 8 different numbers
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(p);
    for (int i = 0; i < 8; i++)
    {
        // We first encrypt with large Q
        st.PauseTiming();
        auto m = dug.GenerateInteger().ConvertToInt();
        auto ct1 = cc.Encrypt(sk, m, FRESH, p, qin);
        std::vector<LWECiphertext> decomp_array;
        st.ResumeTiming();
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
    }
}

// the first arg changes first
BENCHMARK_REGISTER_F(MyFixture, SignTest)->ArgsProduct({benchmark::CreateDenseRange(13, 29, 1), benchmark::CreateDenseRange(0, param_sets.size() - 1, 1)})->Repetitions(1);
BENCHMARK_MAIN();

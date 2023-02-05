#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <random>
#include "regevEncryption.h"
#include "seal/seal.h"
#include "global.h"
#include "client.h"
#include "MathUtil.h"

using namespace seal;

/**
 * @brief Multi-Recipient Encryption
 */
namespace mre {

    typedef NativeVector MREsharedSK; // for one recipient, side of (sk_shared_length)
    typedef vector<NativeVector> MREsecretSK;

    struct MREsk{
        MREsecretSK secretSK; // ell x param.n, double vector 
        MREsharedSK shareSK; // partialSize, single vector

        MREsk() {}
        MREsk(MREsecretSK& secret, MREsharedSK& share)
        : secretSK(secret), shareSK(share)
        {}
    };

    struct MREPartialGPK {
        NativeVector A1; // size of (param.n)
        NativeVector b; // size of (ell)
        vector<NativeVector> b_prime; // size of (partySize) x (ell)

        MREPartialGPK() {}
        MREPartialGPK(NativeVector& A1, NativeVector& b, vector<NativeVector>& b_prime)
        : A1(A1), b(b), b_prime(b_prime)
        {}
    };

    struct MREGroupPK {
        vector<MREPartialGPK> partialPK; // param.m's partial PK, each contains a pair of (A1, b)
        vector<MREsharedSK> sharedSK; // T's (param.ell x sk_shared_length) vectors

        MREGroupPK() {}
        MREGroupPK(vector<MREPartialGPK>& partialPK, vector<MREsharedSK>& sharedSK)
        : partialPK(partialPK), sharedSK(sharedSK)
        {}
    };

    MREsharedSK MREGenerateSharedSK(const PVWParam& param){
        int q = param.q;
        lbcrypto::DiscreteUniformGeneratorImpl<regevSK> dug;
        dug.SetModulus(q);
        return dug.GenerateVector(partial_size_glb);
    }

    vector<MREsk> MREgenerateSK(const PVWParam& param, const PVWsk& target_secretSK, const MREsharedSK& target_sharedSK,
                                const int partialSize = partial_size_glb, const int partySize = party_size_glb) {
        vector<MREsk> mreSK(partySize);

        for (int i = 0; i < partySize; i++) {
            // put the sk given in param as the first of the group
            // for pertinent messages, this will the recipient's sk, otherwise, a random sk will be passed in
            auto temp_secretSK = i == 0 ? target_secretSK : PVWGenerateSecretKey(param);
            auto temp_sharedSK = i == 0 ? target_sharedSK : MREGenerateSharedSK(param);

            MREsecretSK leftSK(param.ell);
            MREsharedSK rightSK = NativeVector(partialSize);
            for (int l = 0; l < param.ell; l++) {
                leftSK[l] = NativeVector(param.n);
                
                for (int j = 0; j < param.n; j++) {
                    leftSK[l][j] = temp_secretSK[l][j].ConvertToInt();
                }
            }

            for(int j = 0; j < partialSize; j++) {
                rightSK[j] = target_sharedSK[j].ConvertToInt();
            }
            mreSK[i] = MREsk(leftSK, rightSK);
        }
        return mreSK;
    }

    MREGroupPK MREgeneratePartialPK(const PVWParam& param, const vector<MREsk>& groupSK, prng_seed_type& seed, const int partialSize = partial_size_glb) {
        auto mrerng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
        RandomToStandardAdapter engine(mrerng->create());
        std::uniform_int_distribution<std::mt19937::result_type> dist(0, param.q-1);

        vector<MREPartialGPK> partialPK(param.m);
        vector<MREsharedSK> sharedSK(groupSK.size());

        for (int w = 0; w < param.m; w++) {
            NativeVector A1(param.n), b(param.ell);
            vector<NativeVector> b_prime(groupSK.size());
            for (int i = 0; i < param.n; i++) {
                A1[i] = dist(engine) % param.q;
            }
            for (int i = 0; i < param.ell; i++) {
                b[i] = dist(engine) % param.q;
            }

            for (int i = 0; i < (int)groupSK.size(); i++) {
                b_prime[i] = NativeVector(param.ell);

                for (int l = 0; l < param.ell; l++) {
                    long temp = 0;
                    for (int j = 0; j < param.n; j++) {
                        temp = (temp + groupSK[i].secretSK[l][j].ConvertToInt() * A1[j].ConvertToInt()) % param.q;
                        temp = temp < 0 ? temp + param.q : temp;
                    }
                    if (b[l] < temp) {
                        b[l] += param.q;
                    }
                    b_prime[i][l] = (b[l] - temp) % param.q;
                    // TODO: need gaussian error here for b_prime
                    b[l] = b[l] % param.q;
                }
            }

            partialPK[w] = MREPartialGPK(A1, b, b_prime);
        }

        for (int i = 0; i < (int)groupSK.size(); i++) {
            sharedSK[i] = groupSK[i].shareSK;
        }

        return MREGroupPK(partialPK, sharedSK);
    }

    /**
     * @brief The encryption contains three main steps.
     * The first is to perform a subsum on A1 and b part included in the GroupPK, to get a final (A1*, b*) pair embedded in the final ciphertext.
     * Next, with the same subsum randomness, we also add up the b_prime to get a b_prime*.
     * At last, similar to the main idea of ObliviousMultiplexer, besides the normal param.n (n=450) sk, notice that we have 8 more elements (n=458,
     * where partialSize = 8) serving as the "sharedSK". By first exponential extended up to sk^party_size, we form a sharedSK matrix of size
     * (ell*partySize) x (partialSize * partySize) and then by multiplying it with a random matrix of size (partialSize*partySize) x (ell*partySize),
     * we perserve it to be full rank = ell*partySize with high probability. The resulted matrix is then used to solve a linear equation system such
     * that f(sharedSK') = b_prime*.
     *
     * @param ct clue
     * @param msg msg
     * @param groupPK MREGroupPK, containing (A1, b, b_prime, sharedSK)
     * @param param PVWParam
     * @param exp_seed randomness seed used to generate exponential extension of sharedSK
     * @param partialSize partialSize
     * @param partySize partySize
     */
    void MREEncPK(PVWCiphertext& ct, const vector<int>& msg, const MREGroupPK& groupPK, const PVWParam& param, prng_seed_type& exp_seed,
                  const int partialSize = partial_size_glb, const int partySize = party_size_glb) {
        prng_seed_type seed;
        for (auto &i : seed) {
            i = random_uint64();
        }

        auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
        RandomToStandardAdapter engine(rng->create());
        uniform_int_distribution<uint64_t> dist(0, 1);

        NativeInteger q = param.q;
        ct.a = NativeVector(param.n + param.ell * (partySize + secure_extra_length_glb));
        ct.b = NativeVector(param.ell);

        chrono::high_resolution_clock::time_point time_start, time_end;
        time_start = chrono::high_resolution_clock::now();
        vector<NativeVector> b_prime(partySize, NativeVector(param.ell));
        for(size_t i = 0; i < groupPK.partialPK.size(); i++){
            if (true) {
	            for(int j = 0; j < (int) groupPK.partialPK[i].A1.GetLength(); j++) {
                    ct.a[j].ModAddFastEq(groupPK.partialPK[i].A1[j], q);
                }
                for(int j = 0; j < param.ell; j++) {
                    ct.b[j].ModAddFastEq(groupPK.partialPK[i].b[j], q);
                }
                for (int j = 0; j < (int) groupPK.partialPK[i].b_prime.size(); j++) {
                    for (int l = 0; l < param.ell; l++) {
                        b_prime[j][l].ModAddFastEq(groupPK.partialPK[i].b_prime[j][l], q);
                    }
                }
            }
        }
        time_end = chrono::high_resolution_clock::now();
        // cout << "add: " << chrono::duration_cast<chrono::microseconds>(time_end - time_start).count() << endl;

        vector<vector<int>> rhs(partySize, vector<int>(param.ell)), lhs(partySize), old_shared_sk(partySize);

        for (int p = 0; p < partySize; p++) {
            for (int i = 0; i < param.ell; i++) {
                rhs[p][i] = b_prime[p][i].ConvertToInt();
            }

            old_shared_sk[p].resize(partialSize);
            for (int j = 0; j < partialSize; j++) {
                old_shared_sk[p][j] = groupPK.sharedSK[p][j].ConvertToInt();
            }
        }

        vector<vector<int>> extended_shared_sk = generateExponentialExtendedVector(param, old_shared_sk, partySize);
        lhs = compressVector(param, exp_seed, extended_shared_sk);
        vector<vector<long>> res = equationSolvingRandomBatch(lhs, rhs, -1);

        for (int j = 0; j < param.ell * (partySize + secure_extra_length_glb); j++) {
            int ell_ind = j / (partySize + secure_extra_length_glb);
            int party_ind = j % (partySize + secure_extra_length_glb);
            ct.a[j + param.n] = res[ell_ind][party_ind];
        }

        for(int j = 0; j < param.ell; j++){
            msg[j]? ct.b[j].ModAddFastEq(3*q/4, q) : ct.b[j].ModAddFastEq(q/4, q);
        }
    }
}

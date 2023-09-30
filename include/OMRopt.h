#include "PVWToBFVSeal.h"
#include "SealUtils.h"
#include "retrieval.h"
#include "client.h"
#include "LoadAndSaveUtils.h"
#include "OMRUtil.h"
#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ.h>
#include <thread>

void test() {
    size_t poly_modulus_degree = 32768;
    int stepSize = 32;

    EncryptionParameters parms(scheme_type::bfv);
    auto degree = poly_modulus_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 28, 60, 60, 60, 60,
                                                                     60, 60, 60, 60, 60, 
                                                                     60, 60, 60, 60, 60,
                                                                     60, 60, 30, 60});
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(65537);


    // EncryptionParameters parms2(scheme_type::bfv);
    // parms2.set_poly_modulus_degree(poly_modulus_degree);
    // auto coeff_modulus2 = CoeffModulus::Create(poly_modulus_degree, { 28, 60, 60, 60,
    //                                                                  60, 60 });
    // parms2.set_coeff_modulus(coeff_modulus2);
    // parms2.set_plain_modulus(65537);

	prng_seed_type seed;
    for (auto &i : seed) {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);
    // parms2.set_random_generator(rng);

    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context); 
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    GaloisKeys glk, gal_keys_expand; //gal_keys_slotToCoeff;
    vector<uint32_t> galois_elts;
    auto n = poly_modulus_degree;
    for (int i = 0; i < ceil(log2(poly_modulus_degree)); i++) {
        galois_elts.push_back((n + exponentiate_uint(2, i)) / exponentiate_uint(2, i));
    }
    cout << "Steps: " << galois_elts << endl;
    keygen.create_galois_keys(galois_elts, glk);
    cout << "Finished generating keys...\n";

    vector<Modulus> coeff_modulus_expand = coeff_modulus;
    coeff_modulus_expand.erase(coeff_modulus_expand.begin() + 2, coeff_modulus_expand.end()-1);
    EncryptionParameters parms_expand = parms;
    parms_expand.set_coeff_modulus(coeff_modulus_expand);
    SEALContext context_expand = SEALContext(parms_expand, true, sec_level_type::none);

    SecretKey sk_expand;
    sk_expand.data().resize(coeff_modulus_expand.size() * degree);
    sk_expand.parms_id() = context_expand.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_expand.size() - 1, sk_expand.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_expand.data().data() + degree * (coeff_modulus_expand.size() - 1));
    KeyGenerator keygen_expand(context_expand, sk_expand); 
    // for (int i = 0; i < ceil(log2(poly_modulus_degree)); i++) {
    //     galois_elts.push_back((n + exponentiate_uint(2, i)) / exponentiate_uint(2, i));
    // }
    keygen_expand.create_galois_keys(galois_elts, gal_keys_expand);

    Plaintext plainInd;
    plainInd.resize(degree);
    plainInd.parms_id() = parms_id_zero;
    for (int i = 0; i < (int) degree; i++) {
        plainInd.data()[i] = 0;
    }
    plainInd.data()[1] = 1;
    // plainInd.data()[2] = 1;
    // plainInd.data()[5] = 1;
    // plainInd.data()[1024] = 1;

    Ciphertext c1;
    encryptor.encrypt(plainInd, c1);

    for (int i = 0; i < 15; i++) {
    evaluator.mod_switch_to_next_inplace(c1);
    }
    // evaluator.mod_switch_to_next_inplace(c1);
    // evaluator.mod_switch_to_next_inplace(c1);

    vector<Ciphertext> expanded_subtree_leaves = subExpand(context_expand, parms, c1, poly_modulus_degree, gal_keys_expand, poly_modulus_degree/stepSize);

    cout << "after subexpand\n";

    vector<Ciphertext> partial_final_leaves(stepSize);
    for (int i = 0; i < (int) expanded_subtree_leaves.size(); i++) {
        cout << "final expand " << i << endl;
                partial_final_leaves = expand(context, parms, expanded_subtree_leaves[i], poly_modulus_degree, gal_keys_expand, stepSize);

        for (int j = 0; j < 10; j++) {
            Plaintext t;
            decryptor.decrypt(partial_final_leaves[j], t);
            for (int k = 0; k < (int) 10; k++) {
                cout << t.data()[k] << " ";
            }
            cout << endl;
        }
    }
}

void OMR3_opt() {

    size_t poly_modulus_degree = poly_modulus_degree_glb;
    int t = 65537;

    int numOfTransactions = numOfTransactions_glb;
    createDatabase(numOfTransactions * party_size_glb, 306);
    cout << "Finishing createDatabase\n";

    // step 1. generate OPVW sk
    // recipient side
    auto params = OPVWParam(750, 65537, 0.5, 2, 32); 
    auto sk = OPVWGenerateSecretKey(params);
    auto pk = OPVWGeneratePublicKey(params, sk);
    cout << "Finishing generating sk for OPVW cts\n";

    // step 2. prepare transactions
    vector<int> pertinentMsgIndices;
    auto expected = preparingTransactionsFormal_opt(pertinentMsgIndices, pk, numOfTransactions, num_of_pertinent_msgs_glb,  params);
    cout << expected.size() << " pertinent msg: Finishing preparing messages\n";
    cout << "Perty: "<< pertinentMsgIndices << endl;

    // step 3. generate detection key
    // recipient side
    EncryptionParameters parms(scheme_type::bfv);
    auto degree = poly_modulus_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 28, 60, 60, 60, 60,
                                                                     60, 60, 60, 60,
                                                                     60, 60, 60, 60,
                                                                     60, 60, 30, 60});
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(t);


	prng_seed_type seed;
    for (auto &i : seed) {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

    SEALContext context(parms, true, sec_level_type::none);
    cout << "primitive root: " << context.first_context_data()->plain_ntt_tables()->get_root() << endl;
    print_parameters(context); 
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    Ciphertext switchingKey = omr::generateDetectionKeyForOPVWsk(context, poly_modulus_degree, public_key, secret_key, sk, params);
    Ciphertext packedSIC;
    
    vector<vector<OPVWCiphertext>> SICPVW_multicore(numcores);
    vector<vector<vector<uint64_t>>> payload_multicore(numcores);
    vector<int> counter(numcores);

    GaloisKeys gal_keys, gal_keys_slotToCoeff, gal_keys_expand;
    vector<int> stepsfirst = {1};
    // for (int i = 0; i < ceil(log2(poly_modulus_degree)); i++) {
    //     stepsfirst.push_back((poly_modulus_degree + exponentiate_uint(2, i)) / exponentiate_uint(2, i));
    // }
    // only one rot key is needed for full level
    cout << "Steps: " << stepsfirst << endl;
    keygen.create_galois_keys(stepsfirst, gal_keys);
    cout << "Created.\n";

    /////////////////////////////////////////////////////////////// Rot Key gen
    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2) {
	    steps.push_back(i);
    }

    cout << "Finishing generating detection keys\n";

    /////////////////////////////////////// Level specific keys
    vector<Modulus> coeff_modulus_next = coeff_modulus;
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 4, coeff_modulus_next.end()-1);
    EncryptionParameters parms_next = parms;
    parms_next.set_coeff_modulus(coeff_modulus_next);
    SEALContext context_next = SEALContext(parms_next, true, sec_level_type::none);
    Evaluator evaluator_next(context_next);

    SecretKey sk_next;
    sk_next.data().resize(coeff_modulus_next.size() * degree);
    sk_next.parms_id() = context_next.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_next.size() - 1, sk_next.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_next.data().data() + degree * (coeff_modulus_next.size() - 1));
    KeyGenerator keygen_next(context_next, sk_next); 
    vector<int> steps_next = {0,32,64,128,256,512,1024,2048,4096,8192};
    keygen_next.create_galois_keys(steps, gal_keys_next);

    vector<int> slotToCoeff_steps_coeff = {1};
    for (int i = 0; i < (int) degree/2;) {
        if (find(slotToCoeff_steps_coeff.begin(), slotToCoeff_steps_coeff.end(), i) == slotToCoeff_steps_coeff.end()) {
            slotToCoeff_steps_coeff.push_back(i);
        }
        i += sqrt(degree/2);
    }
    keygen_next.create_galois_keys(slotToCoeff_steps_coeff, gal_keys_slotToCoeff);


    //////////////////////////////////////////////////////
    vector<Modulus> coeff_modulus_expand = coeff_modulus;
    coeff_modulus_expand.erase(coeff_modulus_expand.begin() + 3, coeff_modulus_expand.end()-1);
    EncryptionParameters parms_expand = parms;
    parms_expand.set_coeff_modulus(coeff_modulus_expand);
    SEALContext context_expand = SEALContext(parms_expand, true, sec_level_type::none);

    SecretKey sk_expand;
    sk_expand.data().resize(coeff_modulus_expand.size() * degree);
    sk_expand.parms_id() = context_expand.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_expand.size() - 1, sk_expand.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_expand.data().data() + degree * (coeff_modulus_expand.size() - 1));
    KeyGenerator keygen_expand(context_expand, sk_expand); 
    vector<uint32_t> galois_elts;
    auto n = poly_modulus_degree;
    for (int i = 0; i < ceil(log2(poly_modulus_degree)); i++) {
        galois_elts.push_back((n + exponentiate_uint(2, i)) / exponentiate_uint(2, i));
    }
    keygen_expand.create_galois_keys(galois_elts, gal_keys_expand);

        //////////////////////////////////////
    vector<Modulus> coeff_modulus_last = coeff_modulus;
    coeff_modulus_last.erase(coeff_modulus_last.begin() + 4, coeff_modulus_last.end()-1);
    EncryptionParameters parms_last = parms;
    parms_last.set_coeff_modulus(coeff_modulus_last);
    SEALContext context_last = SEALContext(parms_last, true, sec_level_type::none);

    SecretKey sk_last;
    sk_last.data().resize(coeff_modulus_last.size() * degree);
    sk_last.parms_id() = context_last.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_last.size() - 1, sk_last.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_last.data().data() + degree * (coeff_modulus_last.size() - 1));
    vector<int> steps_last = {1,2,4,8,16};
    KeyGenerator keygen_last(context_last, sk_last); 
    keygen_last.create_galois_keys(steps, gal_keys_last);
    //////////////////////////////////////
    PublicKey public_key_last;
    keygen_next.create_public_key(public_key_last);
    
    //////////////////////////////////////

    vector<vector<Ciphertext>> packedSICfromPhase1(numcores,vector<Ciphertext>(numOfTransactions/numcores/poly_modulus_degree)); // Assume numOfTransactions/numcores/poly_modulus_degree is integer, pad if needed

    NTL::SetNumThreads(numcores);
    SecretKey secret_key_blank;

    chrono::high_resolution_clock::time_point time_start, time_end, s,e;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();

    Plaintext pl;
    vector<uint64_t> tm(poly_modulus_degree);

    MemoryPoolHandle my_pool = MemoryPoolHandle::New();
    auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++){
        counter[i] = numOfTransactions/numcores*i;
        
        size_t j = 0;
        while(j < numOfTransactions/numcores/poly_modulus_degree) {
            if(!i)
                cout << "Phase 1, Core " << i << ", Batch " << j << endl;

            Ciphertext packedSIC_temp;
            s = chrono::high_resolution_clock::now();
            for (int p = 0; p < party_size_glb; p++) {
                loadClues_OPVW(SICPVW_multicore[i], counter[i], counter[i]+poly_modulus_degree, params, p, party_size_glb);
                
                packedSIC_temp = obtainPackedSICFromRingLWEClue(secret_key, SICPVW_multicore[i], switchingKey, relin_keys, gal_keys,
                                                                poly_modulus_degree, context, params, poly_modulus_degree);
                // evaluator.mod_switch_to_next_inplace(packedSIC_temp);
                // evaluator.mod_switch_to_next_inplace(packedSIC_temp);

                decryptor.decrypt(packedSIC_temp, pl);
                cout << "noise: " << decryptor.invariant_noise_budget(packedSIC_temp) << endl;
                batch_encoder.decode(pl, tm);
                cout << "SIC before rangeCheck: ------------------------------ \n";
                for (int c = 0; c < 10; c++) {
                    cout << tm[c] << " ";
                }
                cout << endl;

                if (p == 0){
                    packedSICfromPhase1[i][j] = packedSIC_temp;
                } else {
                    evaluator.add_inplace(packedSICfromPhase1[i][j], packedSIC_temp);
                }
            }
            j++;
            counter[i] += poly_modulus_degree;
            SICPVW_multicore[i].clear();
            e = chrono::high_resolution_clock::now();
            cout << "BB to PV time: " << chrono::duration_cast<chrono::microseconds>(e - s).count() << endl;
        }
    }
    NTL_EXEC_RANGE_END;
    MemoryManager::SwitchProfile(std::move(old_prof));


    // step 4. detector operations
    vector<vector<Ciphertext>> lhs_multi_ctr(numcores);
    vector<Ciphertext> rhs_multi(numcores);
    vector<vector<vector<int>>> bipartite_map(numcores);

    for (auto &i : seed_glb) {
        i = random_uint64();
    }
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions, OMRthreeM, repeatition_glb, seed_glb);

    // for 32768 (15 bit) messages, partySize = 15 (4 bit), we need 60/16 = 4 acc slots
    int encode_bit = ceil(log2(party_size_glb + 1));
    int index_bit = log2(numOfTransactions_glb);
    int acc_slots = ceil(encode_bit * index_bit / (16.0));
    cout << "Acc slots: " << encode_bit << " " << index_bit << " " << acc_slots << endl;
    int number_of_ct = ceil(repetition_glb * (acc_slots+1) * num_bucket_glb / ((poly_modulus_degree_glb / num_bucket_glb / (acc_slots+1) * (acc_slots+1) * num_bucket_glb) * 1.0));
    cout << "number of ct: " << number_of_ct << endl;

    int sq_ct = sqrt(degree/2);
    vector<Ciphertext> packSIC_sqrt_list(2*sq_ct);
    uint64_t inv = modInverse(degree, t);
    cout << "Inv: " << inv << endl;

    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++){
        MemoryPoolHandle my_pool = MemoryPoolHandle::New();
        auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
        size_t j = 0;
        counter[i] = numOfTransactions/numcores*i;

        while(j < numOfTransactions/numcores/poly_modulus_degree){
            if(!i)
                cout << "Phase 2-3, Core " << i << ", Batch " << j << endl;
            loadData(payload_multicore[i], counter[i], counter[i]+poly_modulus_degree);
            vector<Ciphertext> templhsctr;
            Ciphertext temprhs;

            Ciphertext curr_PackSIC(packedSICfromPhase1[i][j]);
            Ciphertext packSIC_copy(curr_PackSIC);
            evaluator_next.rotate_columns_inplace(packSIC_copy, gal_keys_slotToCoeff);

            for (int c = 0; c < sq_ct; c++) {
                evaluator_next.rotate_rows(curr_PackSIC, sq_ct * c, gal_keys_slotToCoeff, packSIC_sqrt_list[c]);
                evaluator_next.transform_to_ntt_inplace(packSIC_sqrt_list[c]);
                evaluator_next.rotate_rows(packSIC_copy, sq_ct * c, gal_keys_slotToCoeff, packSIC_sqrt_list[c+sq_ct]);
                evaluator_next.transform_to_ntt_inplace(packSIC_sqrt_list[c+sq_ct]);
            }
            
            Ciphertext packSIC_coeff = slotToCoeff_WOPrepreocess(context, context_next, packSIC_sqrt_list,
                                                                 gal_keys_slotToCoeff, 128, degree, t, inv);

            decryptor.decrypt(packSIC_coeff, pl);
            cout << "noise: " << decryptor.invariant_noise_budget(packSIC_coeff) << endl;
            cout << "SIC plaintext after slotToCoeff: ------------------------------ \n";
            for (int c = 0; c < (int) degree; c++) {
                cout << pl.data()[c] << " ";
            }
            cout << endl;

            serverOperations3therest_obliviousExpansion(parms_expand, templhsctr, bipartite_map[i], temprhs, packSIC_coeff, payload_multicore[i],
                            relin_keys, gal_keys_expand, sk_expand, public_key_last, poly_modulus_degree, context_next, context_expand,
                            poly_modulus_degree, counter[i], number_of_ct, party_size_glb, acc_slots+1);

            if(j == 0){
                lhs_multi_ctr[i] = templhsctr;
                rhs_multi[i] = temprhs;
            } else {
                for(size_t q = 0; q < lhs_multi_ctr[i].size(); q++){
                    evaluator.add_inplace(lhs_multi_ctr[i][q], templhsctr[q]);
                }
                evaluator.add_inplace(rhs_multi[i], temprhs);
            }
            j++;
            payload_multicore[i].clear();
        }

        MemoryManager::SwitchProfile(std::move(old_prof));
    }
    NTL_EXEC_RANGE_END;

    for(int i = 1; i < numcores; i++){
        for(size_t q = 0; q < lhs_multi_ctr[i].size(); q++){
            evaluator.add_inplace(lhs_multi_ctr[0][q], lhs_multi_ctr[i][q]);
        }
        evaluator.add_inplace(rhs_multi[0], rhs_multi[i]);
    }

    cout << "!!! FINAL NOISE: " << decryptor.invariant_noise_budget(lhs_multi_ctr[0][0]) << endl;
    while(context.last_parms_id() != lhs_multi_ctr[0][0].parms_id()){
            for(size_t q = 0; q < lhs_multi_ctr[0].size(); q++){
                evaluator.mod_switch_to_next_inplace(lhs_multi_ctr[0][q]);
            }
            evaluator.mod_switch_to_next_inplace(rhs_multi[0]);
        }

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nDetector running time: " << time_diff.count() << "us." << "\n";

    stringstream data_streamdg, data_streamdg2;
    auto digsize = rhs_multi[0].save(data_streamdg);
    for(size_t q = 0; q < lhs_multi_ctr[0].size(); q++){
        digsize += lhs_multi_ctr[0][q].save(data_streamdg2);
    }
    cout << "Digest size: " << digsize << " bytes" << endl;

    // step 5. receiver decoding
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions, OMRthreeM, repeatition_glb, seed_glb);
    time_start = chrono::high_resolution_clock::now();
    auto res = receiverDecodingOMR3(lhs_multi_ctr[0], bipartite_map[0], rhs_multi[0], poly_modulus_degree, secret_key, context,
                                    numOfTransactions, party_size_glb, acc_slots+1);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nRecipient running time: " << time_diff.count() << "us." << "\n";

    cout << "EXPECTED -------------------------------------------------------- \n" << expected << endl;
    cout << "RESULT ---------------------------------------------------------- \n" << res << endl;

    if(checkRes(expected, res))
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;
    
    for(size_t i = 0; i < res.size(); i++){
    }
}
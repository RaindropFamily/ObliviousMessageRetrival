//#include "PVWToBFV.h"
#include "unitTests.h"
#include "LoadAndSaveUtils.h"
#include <thread>

using namespace seal;

void genTestData(){
    createDatabase();
    //createSICforEachTransaction(450, 65537, 1.2, 1, 524288, 32768);
}

vector<vector<uint64_t>> preparinngTransactions(vector<PVWCiphertext>& SICPVW, vector<vector<uint64_t>>& payload, PVWsk& sk, 
                                                    int numOfTransactions, int pertinentfactor, const PVWParam& params, bool formultitest = false){
    srand (time(NULL));
    //auto pk = PVWGeneratePublicKey(params, sk);

    vector<int> msgs(numOfTransactions);
    vector<vector<uint64_t>> ret;
    SICPVW.resize(numOfTransactions);
    vector<int> zeros(params.ell, 0);
    for(int i = 0; i < numOfTransactions; i++){
        if(rand()%pertinentfactor == 0){
            PVWEncSK(SICPVW[i], zeros, sk, params);
            msgs[i] = 1;
        }
        else
        {
            auto sk2 = PVWGenerateSecretKey(params);
            PVWEncSK(SICPVW[i], zeros, sk2, params);
            msgs[i] = 0;
        }
    }

    payload = loadData(numOfTransactions, 306);
    cout << "Supposed result: \n";
    for(int i = 0; i < numOfTransactions; i++){
        if(msgs[i]){
            cout << i << ": " << payload[i] << endl;
            ret.push_back(payload[i]);
        }
    }
    if(formultitest){
        ret.clear();
        msgs.resize(numOfTransactions/numcores);
        for(int i = 0; i < int(msgs.size()); i++){
            if(msgs[i]){
                ret.push_back(payload[i]);
            }
        }
    }
    return ret;
}

Ciphertext serverOperations1Previous(SecretKey& sk, vector<PVWCiphertext>& SICPVW, vector<vector<Ciphertext>>& switchingKey, const RelinKeys& relin_keys,
                            const size_t& degree, const SEALContext& context, const PVWParam& params, const int numOfTransactions){

    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);
    
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    time_start = chrono::high_resolution_clock::now();
    vector<Ciphertext> packedSIC;
    computeBplusASPVW(packedSIC, SICPVW, switchingKey, context, params);
    switchingKey.clear();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "1\n";

    time_start = chrono::high_resolution_clock::now();
    int rangeToCheck = 32; // range check is from [-rangeToCheck, rangeToCheck-1]
    evalRangeCheckMemorySavingOptimizedPVW(packedSIC, rangeToCheck, relin_keys, degree, context, params);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "2\n";

    cout << decryptor.invariant_noise_budget(packedSIC[0]) << " bits left" << endl;
    for(int i = 0; i < 5; i++)
        evaluator.mod_switch_to_next_inplace(packedSIC[0]);
    // evaluator.mod_switch_to_next_inplace(packedSIC);
    cout << decryptor.invariant_noise_budget(packedSIC[0]) << " bits left" << endl;

    return packedSIC[0];
}

Ciphertext serverOperations1obtainPackedSIC(const SecretKey& sk, vector<PVWCiphertext>& SICPVW, vector<Ciphertext> switchingKey, const RelinKeys& relin_keys,
                            const GaloisKeys& gal_keys, const size_t& degree, const SEALContext& context, const PVWParam& params, const int numOfTransactions){
    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);
    
    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    // cout << "1: " << SICPVW[0].parms_id();

    time_start = chrono::high_resolution_clock::now();
    vector<Ciphertext> packedSIC(params.ell);
    computeBplusASPVWOptimized(packedSIC, SICPVW, switchingKey, gal_keys, context, params);
    // for(size_t i = 0; i < switchingKey.size(); i++){
    //     for(size_t j = 0; j < switchingKey[i].size(); j++){
    //         switchingKey[i][j].release();
    //     }
    // }
    // switchingKey.clear();
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "1\n";
    cout << "2: " << packedSIC[0].parms_id() << endl;

    time_start = chrono::high_resolution_clock::now();
    int rangeToCheck = 850; // range check is from [-rangeToCheck, rangeToCheck-1]
    newRangeCheckPVW(packedSIC, rangeToCheck, relin_keys, degree, context, params);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "2\n";
    cout << "3: " << packedSIC[0].parms_id() << endl;

    cout << decryptor.invariant_noise_budget(packedSIC[0]) << " bits left" << endl;
    // for(int i = 0; i < num_batches; i++)
        // evaluator.mod_switch_to_next_inplace(packedSIC[0]);
    //evaluator.mod_switch_to_next_inplace(packedSIC);
    cout << decryptor.invariant_noise_budget(packedSIC[0]) << " bits left" << endl;
    cout << "3: " << packedSIC[0].parms_id() << endl;

    return packedSIC[0];
}

void serverOperations2therest(Ciphertext& lhs, vector<vector<int>>& bipartite_map, Ciphertext& rhs, SecretKey& sk, // sk just for test
                        Ciphertext& packedSIC, const vector<vector<uint64_t>>& payload, const RelinKeys& relin_keys, const GaloisKeys& gal_keys,
                        const size_t& degree, const SEALContext& context, const SEALContext& context2, const PVWParam& params, const int numOfTransactions, size_t counter = 0, const int payloadSize = 306){

    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    // 5. generate bipartite graph. in real application, we return only the seed, but in demo, we directly give the graph
    time_start = chrono::high_resolution_clock::now();
    int repeatition = 5;
    int seed = 3;
    // bipartiteGraphGeneration(bipartite_map,numOfTransactions,100,repeatition,seed);
    vector<vector<int>> weights;
    bipartiteGraphWeightsGeneration(bipartite_map, weights,numOfTransactions,OMRtwoM,repeatition,seed);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "5\n";

    int step = 32;
    time_start = chrono::high_resolution_clock::now();
    // while(context.last_parms_id() != packedSIC.parms_id()){
        // evaluator.mod_switch_to_next_inplace(packedSIC);
    // }
    for(int i = 0; i < numOfTransactions; i += step){
        if (i % 256 == 0){
            cout << packedSIC.parms_id() << endl;
            cout << i <<" " << numOfTransactions << endl;
            chrono::high_resolution_clock::time_point time_start2, time_end2;
            chrono::microseconds time_diff2;
            // cout << i <<" " << numOfTransactions << endl;
            // 3 4 6 7. expand SIC; retrieve indices; retrieve payloads, shift the payload according to the graph; payload paking
            time_start2 = chrono::high_resolution_clock::now();
            vector<Ciphertext> expandedSIC;
            expandSIC(expandedSIC, packedSIC, gal_keys, int(degree), context, context2, step, i);
            time_end2 = chrono::high_resolution_clock::now();
            time_diff2 = chrono::duration_cast<chrono::microseconds>(time_end2 - time_start2);
            cout << time_diff2.count() << " " << "3\n";
            cout << expandedSIC[0].parms_id() << endl;
    
            time_start2 = chrono::high_resolution_clock::now();
            deterministicIndexRetrieval(lhs, expandedSIC, context, degree, i);
            time_end2 = chrono::high_resolution_clock::now();
            time_diff2 = chrono::duration_cast<chrono::microseconds>(time_end2 - time_start2);
            cout << time_diff2.count() << " " << "4\n";
    
            time_start2 = chrono::high_resolution_clock::now();
            vector<vector<Ciphertext>> payloadUnpacked;
            // payloadRetrievalOptimized(payloadUnpacked, payload, bipartite_map, expandedSIC, context, i);
            payloadRetrievalOptimizedwithWeights(payloadUnpacked, payload, bipartite_map, weights, expandedSIC, context, i);
            time_end2 = chrono::high_resolution_clock::now();
            time_diff2 = chrono::duration_cast<chrono::microseconds>(time_end2 - time_start2);
            cout << time_diff2.count() << " " << "6\n";
    
            time_start2 = chrono::high_resolution_clock::now();
            payloadPackingOptimized(rhs, payloadUnpacked, bipartite_map, degree, context, gal_keys, i);
            time_end2 = chrono::high_resolution_clock::now();
            time_diff2 = chrono::duration_cast<chrono::microseconds>(time_end2 - time_start2);
            cout << time_diff2.count() << " " << "7\n";
            cout << rhs.parms_id() << endl;
        } else {
            // cout << i <<" " << numOfTransactions << endl;
            // 3 4 6 7. expand SIC; retrieve indices; retrieve payloads, shift the payload according to the graph; payload paking
            // time_start = chrono::high_resolution_clock::now();
            vector<Ciphertext> expandedSIC;
            expandSIC(expandedSIC, packedSIC, gal_keys, int(degree), context, context2, step, i);
            // time_end = chrono::high_resolution_clock::now();
            // time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            // cout << time_diff.count() << " " << "3\n";

            // time_start = chrono::high_resolution_clock::now();
            deterministicIndexRetrieval(lhs, expandedSIC, context, degree, i);
            // time_end = chrono::high_resolution_clock::now();
            // time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            // cout << time_diff.count() << " " << "4\n";

            // time_start = chrono::high_resolution_clock::now();
            vector<vector<Ciphertext>> payloadUnpacked;
            // payloadRetrievalOptimized(payloadUnpacked, payload, bipartite_map, expandedSIC, context, i);
            payloadRetrievalOptimizedwithWeights(payloadUnpacked, payload, bipartite_map, weights, expandedSIC, context, i);
            // time_end = chrono::high_resolution_clock::now();
            // time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            // cout << time_diff.count() << " " << "6\n";

            // time_start = chrono::high_resolution_clock::now();
            payloadPackingOptimized(rhs, payloadUnpacked, bipartite_map, degree, context, gal_keys, i);
        }
        
    }
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "7\n";

    Ciphertext newtest = rhs;
    for(int i = 0; i < 16; i++)
        evaluator.add_inplace(newtest, rhs);

    while(context.last_parms_id() != rhs.parms_id()){
        cout << "!" << endl;
        evaluator.mod_switch_to_next_inplace(rhs);
        evaluator.mod_switch_to_next_inplace(lhs);
        evaluator.mod_switch_to_next_inplace(newtest);
    }
    //for(int i = 0; i < 2; i++){
    //    evaluator.mod_switch_to_next_inplace(rhs);
    //    evaluator.mod_switch_to_next_inplace(lhs);
    //}
    cout << rhs.parms_id() << endl;
    cout << decryptor.invariant_noise_budget(rhs) << " bits left" << endl;
    cout << decryptor.invariant_noise_budget(lhs) << " bits left" << endl;
    cout << decryptor.invariant_noise_budget(newtest) << " bits left" << endl;

    stringstream data_stream, data_stream2;
    cout << rhs.save(data_stream) << " bytes" << endl;
    cout << lhs.save(data_stream2) << " bytes" << endl;
}

void serverOperations3therest(vector<vector<Ciphertext>>& lhs, vector<Ciphertext>& lhsCounter, vector<vector<int>>& bipartite_map, Ciphertext& rhs, SecretKey& sk, // sk just for test
                        Ciphertext& packedSIC, const vector<vector<uint64_t>>& payload, const RelinKeys& relin_keys, const GaloisKeys& gal_keys, const PublicKey& public_key,
                        const size_t& degree, const SEALContext& context, const PVWParam& params, const int numOfTransactions, size_t counter = 0, const int payloadSize = 306){

    Decryptor decryptor(context, sk);
    Evaluator evaluator(context);

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    // 5. generate bipartite graph. in real application, we return only the seed, but in demo, we directly give the graph
    time_start = chrono::high_resolution_clock::now();
    int repeatition = 5;
    int seed = 3;
    // bipartiteGraphGeneration(bipartite_map,numOfTransactions,20,repeatition,seed);
    vector<vector<int>> weights;
    bipartiteGraphWeightsGeneration(bipartite_map, weights,numOfTransactions,20,repeatition,seed);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "5\n";

    time_start = chrono::high_resolution_clock::now();
    int step = 32;
    // size_t counter = 0;
    for(int i = 0; i < numOfTransactions; i += step){
        if (1){
            cout << i <<" " << numOfTransactions << endl;
            // cout << packedSIC.parms_id() << endl;
            chrono::high_resolution_clock::time_point time_start2, time_end2;
            chrono::microseconds time_diff2;
            // cout << i <<" " << numOfTransactions << endl;
            // 3 4 6 7. expand SIC; retrieve indices; retrieve payloads, shift the payload according to the graph; payload paking
            time_start2 = chrono::high_resolution_clock::now();
            vector<Ciphertext> expandedSIC;
            expandSIC(expandedSIC, packedSIC, gal_keys, int(degree), context, context, step, i);
            time_end2 = chrono::high_resolution_clock::now();
            time_diff2 = chrono::duration_cast<chrono::microseconds>(time_end2 - time_start2);
            cout << time_diff2.count() << " " << "3\n";
            // cout << expandedSIC[0].parms_id() << endl;
    
            time_start2 = chrono::high_resolution_clock::now();
            vector<vector<Ciphertext>> payloadUnpacked;
            // payloadRetrievalOptimized(payloadUnpacked, payload, bipartite_map, expandedSIC, context, i);
            payloadRetrievalOptimizedwithWeights(payloadUnpacked, payload, bipartite_map, weights, expandedSIC, context, i);
            time_end2 = chrono::high_resolution_clock::now();
            time_diff2 = chrono::duration_cast<chrono::microseconds>(time_end2 - time_start2);
            cout << time_diff2.count() << " " << "6\n";
    
            time_start2 = chrono::high_resolution_clock::now();
            payloadPackingOptimized(rhs, payloadUnpacked, bipartite_map, degree, context, gal_keys, i);
            time_end2 = chrono::high_resolution_clock::now();
            time_diff2 = chrono::duration_cast<chrono::microseconds>(time_end2 - time_start2);
            cout << time_diff2.count() << " " << "7\n";

            time_start2 = chrono::high_resolution_clock::now();
            randomizedIndexRetrieval(lhs, lhsCounter, expandedSIC, context, public_key, counter, degree, 5);
            time_end2 = chrono::high_resolution_clock::now();
            time_diff2 = chrono::duration_cast<chrono::microseconds>(time_end2 - time_start2);
            cout << time_diff2.count() << " " << "4\n";
            // cout << lhs[0].parms_id() << endl;
        } else {
            // cout << i <<" " << numOfTransactions << endl;
            // 3 4 6 7. expand SIC; retrieve indices; retrieve payloads, shift the payload according to the graph; payload paking
            // time_start = chrono::high_resolution_clock::now();
            vector<Ciphertext> expandedSIC;
            expandSIC(expandedSIC, packedSIC, gal_keys, int(degree), context, context, step, i);
            // time_end = chrono::high_resolution_clock::now();
            // time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            // cout << time_diff.count() << " " << "3\n";

            // time_start = chrono::high_resolution_clock::now();
            vector<vector<Ciphertext>> payloadUnpacked;
            // payloadRetrievalOptimized(payloadUnpacked, payload, bipartite_map, expandedSIC, context, i);
            payloadRetrievalOptimizedwithWeights(payloadUnpacked, payload, bipartite_map, weights, expandedSIC, context, i);
            // time_end = chrono::high_resolution_clock::now();
            // time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            // cout << time_diff.count() << " " << "6\n";

            // time_start = chrono::high_resolution_clock::now();
            payloadPackingOptimized(rhs, payloadUnpacked, bipartite_map, degree, context, gal_keys, i);

            // time_start = chrono::high_resolution_clock::now();
            randomizedIndexRetrieval(lhs, lhsCounter, expandedSIC, context, public_key, counter, degree, 5);
            // time_end = chrono::high_resolution_clock::now();
            // time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
            // cout << time_diff.count() << " " << "4\n";
        }
        
    }
    for(size_t i = 0; i < lhs.size(); i++){
            evaluator.transform_from_ntt_inplace(lhs[i][0]);
            evaluator.transform_from_ntt_inplace(lhs[i][1]);
            evaluator.transform_from_ntt_inplace(lhsCounter[i]);
    }
    
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " " << "7\n";

    while(context.last_parms_id() != rhs.parms_id()){
        cout << '?' << endl;
        for(size_t i = 0; i < lhs.size(); i++){
            for(size_t j = 0; j < lhs[i].size(); j++)
                evaluator.mod_switch_to_next_inplace(lhs[i][j]);
            evaluator.mod_switch_to_next_inplace(lhsCounter[i]);
        }
        evaluator.mod_switch_to_next_inplace(rhs);
    }
    //for(int i = 0; i < 2; i++){
    //    evaluator.mod_switch_to_next_inplace(rhs);
    //    evaluator.mod_switch_to_next_inplace(lhs);
    //}

    stringstream data_stream, data_stream2;
    cout << rhs.save(data_stream) << " bytes" << endl;
    cout << lhs[0][0].save(data_stream2) << " * 15 ~ bytes" << endl;
}

vector<vector<long>> receiverDecoding(Ciphertext& lhsEnc, vector<vector<int>>& bipartite_map, Ciphertext& rhsEnc,
                        const size_t& degree, const SecretKey& secret_key, const SEALContext& context, const int numOfTransactions, int seed = 3,
                        const int payloadUpperBound = 306, const int payloadSize = 306){

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;
    time_start = chrono::high_resolution_clock::now();

    bipartite_map.clear();
    int repeatition = 5;
    // bipartiteGraphGeneration(bipartite_map,numOfTransactions,100,repeatition,seed);
    vector<vector<int>> weights;
    bipartiteGraphWeightsGeneration(bipartite_map,weights,numOfTransactions,OMRtwoM,repeatition,seed);

    // 1. find pertinent indices
    map<int, int> pertinentIndices;
    decodeIndices(pertinentIndices, lhsEnc, numOfTransactions, degree, secret_key, context);
    for (map<int, int>::iterator it = pertinentIndices.begin(); it != pertinentIndices.end(); it++)
    {
        std::cout << it->first    // string (key)
                  << ':'
                  << it->second   // string's value 
                  << std::endl;
    }
    cout << "1\n";
	time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " microseconds for client to decode the result." << "\n";
        time_start = chrono::high_resolution_clock::now();

    // 2. forming rhs
    vector<vector<int>> rhs;
    formRhs(rhs, rhsEnc, secret_key, degree, context, OMRtwoM);
    cout << "2\n";

	time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " microseconds for client to decode the result." << "\n";
        time_start = chrono::high_resolution_clock::now();

    // 3. forming lhs
    vector<vector<int>> lhs;
    // formLhs(lhs, pertinentIndices, bipartite_map, 0, 100);
    formLhsWeights(lhs, pertinentIndices, bipartite_map, weights, 0, OMRtwoM);
    cout << "3\n";

	time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " microseconds for client to decode the result." << "\n";
	time_start = chrono::high_resolution_clock::now();

    // 4. solving equation
    auto newrhs = equationSolving(lhs, rhs, payloadSize);
    cout << "4\n";

    for(size_t i = 0; i < newrhs.size(); i++)
        cout << newrhs[i] << endl;

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " microseconds for client to decode the result." << "\n";

    return newrhs;
}

vector<vector<long>> receiverDecodingOMR3(vector<vector<Ciphertext>>& lhsEnc, vector<Ciphertext>& lhsCounter, vector<vector<int>>& bipartite_map, Ciphertext& rhsEnc,
                        const size_t& degree, const SecretKey& secret_key, const SEALContext& context, const int numOfTransactions, int seed = 3,
                        const int payloadUpperBound = 306, const int payloadSize = 306){

    chrono::high_resolution_clock::time_point time_start, time_end;
    chrono::microseconds time_diff;

    time_start = chrono::high_resolution_clock::now();
    bipartite_map.clear();
    int repeatition = 5;
    // bipartiteGraphGeneration(bipartite_map,numOfTransactions,20,repeatition,seed);
    vector<vector<int>> weights;
    bipartiteGraphWeightsGeneration(bipartite_map,weights,numOfTransactions,20,repeatition,seed);
    cout << "0\n";
	time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " microseconds for client to generat the bipartite graph." << "\n";
    time_start = chrono::high_resolution_clock::now();

    time_start = chrono::high_resolution_clock::now();
    // 1. find pertinent indices
    map<int, int> pertinentIndices;
    decodeIndicesRandom(pertinentIndices, lhsEnc, lhsCounter, degree, secret_key, context);
    for (map<int, int>::iterator it = pertinentIndices.begin(); it != pertinentIndices.end(); it++)
    {
        std::cout << it->first    // string (key)
                  << ':'
                  << it->second   // string's value 
                  << std::endl;
    }
    cout << "1\n";
	time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " microseconds for client to decode the result." << "\n";
        time_start = chrono::high_resolution_clock::now();

    // 2. forming rhs
    vector<vector<int>> rhs;
    formRhs(rhs, rhsEnc, secret_key, degree, context, 20);
    cout << "2\n";

	time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " microseconds for client to decode the result." << "\n";
        time_start = chrono::high_resolution_clock::now();

    // 3. forming lhs
    vector<vector<int>> lhs;
    // formLhs(lhs, pertinentIndices, bipartite_map, 0, 20);
    formLhsWeights(lhs, pertinentIndices, bipartite_map, weights, 0, 20);
    cout << "3\n";

	time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " microseconds for client to decode the result." << "\n";
	time_start = chrono::high_resolution_clock::now();

    // 4. solving equation
    auto newrhs = equationSolving(lhs, rhs, payloadSize);
    cout << "4\n";

    for(size_t i = 0; i < newrhs.size(); i++)
        cout << newrhs[i] << endl;

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << time_diff.count() << " microseconds for client to decode the result." << "\n";

    return newrhs;
}


bool checkRes(vector<vector<uint64_t>> expected, vector<vector<long>> res){
    for(size_t i = 0; i < expected.size(); i++){
        bool flag = false;
        for(size_t j = 0; j < res.size(); j++){
            if(expected[i][0] == uint64_t(res[j][0])){
                if(expected[i].size() != res[j].size())
                {
                    cerr << "expected and res length not the same" << endl;
                    return false;
                }
                for(size_t k = 1; k < res[j].size(); k++){
                    if(expected[i][k] != uint64_t(res[j][k]))
                        break;
                    if(k == res[j].size() - 1){
                        flag = true;
                    }
                }
            }
        }
        if(!flag)
            return false;
    }
    return true;
}

void compressedDetectKeySize(){
    // step 1. generate PVW sk TODO: change to PK
    // receiver side
    auto params = regevParam(10, 65537, 1.2, 8100); 
    auto sk = regevGenerateSecretKey(params);
    cout << "Finishing generating sk for PVW cts\n";

    // step 3. generate detection key
    // receiver side
    //chrono::high_resolution_clock::time_point time_start, time_end;
    //chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 27, \
                                                                            21, 60, 60, 60, 60, \
                                                                            60, 60, 60, 60, 60, 60,\
                                                                            32, 30, 60 }));
    parms.set_plain_modulus(65537);


	prng_seed_type seed;
    for (auto &i : seed)
    {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context); //auto qualifiers = context.first_context_data()->qualifiers();
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    // keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);
    GaloisKeys gal_keys;

    vector<int> steps = {0};
    for(int i = 1; i < 32768/2; i *= 8){
	//steps.push_back(i);
        steps.push_back(32768/2 - i);
    }
    for(size_t i = 0; i < steps.size(); i++)
        cout << steps[i] << " ";
    cout << endl;

    seal::Serializable<PublicKey> pk = keygen.create_public_key();
	seal::Serializable<RelinKeys> rlk = keygen.create_relin_keys();
	stringstream streamPK, streamRLK, streamRTK;
    cout << "pk size: " << pk.save(streamPK) << endl;;
	cout << "rlk size: " << rlk.save(streamRLK) << endl;
	cout << "rot key size: " << keygen.create_galois_keys(steps).save(streamRTK) << endl;

    public_key.load(context, streamPK);
    relin_keys.load(context, streamRLK);
    gal_keys.load(context, streamRTK); //size_t slot_count = batch_encoder.slot_count();
	seal::Serializable<Ciphertext>  switchingKeypacked = genPackedSwitchingKey(context, poly_modulus_degree, public_key, secret_key, sk, params);
	stringstream data_stream;
    cout << "LWE sk (encrypted under BFV) size: " << switchingKeypacked.save(data_stream) << " bytes" << endl;
}

void levelspecificDetectKeySize(){
    // step 1. generate PVW sk TODO: change to PK
    // receiver side
    auto params = regevParam(10, 65537, 1.2, 8100); 
    auto sk = regevGenerateSecretKey(params);
    cout << "Finishing generating sk for PVW cts\n";

    // step 3. generate detection key
    // receiver side
    //chrono::high_resolution_clock::time_point time_start, time_end;
    //chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 32768;
    auto degree = poly_modulus_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 28, 
                                                                            39, 60, 60, 60, 60, 
                                                                            60, 60, 60, 60, 60, 60,
                                                                            32, 30, 60 });
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(65537);


	prng_seed_type seed;
    for (auto &i : seed)
    {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context); //auto qualifiers = context.first_context_data()->qualifiers();
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    // keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);
    GaloisKeys gal_keys;

    vector<int> steps = {0};
    for(int i = 1; i < 32768/2; i *= 2){
	//steps.push_back(i);
        steps.push_back(32768/2 - i);
    }
    for(size_t i = 0; i < steps.size(); i++)
        cout << steps[i] << " ";
    cout << endl;

    stringstream lvlRTK, lvlRTK2;
    /////////////////////////////////////// Level specific keys
    vector<Modulus> coeff_modulus_next = coeff_modulus;
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 4, coeff_modulus_next.end()-1);
    EncryptionParameters parms_next = parms;
    parms_next.set_coeff_modulus(coeff_modulus_next);
    parms_next.set_random_generator(rng);
    SEALContext context_next = SEALContext(parms_next, true, sec_level_type::none);

    SecretKey sk_next;
    sk_next.data().resize(coeff_modulus_next.size() * degree);
    sk_next.parms_id() = context_next.key_parms_id();
    // This copies RNS components for first two primes.
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_next.size() - 1, sk_next.data().data());
    // This copies RNS components for the special prime.
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_next.data().data() + degree * (coeff_modulus_next.size() - 1));
    KeyGenerator keygen_next(context_next, sk_next); // Set a secret key.
    vector<int> steps_next = {0,1};
    cout << "level-RTK1: " << keygen_next.create_galois_keys(steps_next).save(lvlRTK) << endl;
        //////////////////////////////////////
    vector<Modulus> coeff_modulus_last = coeff_modulus;
    coeff_modulus_last.erase(coeff_modulus_last.begin() + 2, coeff_modulus_last.end()-1);
    EncryptionParameters parms_last = parms;
    parms_last.set_coeff_modulus(coeff_modulus_last);
    parms_last.set_random_generator(rng);
    SEALContext context_last = SEALContext(parms_last, true, sec_level_type::none);

    SecretKey sk_last;
    sk_last.data().resize(coeff_modulus_last.size() * degree);
    sk_last.parms_id() = context_last.key_parms_id();
    // This copies RNS components for first two primes.
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_last.size() - 1, sk_last.data().data());
    // This copies RNS components for the special prime.
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_last.data().data() + degree * (coeff_modulus_last.size() - 1));
    KeyGenerator keygen_last(context_last, sk_last); // Set a secret key.
    cout << "level-RTK2: " << keygen_last.create_galois_keys(steps).save(lvlRTK2) << endl;
    
    //////////////////////////////////////

    seal::Serializable<PublicKey> pk = keygen.create_public_key();
	seal::Serializable<RelinKeys> rlk = keygen.create_relin_keys();
	stringstream streamPK, streamRLK, streamRTK;
    cout << "pk size: " << pk.save(streamPK) << endl;;
	cout << "rlk size: " << rlk.save(streamRLK) << endl;
	cout << "rot key size: " << keygen.create_galois_keys(vector<int>({1})).save(streamRTK) << endl;

    public_key.load(context, streamPK);
    relin_keys.load(context, streamRLK);
    gal_keys.load(context, streamRTK); //size_t slot_count = batch_encoder.slot_count();
	seal::Serializable<Ciphertext>  switchingKeypacked = genPackedSwitchingKey(context, poly_modulus_degree, public_key, secret_key, sk, params);
	stringstream data_stream;
    cout << "LWE sk (encrypted under BFV) size: " << switchingKeypacked.save(data_stream) << " bytes" << endl;
}

void OMR2(){

    int numOfTransactions = 512;
    createDatabase(numOfTransactions, 306); // one time
    cout << "Finishing createDatabase\n";

    // step 1. generate PVW sk TODO: change to PK
    // receiver side
    auto params = PVWParam(100, 65537, 1.2, 8100, 4); 
    auto sk = PVWGenerateSecretKey(params);
    cout << "Finishing generating sk for PVW cts\n";

    // step 2. prepare transactions
    // general
    vector<PVWCiphertext> SICPVW;
    vector<vector<uint64_t>> payload;
    auto expected = preparinngTransactions(SICPVW, payload, sk, numOfTransactions, 15, params);
    cout << expected.size() << " pertinent msg: Finishing preparing transactions\n";



    // step 3. generate detection key
    // receiver side
    //chrono::high_resolution_clock::time_point time_start, time_end;
    //chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 32768;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 27, \
                                                                            22, 22, 31, 32, 31, 31, 31, 31, 31, 31, 31, \
                                                                            31, 31, 32, 31, 31, 31, 31, 31, 31, 31, 31,\
                                                                            21, 20, 32 }));
    parms.set_plain_modulus(65537);

	prng_seed_type seed;
    for (auto &i : seed)
    {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context); //auto qualifiers = context.first_context_data()->qualifiers();
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

    // Context data
    // auto context_data = context.first_context_data();
    // while (context_data)
    // {
    //     cout << " Level (chain index): " << context_data->chain_index();
    //     if (context_data->parms_id() == context.first_parms_id())
    //     {
    //         cout << " ...... first_context_data()" << endl;
    //     }
    //     else if (context_data->parms_id() == context.last_parms_id())
    //     {
    //         cout << " ...... last_context_data()" << endl;
    //     }
    //     else
    //     {
    //         cout << endl;
    //     }
    //     cout << "      parms_id: " << context_data->parms_id() << endl;
    //     cout << "      coeff_modulus primes: ";
    //     cout << hex;
    //     for (const auto &prime : context_data->parms().coeff_modulus())
    //     {
    //         cout << prime.value() << " ";
    //     }
    //     cout << dec << endl;
    //     cout << "\\" << endl;
    //     cout << " \\-->";

    //     /*
    //     Step forward in the chain.
    //     */
    //     context_data = context_data->next_context_data();
    // }
    // cout << " End of chain reached" << endl << endl;
    // end context data

    vector<Ciphertext> switchingKey;
    Ciphertext packedSIC;
    // {
        // MemoryPoolHandle my_pool = MemoryPoolHandle::New();
        // auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
    genSwitchingKeyPVWPacked(switchingKey, context, poly_modulus_degree, public_key, secret_key, sk, params);

    GaloisKeys gal_keys;
    vector<int> stepsfirst = {1};
    keygen.create_galois_keys(stepsfirst, gal_keys);
        
    auto temp = serverOperations1obtainPackedSIC(secret_key, SICPVW, switchingKey, relin_keys, gal_keys, poly_modulus_degree, context, params, numOfTransactions);
    // MemoryManager::SwitchProfile(std::move(old_prof));
    
    packedSIC = temp;
    // }

    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2){
	    steps.push_back(i);
    }
    keygen.create_galois_keys(steps, gal_keys);

    cout << "Finishing generating detection keys\n";

    // step 4. detector operations
    Ciphertext lhs, rhs;
    //evaluator.encrypt_zero(rhs);
    vector<vector<int>> bipartite_map;
    size_t counter = 0;
    serverOperations2therest(lhs, bipartite_map, rhs, secret_key,
                        packedSIC, payload, relin_keys, gal_keys,
                        poly_modulus_degree, context, context, params, numOfTransactions, counter);

    cout << decryptor.invariant_noise_budget(lhs) << " bits left" << endl;
    cout << decryptor.invariant_noise_budget(rhs) << " bits left" << endl;

    // step 5. receiver decoding
    auto res = receiverDecoding(lhs, bipartite_map, rhs,
                        poly_modulus_degree, secret_key, context, numOfTransactions);

    if(checkRes(expected, res))
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;
}

void OMR3(){

    int numOfTransactions = 128;
    createDatabase(numOfTransactions, 306); // one time
    cout << "Finishing createDatabase\n";

    // step 1. generate PVW sk TODO: change to PK
    // receiver side
    auto params = PVWParam(100, 65537, 1.2, 8100, 4); 
    auto sk = PVWGenerateSecretKey(params);
    cout << "Finishing generating sk for PVW cts\n";

    // step 2. prepare transactions
    // general
    vector<PVWCiphertext> SICPVW;
    vector<vector<uint64_t>> payload;
    auto expected = preparinngTransactions(SICPVW, payload, sk, numOfTransactions, 30, params);
    cout << "Finishing preparing transactions\n";



    // step 3. generate detection key
    // receiver side
    //chrono::high_resolution_clock::time_point time_start, time_end;
    //chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 28, \
                                                                            31, 27, 30, 30, 30, 30, 30, 30, 30, 30, \
                                                                            30, 30, 30, 30, 30, 30, 30, 30, 30, 30,\
                                                                            30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 25,\
                                                                            25, 35 }));
    parms.set_plain_modulus(65537);

	prng_seed_type seed;
    for (auto &i : seed)
    {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context); //auto qualifiers = context.first_context_data()->qualifiers();
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

    vector<vector<Ciphertext>> switchingKey;
    genSwitchingKeyPVW(switchingKey, context, poly_modulus_degree, public_key, sk, params);

    auto packedSIC = serverOperations1Previous(secret_key, SICPVW, switchingKey, relin_keys, poly_modulus_degree, context, params, numOfTransactions);

    GaloisKeys gal_keys;
    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2){
	    steps.push_back(i);
    }
    keygen.create_galois_keys(steps, gal_keys);

    cout << "Finishing generating detection keys\n";

    // step 4. detector operations

    Ciphertext rhs;
    vector<vector<Ciphertext>> lhs;
    vector<Ciphertext> lhsctr;
    //evaluator.encrypt_zero(rhs);
    vector<vector<int>> bipartite_map;
    size_t counter = 0;
    serverOperations3therest(lhs, lhsctr, bipartite_map, rhs, secret_key,
                        packedSIC, payload, relin_keys, gal_keys, public_key,
                        poly_modulus_degree, context, params, numOfTransactions, counter);

    cout << decryptor.invariant_noise_budget(lhs[0][0]) << " bits left" << endl;
    cout << decryptor.invariant_noise_budget(rhs) << " bits left" << endl;

    // step 5. receiver decoding
    auto res = receiverDecodingOMR3(lhs, lhsctr, bipartite_map, rhs,
                        poly_modulus_degree, secret_key, context, numOfTransactions);

    if(checkRes(expected, res))
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;
}

void OMR2multi(){

    // int numcores = 4;

    int numOfTransactions = 256*numcores;
    createDatabase(numOfTransactions, 306); // one time
    cout << "Finishing createDatabase\n";

    // step 1. generate PVW sk TODO: change to PK
    // receiver side
    auto params = PVWParam(100, 65537, 1.2, 8100, 4); 
    auto sk = PVWGenerateSecretKey(params);
    cout << "Finishing generating sk for PVW cts\n";

    // step 2. prepare transactions
    // general
    vector<PVWCiphertext> SICPVW;
    vector<vector<uint64_t>> payload;
    auto expected = preparinngTransactions(SICPVW, payload, sk, numOfTransactions, 10, params, true);
    cout << expected.size() << " pertinent msg: Finishing preparing transactions\n";



    // step 3. generate detection key
    // receiver side
    //chrono::high_resolution_clock::time_point time_start, time_end;
    //chrono::microseconds time_diff;
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 32768;
    auto degree = poly_modulus_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 28, 
                                                                            39, 60, 60, 60, 60, 
                                                                            60, 60, 60, 60, 60, 60,
                                                                            32, 30, 60 });
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(65537);


	prng_seed_type seed;
    for (auto &i : seed)
    {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

    SEALContext context(parms, true, sec_level_type::none);
    print_parameters(context); //auto qualifiers = context.first_context_data()->qualifiers();
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


    vector<Ciphertext> switchingKey;
    Ciphertext packedSIC;
    // {
        // MemoryPoolHandle my_pool = MemoryPoolHandle::New();
        // auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
    switchingKey.resize(params.ell);
    genSwitchingKeyPVWPacked(switchingKey, context, poly_modulus_degree, public_key, secret_key, sk, params);
    
    vector<vector<PVWCiphertext>> SICPVW_multicore(numcores);
    vector<vector<vector<uint64_t>>> payload_multicore(numcores);
    for(int i = 0; i < numcores; i++){
        SICPVW_multicore[i] = vector<PVWCiphertext>(SICPVW.begin()+i*numOfTransactions/numcores, SICPVW.begin()+(i+1)*numOfTransactions/numcores);
        payload_multicore[i] = vector<vector<uint64_t>>(payload.begin()+i*numOfTransactions/numcores, payload.begin()+(i+1)*numOfTransactions/numcores);
    }

    GaloisKeys gal_keys;
    vector<int> stepsfirst = {1};
    keygen.create_galois_keys(stepsfirst, gal_keys);

    /////////////////////////////////////////////////////////////// Rot Key gen
    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2){
	    steps.push_back(i);
    }
    // keygen.create_galois_keys(steps, gal_keys);

    cout << "Finishing generating detection keys\n";

    /////////////////////////////////////// Level specific keys
    vector<Modulus> coeff_modulus_next = coeff_modulus;
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 4, coeff_modulus_next.end()-1);
    EncryptionParameters parms_next = parms;
    parms_next.set_coeff_modulus(coeff_modulus_next);
    SEALContext context_next = SEALContext(parms_next, true, sec_level_type::none);

    SecretKey sk_next;
    sk_next.data().resize(coeff_modulus_next.size() * degree);
    sk_next.parms_id() = context_next.key_parms_id();
    // This copies RNS components for first two primes.
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_next.size() - 1, sk_next.data().data());
    // This copies RNS components for the special prime.
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_next.data().data() + degree * (coeff_modulus_next.size() - 1));
    cout << "!!!---" << endl;
    KeyGenerator keygen_next(context_next, sk_next); // Set a secret key.
    vector<int> steps_next = {0,1};
    keygen_next.create_galois_keys(steps_next, gal_keys_next);
        //////////////////////////////////////
    vector<Modulus> coeff_modulus_last = coeff_modulus;
    coeff_modulus_last.erase(coeff_modulus_last.begin() + 2, coeff_modulus_last.end()-1);
    EncryptionParameters parms_last = parms;
    parms_last.set_coeff_modulus(coeff_modulus_last);
    SEALContext context_last = SEALContext(parms_last, true, sec_level_type::none);

    SecretKey sk_last;
    sk_last.data().resize(coeff_modulus_last.size() * degree);
    sk_last.parms_id() = context_last.key_parms_id();
    // This copies RNS components for first two primes.
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_last.size() - 1, sk_last.data().data());
    // This copies RNS components for the special prime.
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_last.data().data() + degree * (coeff_modulus_last.size() - 1));
    KeyGenerator keygen_last(context_last, sk_last); // Set a secret key.
    keygen_last.create_galois_keys(steps, gal_keys_last);
    
    //////////////////////////////////////

    vector<Ciphertext> temps(numcores);

    NTL::SetNumThreads(numcores);
    int batchcounter = 0;
    while(batchcounter < num_batches){
    batchcounter++;
    cout << "Phase 2-3, batch " << batchcounter << " for 4 cores" << endl;
    MemoryPoolHandle my_pool = MemoryPoolHandle::New();
    auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++){
        // std::chrono::seconds dura(15*i);
        // std::this_thread::sleep_for( dura );
        cout << "!!! " << i << endl;
        temps[i] = serverOperations1obtainPackedSIC(secret_key, SICPVW_multicore[i], switchingKey, relin_keys, gal_keys,
                                                        poly_modulus_degree, context, params, numOfTransactions/numcores);
    }
    NTL_EXEC_RANGE_END;
    MemoryManager::SwitchProfile(std::move(old_prof));
    }
    
    // MemoryManager::SwitchProfile(std::move(old_prof));
    
    packedSIC = temps[0];
    // }

    // step 4. detector operations
    vector<Ciphertext> lhs_multi(numcores), rhs_multi(numcores);
    vector<vector<vector<int>>> bipartite_map(numcores);
    vector<size_t> counter(numcores);

    batchcounter = 0;
    while(batchcounter < num_batches){
    batchcounter++;
    cout << "Phase 2-3, batch " << batchcounter << " for 4 cores" << endl;
    NTL_EXEC_RANGE(numcores, first, last);
    for(int i = first; i < last; i++){
        MemoryPoolHandle my_pool = MemoryPoolHandle::New();
        auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
        //evaluator.encrypt_zero(rhs);
        serverOperations2therest(lhs_multi[i], bipartite_map[i], rhs_multi[i], sk_next,
                            temps[i], payload_multicore[i], relin_keys, gal_keys_next,
                            poly_modulus_degree, context_next, context_last, params, numOfTransactions/numcores, counter[i]);
        MemoryManager::SwitchProfile(std::move(old_prof));
    }
    NTL_EXEC_RANGE_END;
    }

    // step 5. receiver decoding
    auto res = receiverDecoding(lhs_multi[0], bipartite_map[0], rhs_multi[0],
                        poly_modulus_degree, secret_key, context, numOfTransactions/numcores);

    if(checkRes(expected, res))
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;
    
    for(size_t i = 0; i < res.size(); i++){

    }
    
}


int main(){
    // testFunc();
    // testCalIndices();
    // return 0;
    // degreeUpToTest();

    // 1. To check compressed detection size
    levelspecificDetectKeySize(); 

    // 3. To run OMR3
    // OMR3();

    // 2. To run OMR2
    // OMR2();

    // multi-thread test OMR2
    OMR2multi(); 

    
}
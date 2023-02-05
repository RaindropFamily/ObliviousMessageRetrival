#pragma once

#include<iostream>
#include<fstream>
#include<string>
#include "MRE.h"
#include "scheme.h"
#include "MathUtil.h"
using namespace std;

void createDatabase(int num_of_transactions = 524288, int payloadSize = 306){
    for(int i = 0; i < num_of_transactions; i++){
        ofstream datafile;
        auto tempi = i % 65537;
        datafile.open ("../data/payloads/"+to_string(i)+".txt");
        for(int j = 0; j < payloadSize; j++){
            datafile << (65537 - tempi+j)%65537 << "\n";
        }
        datafile.close();
    }
}

vector<uint64_t> loadDataSingle(int i, const string folder = "payloads", int payloadSize = 306) {
    vector<uint64_t> ret;

    ret.resize(payloadSize);
    ifstream datafile;
    datafile.open ("../data/"+folder+"/"+to_string(i)+".txt");
    for(int j = 0; j < payloadSize; j++){
        datafile >> ret[j];
    }
    datafile.close();

    return ret;
}


void saveSK(const PVWParam& param, const PVWsk sk) {
    ofstream datafile;
    datafile.open ("../data/clues/sk.txt");
    for (int i = 0; i < param.ell; i++) {
        for (int j = 0; j < param.n; j++) {
            datafile << sk[i][j].ConvertToInt() << "\n";
        }
    }
    datafile.close();
}


PVWsk loadSK(const PVWParam& param) {
    PVWsk sk(param.ell);
    ifstream datafile;
    datafile.open ("../data/clues/sk.txt");
    for (int i = 0; i < param.ell; i++) {
        sk[i] = NativeVector(param.n);
        for (int j = 0; j < param.n; j++) {
            uint64_t temp;
            datafile >> temp;
            sk[i][j] = temp;
        }
    }
    datafile.close();

    return sk;
}


void saveClues(const PVWCiphertext& clue, int transaction_num){
    ofstream datafile;
    datafile.open ("../data/clues/"+to_string(transaction_num)+".txt");

    for (size_t i = 0; i < clue.a.GetLength(); i++) {
        datafile << clue.a[i].ConvertToInt() << "\n";
    }
    for (size_t i = 0; i < clue.b.GetLength(); i++) {
        datafile << clue.b[i].ConvertToInt() << "\n";
    }

    datafile.close();
}

void saveGroupClues(const vector<vector<long>>& cluePolynomial, int transaction_num){
    ofstream datafile;
    datafile.open ("../data/cluePoly/"+to_string(transaction_num)+".txt");

    for(size_t i = 0; i < cluePolynomial.size(); i++){
        for (size_t j = 0; j < cluePolynomial[0].size(); j++) {
            datafile << cluePolynomial[i][j] << "\n";
        }
    }

    datafile.close();
}

void saveCluesWithRandomness(const PVWCiphertext& clue, const int transaction_num) {
    ofstream datafile;
    datafile.open ("../data/clues/"+to_string(transaction_num)+".txt");

    for (size_t i = 0; i < clue.a.GetLength(); i++) {
        datafile << clue.a[i].ConvertToInt() << "\n";
    }
    for (size_t i = 0; i < clue.b.GetLength(); i++) {
        datafile << clue.b[i].ConvertToInt() << "\n";
    }
    datafile.close();
}

void loadData(vector<vector<uint64_t>>& msgs, const int& start, const int& end, string folder = "payloads", int payloadSize = 306, int partySize = 1){
    msgs.resize((end-start) * partySize);
    for(int i = start; i < end; i++){
        msgs[i-start].resize(payloadSize);
        ifstream datafile;

        // duplicate each unique message |partySize| times
        for (int p = 0; p < partySize; p++) {
            datafile.open("../data/"+folder+"/"+to_string(i)+".txt");
            datafile.seekg(0, ios::beg);
            for(int j = 0; j < payloadSize; j++){
                datafile >> msgs[(i-start) * partySize + p][j];
            }
            datafile.close();
        }
    }
}


void loadClues(vector<PVWCiphertext>& clues, const int& start, const int& end, const PVWParam& param, int party_ind = 0, int partySize = 1){
    clues.resize(end-start);
    for(int i = start; i < end; i++){
        clues[i-start].a = NativeVector(param.n);
        clues[i-start].b = NativeVector(param.ell);

        ifstream datafile;
        datafile.open ("../data/clues/"+to_string(i * partySize + party_ind)+".txt");

        for(int j = 0; j < param.n; j++){
            uint64_t temp;
            datafile >> temp;
            clues[i-start].a[j] = temp;
        }

        for(int j = 0; j < param.ell; j++){
            uint64_t temp;
            datafile >> temp;
            clues[i-start].b[j] = temp;
        }
    }
}


/**
 * @brief For ObliviousMultiplexer, the clue includes ((param.n + param.ell) * party_size_glb + prng_seed_count) elements.
 * Different from loadData, this function load the cluePoly.txt into two separate data structures, one is the normal cluPoly CM of size (clue_length) x (party_size),
 * one is randomness, and then use the randomness to generate a random matrix R of size (party_size * id_size) x party_size.
 * The resulted matrix CM*R^T, of size (clue_length) x (party_size * id_size).
 * Different from loadObliviousMultiplexerClues, this one does not multiply the result with target Id, since the later one is encrypted.
 *
 * This function will save the processed matrix back to the file system
 *
 * @param randomness 
 * @param start 
 * @param end 
 * @param payloadSize = clueLength * T', where T' = party_size + extra_secure_length
 */
vector<vector<uint64_t>> loadOMClue_CluePoly(const PVWParam& params, const int& start, const int& end, int payloadSize) {
    vector<vector<uint64_t>> clues(end-start);

    for(int i = start; i < end; i++){
        clues[i-start].resize(payloadSize);

        ifstream datafile;

        datafile.open("../data/cluePoly/"+to_string(i)+".txt");
        datafile.seekg(0, ios::beg);
        for(int j = 0; j < payloadSize; j++){
            datafile >> clues[i-start][j];
        }
        datafile.close();
    }

    return clues;
}

vector<vector<uint64_t>> loadOMClue_Randomness(const PVWParam& params, const int& start, const int& end, int payloadSize) {
    vector<vector<uint64_t>> clues(end-start), randomness(end-start);

    for(int i = start; i < end; i++){
        clues[i-start].resize(payloadSize - prng_seed_uint64_count);
        randomness[i-start].resize(prng_seed_uint64_count);

        ifstream datafile;

        datafile.open("../data/cluePoly/"+to_string(i)+".txt");
        datafile.seekg(0, ios::beg);
        for(int j = 0; j < payloadSize; j++){
	    if (j < (int) (payloadSize - prng_seed_uint64_count)) {
                datafile >> clues[i-start][j];
            } else {
                datafile >> randomness[i-start][j - (payloadSize - prng_seed_uint64_count)];
            }
        }
        datafile.close();
    }

    return randomness;
}


vector<vector<int>> loadFixedGroupClues(const int& start, const int& end, const PVWParam& param, const int partySize = party_size_glb, const int partialSize = partial_size_glb){
    vector<vector<int>> result(end-start);
    int a1_size = param.n, a2_size = param.ell * partialSize;

    vector<int> old_a2(a2_size);

    for(int i = start; i < end; i++){
        result[i-start].resize(a1_size + a2_size + param.ell);

        ifstream datafile;
        datafile.open ("../data/clues/"+to_string(i)+".txt");

        for (int j = 0; j < a1_size + a2_size; j++) {
            uint64_t temp;
            datafile >> temp;
            result[i-start][j] = temp;
        }

        for (int j = 0; j < param.ell; j++) {
            uint64_t temp;
            datafile >> temp;
            result[i-start][j + a1_size + a2_size] = temp;
        }

        datafile.close();
    }

    return result;
}

// similar to loadClues but under Oblivious Multiplexer, load the clue polynomial coefficient matrix, and compute the clues based on target ID
void loadObliviousMultiplexerClues(vector<int> pertinent_msgs, vector<PVWCiphertext>& clues, const vector<int>& targetId, const int& start,
                                const int& end, const PVWParam& param, int clueLength = 454) {
    clues.resize(end-start);

    for (int i = start; i < end; i++) {
        prng_seed_type seed;
        vector<uint64_t> polyFlat = loadDataSingle(i, "cluePoly", clueLength * (party_size_glb + secure_extra_length_glb) + prng_seed_uint64_count);

        int prng_seed_uint64_counter = 0;
        for (auto &s : seed) {
            s = polyFlat[clueLength * (party_size_glb + secure_extra_length_glb) + prng_seed_uint64_counter];
            prng_seed_uint64_counter++;
        }

        vector<vector<int>> ids(1);
        ids[0] = targetId;
        vector<vector<int>> compressed_id = compressVector(param, seed, generateExponentialExtendedVector(param, ids));

        vector<long> res(clueLength, 0);
        int res_ind = 0;

        clues[i-start].a = NativeVector(param.n);
        clues[i-start].b = NativeVector(param.ell);

        for (int c = 0; c < clueLength; c++) {
	  for(int j = 0; j < (int)compressed_id[0].size(); j++) {
                res[c] = (res[c] + polyFlat[c * compressed_id[0].size() + j] * compressed_id[0][j]) % param.q;
                res[c] = res[c] < 0 ? res[c] + param.q : res[c];
            }
        }

        for(int j = 0; j < param.n; j++, res_ind++){
            clues[i-start].a[j] = res[res_ind];
        }

        for(int j = 0; j < param.ell; j++, res_ind++){
            clues[i-start].b[j] = res[res_ind];
        }
    }
}

uint64_t extractEntryFromRandomMatrix(const PVWParam& params, const vector<uint64_t>& randomness, const int r, const int c) {
    prng_seed_type seed;
    int prng_seed_uint64_counter = 0;
    for (auto &i : seed) {
        i = randomness[prng_seed_uint64_counter];
        prng_seed_uint64_counter++;
    }

    vector<vector<uint64_t>> random_Z = generateRandomMatrixWithSeed(params, seed, party_size_glb * id_size_glb,
                                                                     party_size_glb + secure_extra_length_glb);

    return random_Z[c][r]; // transpose with the original random Matrix, which is of size (TI x T')
}


vector<vector<vector<uint64_t>>> batchLoadRandomMatrices(const PVWParam& param, const int start, const int end, const vector<vector<uint64_t>>& randomness) {
    prng_seed_type seed;
    int prng_seed_uint64_counter = 0;

    vector<vector<vector<uint64_t>>> random_matrices(end-start);

    for (int c = start; c < end; c++) {
        prng_seed_uint64_counter = 0;
        for (auto &i : seed) {
            i = randomness[c][prng_seed_uint64_counter];
            prng_seed_uint64_counter++;
        }

        random_matrices[c - start] = generateRandomMatrixWithSeed(param, seed, party_size_glb * id_size_glb,
                                                                  party_size_glb + secure_extra_length_glb);
    }

    return random_matrices;
}

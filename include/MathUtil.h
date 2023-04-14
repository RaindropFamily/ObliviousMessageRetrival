#pragma once

#include <openssl/aes.h>

using namespace std;

void random_bytes(unsigned char *buf, size_t count) {
    random_device rd("/dev/urandom");
    while (count >= 4) {
        *reinterpret_cast<uint32_t *>(buf) = rd();
        buf += 4;
        count -= 4;
    }
    if (count) {
        uint32_t last = rd();
        memcpy(buf, &last, count);
    }
}

int convertChar2Uint64(unsigned char *ciphertext, const unsigned long long clen, const uint64_t mod = 65537) {
    uint64_t a = 0;
    int cnt = clen-1;
    while (cnt >= 0) {
        for( int i = 7; i >= 0; i-- ) {
            a = (a << 1);
            a = a ^ (( ciphertext[cnt] >> i ) & 1 ? 1 : 0);
        }
        cnt--;
    }
    return a % mod;
}

vector<vector<int>> generateExponentialExtendedVector(const PVWParam& params, vector<vector<int>> old_vec, const int extend_size = party_size_glb) {
    vector<vector<int>> extended_vec(old_vec.size());
    for (int i = 0; i < (int) old_vec.size(); i++) {
        extended_vec[i].resize(old_vec[i].size() * extend_size);
        for (int j = 0; j < (int) extended_vec[i].size(); j++) {
            extended_vec[i][j] = power(old_vec[i][j / extend_size], j % extend_size + 1, params.q);
        }
    }

    return extended_vec;
}

vector<vector<uint64_t>> generateRandomMatrixWithAES(const unsigned char *key, int row, int col, bool print = false) {
    vector<vector<uint64_t>> random_matrix(row, vector<uint64_t>(col));

    unsigned char out[32];
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
    unsigned char* input_buffer;
    uint64_t input[2];
    input[1] = 0;
    for (int i = 0; i < (int) random_matrix.size(); i++) {
        for (int j = 0; j < (int) random_matrix[0].size(); j++) {
            input[0] = i * random_matrix[0].size() + j;
            input_buffer = (unsigned char*)input;
            AES_ecb_encrypt(input_buffer, out, &aes_key, AES_ENCRYPT);
            random_matrix[i][j] = convertChar2Uint64(out, 8);
        }
    }
    return random_matrix;
}

vector<vector<uint64_t>> generateRandomMatrixWithSeed(const PVWParam& params, prng_seed_type seed, int row, int col) {
    vector<vector<uint64_t>> random_matrix(row, vector<uint64_t>(col));

    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    RandomToStandardAdapter engine(rng->create());
    uniform_int_distribution<uint64_t> dist(0, params.q - 1);

    for (int i = 0; i < (int) random_matrix.size(); i++) {
      for (int j = 0; j < (int) random_matrix[0].size(); j++) {
            random_matrix[i][j] = dist(engine);
        }
    }

    return random_matrix;
}

vector<vector<int>> compressVector(const PVWParam& params, prng_seed_type seed, vector<vector<int>> ids, const int compress_size = party_size_glb + secure_extra_length_glb) {
    vector<vector<int>> compressed_result(ids.size(), vector<int>(compress_size));
    vector<vector<uint64_t>> random_matrix = generateRandomMatrixWithSeed(params, seed, ids[0].size(), compress_size);

    for (int i = 0; i < (int) compressed_result.size(); i++) {
      for (int j = 0; j < (int) compressed_result[0].size(); j++) {
            long temp = 0;
            for (int k = 0; k < (int) random_matrix.size(); k++) {
                temp = (temp + ids[i][k] * random_matrix[k][j]) % params.q;
                temp = temp < 0 ? temp + params.q : temp;
            }
            compressed_result[i][j] = temp;
        }
    }

    return compressed_result;
}

vector<vector<int>> compressVectorByAES(const PVWParam& params, unsigned char *key, vector<vector<int>> ids,
                                        const int compress_size = party_size_glb + secure_extra_length_glb, bool print = false) {
    
    vector<vector<int>> compressed_result(ids.size(), vector<int>(compress_size));
    vector<vector<uint64_t>> random_matrix = generateRandomMatrixWithAES(key, ids[0].size(), compress_size, print);

    for (int i = 0; i < (int) compressed_result.size(); i++) {
      for (int j = 0; j < (int) compressed_result[0].size(); j++) {
            long temp = 0;
            for (int k = 0; k < (int) random_matrix.size(); k++) {
                temp = (temp + ids[i][k] * random_matrix[k][j]) % params.q;
                temp = temp < 0 ? temp + params.q : temp;
            }
            compressed_result[i][j] = temp;
        }
    }

    return compressed_result;
}

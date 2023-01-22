#pragma once

#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

using namespace std;

void incrementAESCounterValue(unsigned char *output, unsigned char *base_ctr, uint64_t value) {
    for (int i = 0; i < 8; i++) {
        int temp = value & 255;
        output[i] = static_cast<unsigned char>(base_ctr[i] + temp);
        value = value >> 8;
    }
    for (int i = 8; i < EVP_MAX_IV_LENGTH; i++) {
        memcpy(output+i, base_ctr+i, sizeof(unsigned char));
    }
}

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
    int cnt = 0;
    while (cnt < (int) clen) {
        for( int i = 7; i >= 0; i-- ) {
            a = (a << 1);
            a = a ^ (( ciphertext[cnt] >> i ) & 1 ? 1 : 0);
        }
        ++cnt;
    }
    return a % mod;
}

int generateRandomElement(EVP_CIPHER_CTX *ctx, EVP_CIPHER *aes_128ctr_cipher, OSSL_PARAM *openssl_params, unsigned char* key,
                          uint64_t ctr, unsigned char *ciphertext, unsigned char *counter) {
    int outlen;
    incrementAESCounterValue(counter, base_ctr_glb, ctr);
    EVP_EncryptInit_ex2(ctx, aes_128ctr_cipher, key, initial_pt_glb, openssl_params);
    EVP_EncryptUpdate(ctx, ciphertext, &outlen, counter, AES_KEY_SIZE);

    if (outlen < AES_KEY_SIZE) {
        cout << "Warning!!! AES ciphertext less than 16 bytes, actual: " << outlen << endl;
    }
    return convertChar2Uint64(ciphertext, 8);
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

vector<vector<uint64_t>> generateRandomMatrixWithAES(unsigned char *key, int row, int col, bool print = false) {
    vector<vector<uint64_t>> random_matrix(row, vector<uint64_t>(col));

    // prepare AES 128 GCM context for openssl EVP interface
    OSSL_LIB_CTX *libctx = NULL;
    EVP_CIPHER *aes_128ctr_cipher = NULL;
    const char *propq = NULL;
    OSSL_PARAM openssl_params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};
    aes_128ctr_cipher = EVP_CIPHER_fetch(libctx, "AES-128-GCM", propq);

    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();

    unsigned char* temp = (unsigned char *) malloc(sizeof(unsigned char) * EVP_MAX_IV_LENGTH);
    unsigned char ciphertext[16];
    for (int i = 0; i < (int) random_matrix.size(); i++) {
        for (int j = 0; j < (int) random_matrix[0].size(); j++) {
           random_matrix[i][j] = generateRandomElement(context, aes_128ctr_cipher, openssl_params, key, (uint64_t) (i*random_matrix[0].size() + j), ciphertext, temp);
        }
    }
    free(temp);
    EVP_CIPHER_free(aes_128ctr_cipher);
    EVP_CIPHER_CTX_free(context);
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

    // if (print) cout << random_matrix << endl;

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

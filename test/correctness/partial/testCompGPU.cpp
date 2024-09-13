#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <cassert>
#include "optimized/HomCompOPT.h"  
#include "utils.h"

void test_HomCompLe(const TFheGateBootstrappingCloudKeySet* bk, const TFheGateBootstrappingSecretKeySet* key, int num_of_threads, bool use_gpu) {
    const int length = 16;  // Bit length of the numbers

    // Test 1: a <= b, where a = 3.5, b = 3.5 (Equal)
    LweSample* a = encryptBoolean(encodeDouble(length, 3.5), length, bk->params, key);
    LweSample* b = encryptBoolean(encodeDouble(length, 3.5), length, bk->params, key);
    LweSample* result = new_gate_bootstrapping_ciphertext_array(1, bk->params);

    if (use_gpu) {
        HomCompLeGPU(result, a, b, length, bk, num_of_threads);
    } else {
        HomCompLeOPT(result, a, b, length, bk, num_of_threads);
    }
    assert(bootsSymDecrypt(result, key) == 1);  // Should be true since a <= b

    // Test 2: a <= b, where a = 3.5, b = 5.5 (Less than)
    b = encryptBoolean(encodeDouble(length, 5.5), length, bk->params, key);
    if (use_gpu) {
        HomCompLeGPU(result, a, b, length, bk, num_of_threads);
    } else {
        HomCompLeOPT(result, a, b, length, bk, num_of_threads);
    }
    assert(bootsSymDecrypt(result, key) == 1);  // Should be true since a <= b

    // Test 3: a <= b, where a = 5.5, b = 3.5 (Greater than)
    a = encryptBoolean(encodeDouble(length, 5.5), length, bk->params, key);
    b = encryptBoolean(encodeDouble(length, 3.5), length, bk->params, key);
    if (use_gpu) {
        HomCompLeGPU(result, a, b, length, bk, num_of_threads);
    } else {
        HomCompLeOPT(result, a, b, length, bk, num_of_threads);
    }
    assert(bootsSymDecrypt(result, key) == 0);  // Should be false since a > b

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(1, result);
    delete_gate_bootstrapping_ciphertext_array(length, a);
    delete_gate_bootstrapping_ciphertext_array(length, b);

    std::cout << (use_gpu ? "HomCompLeGPU" : "HomCompLeOPT") << " passed all tests." << std::endl;
}

void test_HomCompL(const TFheGateBootstrappingCloudKeySet* bk, const TFheGateBootstrappingSecretKeySet* key, int num_of_threads, bool use_gpu) {
    const int length = 16;  // Bit length of the numbers

    // Test 1: a < b, where a = 3.5, b = 3.5 (Equal)
    LweSample* a = encryptBoolean(encodeDouble(length, 3.5), length, bk->params, key);
    LweSample* b = encryptBoolean(encodeDouble(length, 3.5), length, bk->params, key);
    LweSample* result = new_gate_bootstrapping_ciphertext_array(1, bk->params);

    if (use_gpu) {
        HomCompLGPU(result, a, b, length, bk, num_of_threads);
    } else {
        HomCompLOPT(result, a, b, length, bk, num_of_threads);
    }
    assert(bootsSymDecrypt(result, key) == 0);  // Should be false since a == b

    // Test 2: a < b, where a = 3.5, b = 5.5 (Less than)
    b = encryptBoolean(encodeDouble(length, 5.5), length, bk->params, key);
    if (use_gpu) {
        HomCompLGPU(result, a, b, length, bk, num_of_threads);
    } else {
        HomCompLOPT(result, a, b, length, bk, num_of_threads);
    }
    assert(bootsSymDecrypt(result, key) == 1);  // Should be true since a < b

    // Test 3: a < b, where a = 5.5, b = 3.5 (Greater than)
    a = encryptBoolean(encodeDouble(length, 5.5), length, bk->params, key);
    b = encryptBoolean(encodeDouble(length, 3.5), length, bk->params, key);
    if (use_gpu) {
        HomCompLGPU(result, a, b, length, bk, num_of_threads);
    } else {
        HomCompLOPT(result, a, b, length, bk, num_of_threads);
    }
    assert(bootsSymDecrypt(result, key) == 0);  // Should be false since a > b

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(1, result);
    delete_gate_bootstrapping_ciphertext_array(length, a);
    delete_gate_bootstrapping_ciphertext_array(length, b);

    std::cout << (use_gpu ? "HomCompLGPU" : "HomCompLOPT") << " passed all tests." << std::endl;
}

void test_HomEqui(const TFheGateBootstrappingCloudKeySet* bk, const TFheGateBootstrappingSecretKeySet* key, int num_of_threads, bool use_gpu) {
    const int length = 16;  // Bit length of the numbers

    // Test 1: a == b, where a = 3.5, b = 3.5 (Equal)
    LweSample* a = encryptBoolean(encodeDouble(length, 3.5), length, bk->params, key);
    LweSample* b = encryptBoolean(encodeDouble(length, 3.5), length, bk->params, key);
    LweSample* result = new_gate_bootstrapping_ciphertext_array(1, bk->params);

    if (use_gpu) {
        HomEquiGPU(result, a, b, length, bk, num_of_threads);
    } else {
        HomEquiOPT(result, a, b, length, bk, num_of_threads);
    }
    assert(bootsSymDecrypt(result, key) == 1);  // Should be true since a == b

    // Test 2: a == b, where a = 3.5, b = 5.5 (Not equal)
    b = encryptBoolean(encodeDouble(length, 5.5), length, bk->params, key);
    if (use_gpu) {
        HomEquiGPU(result, a, b, length, bk, num_of_threads);
    } else {
        HomEquiOPT(result, a, b, length, bk, num_of_threads);
    }
    assert(bootsSymDecrypt(result, key) == 0);  // Should be false since a != b

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(1, result);
    delete_gate_bootstrapping_ciphertext_array(length, a);
    delete_gate_bootstrapping_ciphertext_array(length, b);

    std::cout << (use_gpu ? "HomEquiGPU" : "HomEquiOPT") << " passed all tests." << std::endl;
}

int main() {
    // Initialize parameters and keys
    auto params = initializeParams(128);
    auto key = generateKeySet(params);
    const TFheGateBootstrappingCloudKeySet* bk = &key->cloud;

    int num_of_threads = 32;  // Set the number of threads for testing, adjust as necessary

    // Run tests for the optimized CPU implementations
    test_HomCompLe(bk, key, num_of_threads, false);
    test_HomCompL(bk, key, num_of_threads, false);
    test_HomEqui(bk, key, num_of_threads, false);

    // Run tests for the GPU implementations
    test_HomCompLe(bk, key, num_of_threads, true);
    test_HomCompL(bk, key, num_of_threads, true);
    test_HomEqui(bk, key, num_of_threads, true);

    // Clean up keys
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    std::cout << "All unit tests passed." << std::endl;
    return 0;
}


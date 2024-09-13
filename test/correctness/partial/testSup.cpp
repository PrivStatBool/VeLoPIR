#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <cassert>
#include <vector>
#include "native/HomSup.h"
#include "utils.h"

void test_HomBitwiseAND(const int length, const TFheGateBootstrappingCloudKeySet* bk, const TFheGateBootstrappingSecretKeySet* key) {
    // Test 1: v = 1 (encrypted) should return the original ct
    double plaintext = 1.25;  // Example small number within the range
    LweSample* v = encryptBoolean(1, 1, bk->params, key);  // Encrypt 1
    LweSample* ct = encryptBoolean(encodeDouble(length, plaintext), length, bk->params, key);  // Encrypt plaintext

    LweSample* result = HomBitwiseAND(v, ct, length, bk);

    std::vector<int> decryptedResultVec = decryptToBinaryVector(result, length, key);
    double decryptedResult = decodeDouble(decryptedResultVec);
    assert(decryptedResult == plaintext);  // Should match the original plaintext

    // Test 2: v = 0 (encrypted) should return all zeros
    v = encryptBoolean(0, 1, bk->params, key);  // Encrypt 0
    ct = encryptBoolean(encodeDouble(length, plaintext), length, bk->params, key);  // Encrypt plaintext

    result = HomBitwiseAND(v, ct, length, bk);

    decryptedResultVec = decryptToBinaryVector(result, length, key);
    decryptedResult = decodeDouble(decryptedResultVec);
    assert(decryptedResult == 0.0);  // Should be all zeros

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(length, ct);
    delete_gate_bootstrapping_ciphertext_array(length, result);
    delete_gate_bootstrapping_ciphertext(v);

    std::cout << "HomBitwiseAND passed all tests." << std::endl;
}

void test_HomSum(const int lengthService, const TFheGateBootstrappingCloudKeySet* bk, const TFheGateBootstrappingSecretKeySet* key) {
    const int num_elements = 10;   // Number of elements in the array

    // Create an array of encrypted zeros with one non-zero element
    std::vector<LweSample*> ct_array;
    for (int i = 0; i < num_elements; i++) {
        if (i == 3) {  // Only the 4th element is non-zero
            ct_array.push_back(encryptBoolean(encodeDouble(lengthService, 1.25), lengthService, bk->params, key));
        } else {
            ct_array.push_back(encryptBoolean(encodeDouble(lengthService, 0.0), lengthService, bk->params, key));
        }
    }

    // Sum up the array using HomSum
    LweSample* result = HomSum(ct_array, num_elements, lengthService, bk);

    // Decrypt the result and check if it matches the non-zero element
    std::vector<int> decryptedResultVec = decryptToBinaryVector(result, lengthService, key);
    double decryptedResult = decodeDouble(decryptedResultVec);
    assert(decryptedResult == 1.25);  // Should match the non-zero element

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(lengthService, result);
    for (int i = 0; i < num_elements; i++) {
        delete_gate_bootstrapping_ciphertext_array(lengthService, ct_array[i]);
    }

    std::cout << "HomSum passed all tests." << std::endl;
}

int main() {
    // Initialize parameters and keys
    auto params = initializeParams(128);
    auto key = generateKeySet(params);
    const TFheGateBootstrappingCloudKeySet* bk = &key->cloud;

    int length = 16;  // Length of the number (in bits)

    // Run tests
    test_HomBitwiseAND(length, bk, key);
    test_HomSum(length, bk, key);

    // Clean up keys
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    std::cout << "All supplementary function tests passed." << std::endl;
    return 0;
}


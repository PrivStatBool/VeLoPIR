#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <cassert>
#include "native/HomBB.h"
#include "utils.h"

void test_BB3(const int length, const TFheGateBootstrappingCloudKeySet* bk, const TFheGateBootstrappingSecretKeySet* key) {
    // Encrypt two identifiers using binary encryption
    int id_value = 3;  // Binary: 00011
    int targetId_value = 3; // Same identifier, should match

    LweSample* id = encryptBoolean(id_value, length, bk->params, key);
    LweSample* targetId = encryptBoolean(targetId_value, length, bk->params, key);

    // Allocate space for the result
    LweSample* res = new_gate_bootstrapping_ciphertext_array(1, bk->params);

    // Test 1: Matching identifiers
    BB3(res, id, targetId, length, bk);
    assert(bootsSymDecrypt(res, key) == 1);  // Should be 1
    std::cout << "Test 1 (Matching Identifiers) passed." << std::endl;

    // Test 2: Non-matching identifiers
    int targetId_value_2 = 2; // Binary: 00010 (Different identifier)
    delete_gate_bootstrapping_ciphertext_array(length, targetId); // Clean up the previous targetId
    targetId = encryptBoolean(targetId_value_2, length, bk->params, key);
    BB3(res, id, targetId, length, bk);
    assert(bootsSymDecrypt(res, key) == 0);  // Should be 0
    std::cout << "Test 2 (Non-Matching Identifiers) passed." << std::endl;

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(1, res);
    delete_gate_bootstrapping_ciphertext_array(length, id);
    delete_gate_bootstrapping_ciphertext_array(length, targetId);

    std::cout << "BB3 function passed all tests." << std::endl;
}

int main() {
    // Initialize parameters and keys
    auto params = initializeParams(128);
    auto key = generateKeySet(params);
    const TFheGateBootstrappingCloudKeySet* bk = &key->cloud;

    int length = 5;  // Length of the binary identifier (in bits)

    // Run tests
    test_BB3(length, bk, key);

    // Clean up keys
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    std::cout << "All BB3 function tests passed." << std::endl;
    return 0;
}


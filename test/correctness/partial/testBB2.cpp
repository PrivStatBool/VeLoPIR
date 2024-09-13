#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <cassert>
#include <vector>
#include "native/HomBB.h"
#include "utils.h"

// Test the correctness of BB2 function
void test_BB2(const int length, const TFheGateBootstrappingCloudKeySet* bk, const TFheGateBootstrappingSecretKeySet* key) {
    // Test Case 1: Matching coordinates (x, y) == (loc[0], loc[1])
    int x_value = 5;  // Example coordinate value
    int y_value = 7;  // Example coordinate value
    int loc_x_value = 5;  // Matching target coordinate value for x
    int loc_y_value = 7;  // Matching target coordinate value for y

    // Encrypt coordinates and target location coordinates
    LweSample* x = encryptBoolean(x_value, length, bk->params, key);
    LweSample* y = encryptBoolean(y_value, length, bk->params, key);
    
    std::vector<LweSample*> loc(2);
    loc[0] = encryptBoolean(loc_x_value, length, bk->params, key);  // loc[0] corresponds to loc_x
    loc[1] = encryptBoolean(loc_y_value, length, bk->params, key);  // loc[1] corresponds to loc_y

    // Allocate space for the result
    LweSample* res = new_gate_bootstrapping_ciphertext_array(1, bk->params);

    // Test 1: Matching coordinates
    BB2(res, x, y, loc, length, bk);
    assert(bootsSymDecrypt(res, key) == 1);  // Should be 1 (true)
    std::cout << "Test 1 (Matching Coordinates) passed." << std::endl;

    // Test Case 2: Non-matching coordinates (x, y) != (loc[0], loc[1])
    int loc_x_value_2 = 8;  // Non-matching target coordinate value for x
    int loc_y_value_2 = 7;  // Partially matching target coordinate value for y

    // Re-encrypt target location coordinates
    delete_gate_bootstrapping_ciphertext_array(length, loc[0]);
    delete_gate_bootstrapping_ciphertext_array(length, loc[1]);
    loc[0] = encryptBoolean(loc_x_value_2, length, bk->params, key);  // New loc[0]
    loc[1] = encryptBoolean(loc_y_value_2, length, bk->params, key);  // New loc[1]

    BB2(res, x, y, loc, length, bk);
    assert(bootsSymDecrypt(res, key) == 0);  // Should be 0 (false)
    std::cout << "Test 2 (Non-Matching Coordinates) passed." << std::endl;

    // Test Case 3: Non-matching y-coordinate only
    int loc_x_value_3 = 5;  // Matching loc_x
    int loc_y_value_3 = 9;  // Non-matching loc_y

    // Re-encrypt target location coordinates
    delete_gate_bootstrapping_ciphertext_array(length, loc[0]);
    delete_gate_bootstrapping_ciphertext_array(length, loc[1]);
    loc[0] = encryptBoolean(loc_x_value_3, length, bk->params, key);  // New loc[0]
    loc[1] = encryptBoolean(loc_y_value_3, length, bk->params, key);  // New loc[1]

    BB2(res, x, y, loc, length, bk);
    assert(bootsSymDecrypt(res, key) == 0);  // Should be 0 (false)
    std::cout << "Test 3 (Non-Matching Y-Coordinate) passed." << std::endl;

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(1, res);
    delete_gate_bootstrapping_ciphertext_array(length, x);
    delete_gate_bootstrapping_ciphertext_array(length, y);
    delete_gate_bootstrapping_ciphertext_array(length, loc[0]);
    delete_gate_bootstrapping_ciphertext_array(length, loc[1]);

    std::cout << "BB2 function passed all tests." << std::endl;
}

int main() {
    // Initialize parameters and keys
    auto params = initializeParams(128);
    auto key = generateKeySet(params);
    const TFheGateBootstrappingCloudKeySet* bk = &key->cloud;

    int length = 8;  // Length of the binary coordinates (in bits)

    // Run tests
    test_BB2(length, bk, key);

    // Clean up keys
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    std::cout << "All BB2 function tests passed." << std::endl;
    return 0;
}


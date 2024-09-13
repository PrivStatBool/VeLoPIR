#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <cassert>
#include <vector>
#include "native/HomComp.h"
#include "utils.h"
#include "native/HomBB.h"

// Helper function to check if the decrypted result is 1
bool isDecryptedResultOne(LweSample* res, const TFheGateBootstrappingSecretKeySet* key) {
    return bootsSymDecrypt(res, key) == 1;
}

void test_BB1(const int length, const TFheGateBootstrappingCloudKeySet* bk, const TFheGateBootstrappingSecretKeySet* key) {
    // Define the bounding box (x_left, x_right, y_left, y_right)
    double x_left = 1.0;
    double x_right = 3.0;
    double y_left = 2.0;
    double y_right = 4.0;

    // Encrypt the bounding box coordinates
    std::vector<LweSample*> loc(4);
    loc[0] = encryptBoolean(encodeDouble(length, x_left), length, bk->params, key);  // x_left
    loc[1] = encryptBoolean(encodeDouble(length, x_right), length, bk->params, key);  // x_right
    loc[2] = encryptBoolean(encodeDouble(length, y_left), length, bk->params, key);  // y_left
    loc[3] = encryptBoolean(encodeDouble(length, y_right), length, bk->params, key);  // y_right

    // Allocate space for the result
    LweSample* res = new_gate_bootstrapping_ciphertext_array(1, bk->params);

    // Test 1: (x, y) is out of bounding box
    LweSample* x1 = encryptBoolean(encodeDouble(length, 0.5), length, bk->params, key);
    LweSample* y1 = encryptBoolean(encodeDouble(length, 1.5), length, bk->params, key);
    BB1(res, x1, y1, loc, length, bk);
    assert(!isDecryptedResultOne(res, key));  // Should be 0
    std::cout << "Test 1 passed." << std::endl;

    // Test 2: x is out of bounding box while y is in
    LweSample* x2 = encryptBoolean(encodeDouble(length, 0.5), length, bk->params, key);
    LweSample* y2 = encryptBoolean(encodeDouble(length, 2.5), length, bk->params, key);
    BB1(res, x2, y2, loc, length, bk);
    assert(!isDecryptedResultOne(res, key));  // Should be 0
    std::cout << "Test 2 passed." << std::endl;

    // Test 3: y is out of bounding box while x is in
    LweSample* x3 = encryptBoolean(encodeDouble(length, 2.5), length, bk->params, key);
    LweSample* y3 = encryptBoolean(encodeDouble(length, 1.5), length, bk->params, key);
    BB1(res, x3, y3, loc, length, bk);
    assert(!isDecryptedResultOne(res, key));  // Should be 0
    std::cout << "Test 3 passed." << std::endl;

    // Test 4: (x, y) is inside the bounding box
    LweSample* x4 = encryptBoolean(encodeDouble(length, 2.5), length, bk->params, key);
    LweSample* y4 = encryptBoolean(encodeDouble(length, 3.5), length, bk->params, key);
    BB1(res, x4, y4, loc, length, bk);
    assert(isDecryptedResultOne(res, key));  // Should be 1
    std::cout << "Test 4 passed." << std::endl;

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(1, res);
    delete_gate_bootstrapping_ciphertext_array(length, x1);
    delete_gate_bootstrapping_ciphertext_array(length, y1);
    delete_gate_bootstrapping_ciphertext_array(length, x2);
    delete_gate_bootstrapping_ciphertext_array(length, y2);
    delete_gate_bootstrapping_ciphertext_array(length, x3);
    delete_gate_bootstrapping_ciphertext_array(length, y3);
    delete_gate_bootstrapping_ciphertext_array(length, x4);
    delete_gate_bootstrapping_ciphertext_array(length, y4);
    for (int i = 0; i < 4; i++) {
        delete_gate_bootstrapping_ciphertext_array(length, loc[i]);
    }

    std::cout << "BB1 function passed all tests." << std::endl;
}

int main() {
    // Initialize parameters and keys
    auto params = initializeParams(128);
    auto key = generateKeySet(params);
    const TFheGateBootstrappingCloudKeySet* bk = &key->cloud;

    int length = 16;  // Length of the number (in bits)

    // Run tests
    test_BB1(length, bk, key);

    // Clean up keys
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    std::cout << "All BB1 function tests passed." << std::endl;
    return 0;
}


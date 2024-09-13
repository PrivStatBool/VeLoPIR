#include <iostream>
#include <vector>
#include "tfhe/tfhe.h"
#include "tfhe/tfhe_io.h"
#include "utils.h"

int main() {
    int security_param = 128;
    int lengthInterval = 16;  // Length for interval values

    // Initialize TFHE parameters and keys
    auto params = initializeParams(security_param);
    auto key = generateKeySet(params);
    const TFheGateBootstrappingCloudKeySet* bk = &key->cloud;

    // Original double values
    double queryX_value = 2.345;  // Set to a specific value
    double queryY_value = 3.890;  // Set to a specific value

    // Step 1: Encode the double values
    int32_t encodedQueryX = encodeDouble(lengthInterval, queryX_value);
    int32_t encodedQueryY = encodeDouble(lengthInterval, queryY_value);

    // Step 2: Encrypt the encoded values
    LweSample* enc_x = encryptBoolean(encodedQueryX, lengthInterval, params, key);
    LweSample* enc_y = encryptBoolean(encodedQueryY, lengthInterval, params, key);

    // Step 3: Decrypt the encrypted values back to binary vectors
    std::vector<int> decryptedX = decryptToBinaryVector(enc_x, lengthInterval, key);
    std::vector<int> decryptedY = decryptToBinaryVector(enc_y, lengthInterval, key);

    // Step 4: Decode the binary vectors back to double values
    double decodedX_value = decodeDouble(decryptedX);
    double decodedY_value = decodeDouble(decryptedY);

    // Output the results
    std::cout << "Original queryX_value: " << queryX_value << std::endl;
    std::cout << "Decoded queryX_value: " << decodedX_value << std::endl;

    std::cout << "Original queryY_value: " << queryY_value << std::endl;
    std::cout << "Decoded queryY_value: " << decodedY_value << std::endl;

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(lengthInterval, enc_x);
    delete_gate_bootstrapping_ciphertext_array(lengthInterval, enc_y);
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    return 0;
}


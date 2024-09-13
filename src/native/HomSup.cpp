#include "native/HomSup.h"
#include <iostream>

// Perform bitwise AND between a single-bit ciphertext `v` and each bit of a ciphertext array `ct`
LweSample* HomBitwiseAND(const LweSample* v, const LweSample* ct, const int length, const TFheGateBootstrappingCloudKeySet* bk) {
    // Allocate memory for the result array
    LweSample* result = new_gate_bootstrapping_ciphertext_array(length, bk->params);
    
    // Apply the AND operation between `v` and each bit of `ct`
    for (int i = 0; i < length; i++) {
        bootsAND(&result[i], v, &ct[i], bk);
    }
    
    return result;  
}


LweSample* HomSum(const std::vector<LweSample*>& ct_array, const int num_elements, const int lengthService, const TFheGateBootstrappingCloudKeySet* bk) {
    // Allocate memory for the result array
    LweSample* result = new_gate_bootstrapping_ciphertext_array(lengthService, bk->params);

    // Initialize the result array to encrypted zeros
    for (int j = 0; j < lengthService; j++) {
        bootsCONSTANT(&result[j], 0, bk);
    }

    // Iterate over each element in the array
    for (int i = 0; i < num_elements; i++) {
        if (ct_array[i] == nullptr) {
            std::cerr << "Null pointer detected in ct_array at index " << i << std::endl;
            return nullptr;
        }
        // Perform bitwise XOR to sum up the ciphertexts
        for (int j = 0; j < lengthService; j++) {
            bootsXOR(&result[j], &result[j], &ct_array[i][j], bk);
        }
    }

    return result; 
}


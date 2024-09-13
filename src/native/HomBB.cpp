#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <vector>
#include "native/HomComp.h"
 
// BB1: Validates if the encrypted coordinates (x, y) are within the encrypted location bounds
void BB1(LweSample* res, const LweSample* x, const LweSample* y, 
         const std::vector<LweSample*>& loc, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

    // Allocate space for the intermediate results (single-bit ciphertexts)
    LweSample* v_x_left = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* v_x_right = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* v_y_left = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* v_y_right = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* v_x = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* v_y = new_gate_bootstrapping_ciphertext_array(1, bk->params);

    // Perform homomorphic comparisons for latitude
    HomCompLE(v_x_left, loc[0], x, length, bk);  // loc[0] <= x
    HomCompL(v_x_right, x, loc[1], length, bk);  // x < loc[1]

    // Perform homomorphic comparisons for longitude
    HomCompLE(v_y_left, loc[2], y, length, bk);  // loc[2] <= y
    HomCompL(v_y_right, y, loc[3], length, bk);  // y < loc[3]

    // Combine latitude results
    bootsAND(v_x, v_x_left, v_x_right, bk);

    // Combine longitude results
    bootsAND(v_y, v_y_left, v_y_right, bk);

    // Final validation by combining both latitude and longitude results
    bootsAND(res, v_x, v_y, bk);

    // Clean up temporary variables
    delete_gate_bootstrapping_ciphertext_array(1, v_x_left);
    delete_gate_bootstrapping_ciphertext_array(1, v_x_right);
    delete_gate_bootstrapping_ciphertext_array(1, v_y_left);
    delete_gate_bootstrapping_ciphertext_array(1, v_y_right);
    delete_gate_bootstrapping_ciphertext_array(1, v_x);
    delete_gate_bootstrapping_ciphertext_array(1, v_y);
}

// BB2: Validates if the encrypted coordinates (x, y) match the encrypted location (loc_x, loc_y)
void BB2(LweSample* res, const LweSample* x, const LweSample* y, 
         const std::vector<LweSample*>& loc, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

    // Allocate space for the intermediate results (single-bit ciphertexts)
    LweSample* v_x = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* v_y = new_gate_bootstrapping_ciphertext_array(1, bk->params);

    // Perform homomorphic equality check for the x-coordinate
    HomEqui(v_x, x, loc[0], length, bk);  // Check if x == loc_x

    // Perform homomorphic equality check for the y-coordinate
    HomEqui(v_y, y, loc[1], length, bk);  // Check if y == loc_y

    // Final validation by combining both x and y results
    bootsAND(res, v_x, v_y, bk);

    // Clean up temporary variables
    delete_gate_bootstrapping_ciphertext_array(1, v_x);
    delete_gate_bootstrapping_ciphertext_array(1, v_y);
}

// BB3: Validates if the encrypted location identifier `id` matches the encrypted target identifier `targetId`
void BB3(LweSample* res, const LweSample* id, const LweSample* targetId, const int length, const TFheGateBootstrappingCloudKeySet* bk) {
    // Perform homomorphic equality check
    HomEqui(res, id, targetId, length, bk);  // Check if id == targetId

}


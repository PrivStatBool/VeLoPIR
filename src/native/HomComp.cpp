#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>


// a <= b returns 1
void HomCompLE(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* temp = new_gate_bootstrapping_ciphertext_array(3, bk->params);

    // Compare sign bits to check if the signs are different
    bootsXOR(&temp[0], &a[length-1], &b[length-1], bk);  // temp[0] = 1 if signs differ

    // Initialize temp[2] for the case where signs are the same
    // Start with the assumption that a <= b, so set temp[2] to 1
    bootsCONSTANT(&temp[2], 1, bk);

    // Proceed with comparison logic if signs are the same
    for (int i = 0; i < length - 1; i++) {  // Skip the sign bit
        bootsXNOR(&temp[1], &a[i], &b[i], bk);  // temp[1] = 1 if bits are equal
        // If bits are not equal, determine if a is less than b based on the current bit
        // Since we are dealing with inverted logic for bits (0 is positive, 1 is negative), use b[i] to set temp[2]
        bootsMUX(&temp[2], &temp[1], &temp[2], &b[i], bk);
    }

    // If signs are different, determine the result based on the sign of 'a'
    // If 'a' is negative and 'b' is positive, 'a' is definitely less, so result should be 1
    // If 'a' is positive and 'b' is negative, 'a' cannot be less, so result should be 0
    // Use the sign bit of 'a' (a[length-1]) to set the result if signs differ
    bootsMUX(res, &temp[0], &a[length-1], &temp[2], bk);

    delete_gate_bootstrapping_ciphertext_array(3, temp);
}

// a < b returns 1
void HomCompL(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* temp = new_gate_bootstrapping_ciphertext_array(3, bk->params);

    // Compare sign bits to check if the signs are different
    bootsXOR(&temp[0], &a[length-1], &b[length-1], bk);  // temp[0] = 1 if signs differ

    // Initialize temp[2] for the case where signs are the same
    // Start with the assumption that a < b, so set temp[2] to 0
    bootsCONSTANT(&temp[2], 0, bk);

    // Proceed with comparison logic if signs are the same
    for (int i = 0; i < length - 1; i++) {  // Skip the sign bit
        bootsXNOR(&temp[1], &a[i], &b[i], bk);  // temp[1] = 1 if bits are equal
        // If bits are not equal, determine if a is less than b based on the current bit
        bootsMUX(&temp[2], &temp[1], &temp[2], &b[i], bk);
    }

    // If signs are different, determine the result based on the sign of 'a'
    bootsMUX(res, &temp[0], &a[length-1], &temp[2], bk);

    delete_gate_bootstrapping_ciphertext_array(3, temp);
}

// a == b returns 1
void HomEqui(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

    LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);       

    bootsCONSTANT(&temp[0], 1, bk);
    for(int i = 0; i < length; i++){        
        bootsXNOR(&temp[1], &a[i], &b[i], bk);
        bootsAND(&temp[0], &temp[0], &temp[1], bk);
        
    }
    bootsCOPY(&res[0], &temp[0], bk);

    delete_gate_bootstrapping_ciphertext_array(2, temp);
}



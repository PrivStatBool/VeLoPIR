#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <omp.h>
#include <iostream>

// less than or equal to
void HomCompLeOPT(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads) {
    // Allocate temporary array for XNOR results, excluding the sign bit
    LweSample* tempXNOR = new_gate_bootstrapping_ciphertext_array(length - 1, bk->params);
    // Temporary variables for intermediate results
    LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);

    // Set the number of threads for OpenMP
    omp_set_num_threads(num_of_threads);

    // Compare sign bits to check if the signs are different
    bootsXOR(&temp[0], &a[length - 1], &b[length - 1], bk);  // temp[0] = 1 if signs differ

    // Assume a <= b initially (temp[1] set to 1)
    bootsCONSTANT(&temp[1], 1, bk);

    // Parallel XNOR operation for all bits except the sign bit
    #pragma omp parallel for
    for (int i = 0; i < length - 1; i++) {
        bootsXNOR(&tempXNOR[i], &a[i], &b[i], bk);
    }

    // Sequentially determine the final comparison result using MUX operations
    for (int i = 0; i < length - 1; i++) {
        bootsMUX(&temp[1], &tempXNOR[i], &temp[1], &b[i], bk);
    }

    // Determine the final result based on the sign bits if they differ, or the comparison result if they don't
    bootsMUX(res, &temp[0], &a[length - 1], &temp[1], bk);

    // Cleanup: Free the allocated temporary arrays
    delete_gate_bootstrapping_ciphertext_array(length - 1, tempXNOR);
    delete_gate_bootstrapping_ciphertext_array(2, temp);
}

// a < b returns 1
void HomCompLOPT(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads) {
    // Allocate temporary array for XNOR results, excluding the sign bit
    LweSample* tempXNOR = new_gate_bootstrapping_ciphertext_array(length - 1, bk->params);
    // Temporary variables for intermediate results
    LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);

    // Set the number of threads for OpenMP
    omp_set_num_threads(num_of_threads);

    // Compare sign bits to check if the signs are different
    bootsXOR(&temp[0], &a[length - 1], &b[length - 1], bk);  // temp[0] = 1 if signs differ

    // Assume a < b initially (temp[1] set to 0)
    bootsCONSTANT(&temp[1], 0, bk);

    // Parallel XNOR operation for all bits except the sign bit
    #pragma omp parallel for
    for (int i = 0; i < length - 1; i++) {
        bootsXNOR(&tempXNOR[i], &a[i], &b[i], bk);
    }

    // Sequentially determine the final comparison result using MUX operations
    for (int i = 0; i < length - 1; i++) {
        bootsMUX(&temp[1], &tempXNOR[i], &temp[1], &b[i], bk);
    }

    // Determine the final result based on the sign bits if they differ, or the comparison result if they don't
    bootsMUX(res, &temp[0], &a[length - 1], &temp[1], bk);

    // Cleanup: Free the allocated temporary arrays
    delete_gate_bootstrapping_ciphertext_array(length - 1, tempXNOR);
    delete_gate_bootstrapping_ciphertext_array(2, temp);
}

// equal to
void HomEquiOPT(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads) {
    // Allocate temporary array to store intermediate results
    LweSample* temp = new_gate_bootstrapping_ciphertext_array(length, bk->params);

    // Set the number of threads for OpenMP
    omp_set_num_threads(num_of_threads);

    // Parallel XNOR operation: Compute XNOR for each bit and store in temp
    #pragma omp parallel for
    for(int i = 0; i < length; i++) {
        bootsXNOR(&temp[i], &a[i], &b[i], bk);
    }

    // Parallel reduction with AND operation
    for (int stride = 1; stride < length; stride *= 2) {
        #pragma omp parallel for
        for (int i = 0; i < length; i += 2 * stride) { 
            if (i + stride < length) {
            bootsAND(&temp[i], &temp[i], &temp[i + stride], bk);
            }
        }
    }

    for(int i = 1; i < length; i++) {
	bootsAND(&temp[0], &temp[0], &temp[i], bk);
    }

    // Copy the final result to the output
    bootsCOPY(&res[0], &temp[0], bk);

    // Cleanup: Free the allocated temporary array
    delete_gate_bootstrapping_ciphertext_array(length, temp);
}

// less than or equal to using GPU offloading
void HomCompLeGPU(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk, int num_of_cores) {
    // Allocate temporary array for XNOR results, excluding the sign bit
    LweSample* tempXNOR = new_gate_bootstrapping_ciphertext_array(length - 1, bk->params);
    // Temporary variables for intermediate results
    LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);

    // Compare sign bits to check if the signs are different
    bootsXOR(&temp[0], &a[length - 1], &b[length - 1], bk);  // temp[0] = 1 if signs differ

    // Assume a <= b initially (temp[1] set to 1)
    bootsCONSTANT(&temp[1], 1, bk);

    // Parallel XNOR operation for all bits except the sign bit using GPU
    #pragma omp target teams distribute parallel for num_threads(num_of_cores) map(to: a[0:length-1], b[0:length-1], bk[0:1]) map(from: tempXNOR[0:length-1])
    for (int i = 0; i < length - 1; i++) {
        bootsXNOR(&tempXNOR[i], &a[i], &b[i], bk);
    }

    // Sequentially determine the final comparison result using MUX operations
    for (int i = 0; i < length - 1; i++) {
        bootsMUX(&temp[1], &tempXNOR[i], &temp[1], &b[i], bk);
    }

    // Determine the final result based on the sign bits if they differ, or the comparison result if they don't
    bootsMUX(res, &temp[0], &a[length - 1], &temp[1], bk);

    // Cleanup: Free the allocated temporary arrays
    delete_gate_bootstrapping_ciphertext_array(length - 1, tempXNOR);
    delete_gate_bootstrapping_ciphertext_array(2, temp);
}

// a < b returns 1 using GPU offloading
void HomCompLGPU(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk, int num_of_cores) {
    // Allocate temporary array for XNOR results, excluding the sign bit
    LweSample* tempXNOR = new_gate_bootstrapping_ciphertext_array(length - 1, bk->params);
    // Temporary variables for intermediate results
    LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);

    // Compare sign bits to check if the signs are different
    bootsXOR(&temp[0], &a[length - 1], &b[length - 1], bk);  // temp[0] = 1 if signs differ

    // Assume a < b initially (temp[1] set to 0)
    bootsCONSTANT(&temp[1], 0, bk);

    // Parallel XNOR operation for all bits except the sign bit using GPU
    #pragma omp target teams distribute parallel for num_threads(num_of_cores) map(to:a[0:length-1], b[0:length-1], bk[0:1]) map(from:tempXNOR[0:length-1])
    for (int i = 0; i < length - 1; i++) {
        bootsXNOR(&tempXNOR[i], &a[i], &b[i], bk);
    }

    // Sequentially determine the final comparison result using MUX operations
    for (int i = 0; i < length - 1; i++) {
        bootsMUX(&temp[1], &tempXNOR[i], &temp[1], &b[i], bk);
    }

    // Determine the final result based on the sign bits if they differ, or the comparison result if they don't
    bootsMUX(res, &temp[0], &a[length - 1], &temp[1], bk);

    // Cleanup: Free the allocated temporary arrays
    delete_gate_bootstrapping_ciphertext_array(length - 1, tempXNOR);
    delete_gate_bootstrapping_ciphertext_array(2, temp);
}

// Equality check using GPU offloading
void HomEquiGPU(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk, int num_of_cores) {
    // Allocate temporary array to store intermediate results
    LweSample* temp = new_gate_bootstrapping_ciphertext_array(length, bk->params);

    // Parallel XNOR operation: Compute XNOR for each bit and store in temp using GPU
    #pragma omp target teams distribute parallel for num_threads(num_of_cores) map(to:a[0:length], b[0:length], bk[0:1]) map(from:temp[0:length])
    for(int i = 0; i < length; i++) {
        bootsXNOR(&temp[i], &a[i], &b[i], bk);
    }

    // Parallel reduction with AND operation using GPU
    for (int stride = 1; stride < length; stride *= 2) {
        #pragma omp target teams distribute parallel for num_threads(num_of_cores) map(tofrom:temp[0:length])
        for (int i = 0; i < length; i += 2 * stride) { 
            if (i + stride < length) {
                bootsAND(&temp[i], &temp[i], &temp[i + stride], bk);
            }
        }
    }

    // Copy the final result to the output
    bootsCOPY(&res[0], &temp[0], bk);

    // Cleanup: Free the allocated temporary array
    delete_gate_bootstrapping_ciphertext_array(length, temp);
}


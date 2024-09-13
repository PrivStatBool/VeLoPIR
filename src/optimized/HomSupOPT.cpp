#include <omp.h>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <vector>
#include "optimized/HomSupOPT.h"

// Perform bitwise AND between a single-bit ciphertext `v` and each bit of a ciphertext array `ct` using parallelization
LweSample* HomBitwiseANDOPT(LweSample* v, LweSample* ct, const int lengthService, const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads) {

    LweSample* result = new_gate_bootstrapping_ciphertext_array(lengthService, bk->params);

    // Set the number of threads for OpenMP
    omp_set_num_threads(num_of_threads);

    #pragma omp parallel for
    for (int i = 0; i < lengthService; i++) {
        // Apply AND operation on each bit of `ct` with `v`
        bootsAND(&result[i], v, &ct[i], bk);
    }

    return result;  
}

// Perform bitwise AND between a single-bit ciphertext `v` and each bit of a ciphertext array `ct` using GPU offloading with OpenMP
LweSample* HomBitwiseANDGPU(LweSample* v, LweSample* ct, const int lengthService, const TFheGateBootstrappingCloudKeySet* bk, int num_of_cores) {
    
    LweSample* result = new_gate_bootstrapping_ciphertext_array(lengthService, bk->params);

    // Offload computation to the GPU
    #pragma omp target teams distribute parallel for num_threads(num_of_cores) map(to:v[0:1], bk[0:1]) map(tofrom:ct[0:lengthService])
    for (int i = 0; i < lengthService; i++) {
        // Apply AND operation on each bit of `ct` with `v`
        bootsAND(&result[i], v, &ct[i], bk);
    }

    return result;  // Return the modified ciphertext array
}

// Optimized version of HomSum using OpenMP for parallel reduction
LweSample* HomSumOPT(std::vector<LweSample*>& ct_array, const int num_elements, const int lengthService, const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads) {

    // Allocate memory for the result array
    LweSample* result = new_gate_bootstrapping_ciphertext_array(lengthService, bk->params);

    // Perform parallel reduction using XOR
    for (int k = 1; k < num_elements; k *= 2) {
        #pragma omp parallel for num_threads(num_of_threads)
        for (int i = 0; i < num_elements; i += 2 * k) {
            if (i + k < num_elements) {
                for (int j = 0; j < lengthService; j++) {
                    bootsXOR(&ct_array[i][j], &ct_array[i][j], &ct_array[i + k][j], bk);
                }
            }
        }
    }

    // Copy the first element (now containing the result) to the result array
    for (int i = 0; i < lengthService; i++) {
        bootsCOPY(&result[i], &ct_array[0][i], bk);
    }

    // Return the result array
    return result;
}

LweSample* HomSumGPU(std::vector<LweSample*>& ct_array, const int num_elements, const int lengthService, const TFheGateBootstrappingCloudKeySet* bk, int num_of_cores) {

    // Convert std::vector<LweSample*> to raw array for GPU processing
    LweSample** ct_array_raw = new LweSample*[num_elements];
    for (int i = 0; i < num_elements; ++i) {
        ct_array_raw[i] = new_gate_bootstrapping_ciphertext_array(lengthService, bk->params);
    }

    // Copy data from the vector to the raw array
    for (int i = 0; i < num_elements; i++) {
        for (int j = 0; j < lengthService; j++) {
            bootsCOPY(&ct_array_raw[i][j], &ct_array[i][j], bk);
        }
    }

    // Allocate memory for the result array
    LweSample* result = new_gate_bootstrapping_ciphertext_array(lengthService, bk->params);

    // Offload the entire reduction process to the GPU
    for (int k = 1; k < num_elements; k *= 2) {
        #pragma omp target teams distribute parallel for num_threads(num_of_cores) map(tofrom: ct_array_raw[0:num_elements]) map(to: bk[0:1])
        for (int i = 0; i < num_elements; i += 2 * k) {
            if (i + k < num_elements) {
                for (int j = 0; j < lengthService; j++) {
                    bootsXOR(&ct_array_raw[i][j], &ct_array_raw[i][j], &ct_array_raw[i + k][j], bk);
                }
            }
        }
    }

    // Copy the first element (now containing the result) to the result array
    #pragma omp target teams distribute parallel for num_threads(num_of_cores) map(to: bk[0:1]) map(from: result[0:lengthService])
    for (int i = 0; i < lengthService; i++) {
        bootsCOPY(&result[i], &ct_array_raw[0][i], bk);
    }

    // Cleanup the raw array (but not the data it points to)
    for (int i = 0; i < num_elements; ++i) {
        delete_gate_bootstrapping_ciphertext_array(lengthService, ct_array_raw[i]);
    }

    // Return the result array
    return result;
}

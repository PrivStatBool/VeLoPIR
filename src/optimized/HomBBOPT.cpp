#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <vector>
#include <omp.h>
#include "native/HomComp.h"
#include "optimized/HomBBOPT.h"
#include "optimized/HomCompOPT.h"
#include <iostream>

// BB1OPT: Optimized version of BB1 using parallel processing with non-optimized homomorphic functions
void BB1OPT(LweSample* res, const LweSample* x, const LweSample* y, 
            const std::vector<LweSample*>& loc, const int length, 
            const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads) {

    // Allocate space for the intermediate results (single-bit ciphertexts)
    LweSample* v_x_left = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* v_x_right = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* v_y_left = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* v_y_right = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* v_x = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* v_y = new_gate_bootstrapping_ciphertext_array(1, bk->params);

    // First parallel section with 4 threads
    #pragma omp parallel sections num_threads(num_of_threads)
    {
        #pragma omp section
        {
            HomCompLE(v_x_left, loc[0], x, length, bk);  // loc[0] <= x
        }
        #pragma omp section
        {
            HomCompL(v_x_right, x, loc[1], length, bk);  // x < loc[1]
        }
        #pragma omp section
        {
            HomCompLE(v_y_left, loc[2], y, length, bk);  // loc[2] <= y
        }
        #pragma omp section
        {
            HomCompL(v_y_right, y, loc[3], length, bk);  // y < loc[3]
        }
    }

    // Second parallel section with 2 threads for combining results
    #pragma omp parallel sections num_threads(num_of_threads)
    {
        #pragma omp section
        {
            bootsAND(v_x, v_x_left, v_x_right, bk);
        }
        #pragma omp section
        {
            bootsAND(v_y, v_y_left, v_y_right, bk);
        }
    }

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


void BB1OptGPU(LweSample* res, const LweSample* x, const LweSample* y, 
               const std::vector<LweSample*>& loc, const int length, 
               const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads) {

    // Allocate space for the intermediate results (single-bit ciphertexts)
    LweSample* v_x_left = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* v_x_right = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* v_y_left = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* v_y_right = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* v_x = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* v_y = new_gate_bootstrapping_ciphertext_array(1, bk->params);

    // First parallel section with 4 threads: using GPU for homomorphic comparisons
    #pragma omp parallel sections num_threads(num_of_threads)
    {
        #pragma omp section
        {
            // Use GPU-accelerated function for loc[0] <= x
            HomCompLeGPU(v_x_left, loc[0], x, length, bk, 32);
        }
        #pragma omp section
        {
            // Use GPU-accelerated function for x < loc[1]
            HomCompLGPU(v_x_right, x, loc[1], length, bk, 32);
        }
        #pragma omp section
        {
            // Use GPU-accelerated function for loc[2] <= y
            HomCompLeGPU(v_y_left, loc[2], y, length, bk, 32);
        }
        #pragma omp section
        {
            // Use GPU-accelerated function for y < loc[3]
            HomCompLGPU(v_y_right, y, loc[3], length, bk, 32);
        }
    }

    // Second parallel section with 2 threads for combining results
    #pragma omp parallel sections num_threads(num_of_threads)
    {
        #pragma omp section
        {
            // AND operation for x conditions
            bootsAND(v_x, v_x_left, v_x_right, bk);
        }
        #pragma omp section
        {
            // AND operation for y conditions
            bootsAND(v_y, v_y_left, v_y_right, bk);
        }
    }

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

// BB2OPT: Optimized version of BB2 using parallel processing with non-optimized homomorphic functions
void BB2OPT(LweSample* res, const LweSample* x, const LweSample* y, 
            const std::vector<LweSample*>& loc, const int length, 
            const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads) {

    // Allocate space for the intermediate results (single-bit ciphertexts)
    LweSample* v_x = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* v_y = new_gate_bootstrapping_ciphertext_array(1, bk->params);

    // Perform homomorphic equality checks in parallel using non-optimized functions
    #pragma omp parallel sections num_threads(num_of_threads)
    {
        #pragma omp section
        {
            HomEqui(v_x, x, loc[0], length, bk);  // Check if x == loc_x
        }
        #pragma omp section
        {
            HomEqui(v_y, y, loc[1], length, bk);  // Check if y == loc_y
        }
    }

    // Final validation by combining both x and y results
    bootsAND(res, v_x, v_y, bk);

    // Clean up temporary variables
    delete_gate_bootstrapping_ciphertext_array(1, v_x);
    delete_gate_bootstrapping_ciphertext_array(1, v_y);
}

void BB2OptGPU(LweSample* res, const LweSample* x, const LweSample* y, 
               const std::vector<LweSample*>& loc, const int length, 
               const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads) {

    // Allocate space for the intermediate results (single-bit ciphertexts)
    LweSample* v_x = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* v_y = new_gate_bootstrapping_ciphertext_array(1, bk->params);

    // First parallel section with 2 threads: using GPU for homomorphic equality checks
    #pragma omp parallel sections num_threads(num_of_threads)
    {
        #pragma omp section
        {
            // Use GPU-accelerated function for x == loc[0]
            HomEquiGPU(v_x, x, loc[0], length, bk, 32);
        }
        #pragma omp section
        {
            // Use GPU-accelerated function for y == loc[1]
            HomEquiGPU(v_y, y, loc[1], length, bk, 32); 
        }
    }

    // Final validation by combining both x and y results
    bootsAND(res, v_x, v_y, bk);

    // Clean up temporary variables
    delete_gate_bootstrapping_ciphertext_array(1, v_x);
    delete_gate_bootstrapping_ciphertext_array(1, v_y);
}

void BB3OptGPU(LweSample* res, const LweSample* id, const LweSample* targetId, const int length, const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads) {
    // Use GPU-accelerated function for id == targetId
    HomEquiGPU(res, id, targetId, length, bk, 32);
}


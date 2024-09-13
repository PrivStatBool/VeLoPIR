#include <iostream>
#include <chrono>
#include <fstream>
#include <vector>
#include <filesystem>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include "utils.h"
#include "optimized/HomBBOPT.h"
#include "native/HomBB.h"

// Function to test BB2 with threading and GPU options
double testBB2(LweSample* x, LweSample* y, const std::vector<LweSample*>& loc, int length, 
               const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads, bool use_gpu = false) {
    LweSample* result = new_gate_bootstrapping_ciphertext_array(1, bk->params);

    // Start timer
    auto start = std::chrono::high_resolution_clock::now();

    if (use_gpu) {
        if (num_of_threads == 1) {
            BB2(result, x, y, loc, length, bk);  // Non-optimized version without threading
        } else {
            BB2OptGPU(result, x, y, loc, length, bk, num_of_threads);  // GPU-optimized version with multiple threads
        }
    } else {
        if (num_of_threads == 1) {
            BB2(result, x, y, loc, length, bk);  // Non-optimized version without threading
        } else {
            BB2OPT(result, x, y, loc, length, bk, num_of_threads);  // Optimized version with threading
        }
    }

    // Stop timer
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(1, result);

    return elapsed.count();
}


void runTestForBB2(std::vector<int>& thread_counts, std::vector<double>& times_bb2, std::vector<double>& times_bb2optgpu) {
    // Initialize parameters for 128-bit security
    auto params = initializeParams(128);
    auto key = generateKeySet(params);
    const TFheGateBootstrappingCloudKeySet* bk = &key->cloud;

    // Example locational data to be encoded and encrypted
    double x_data = 5.75;
    double y_data = 3.25;
    double loc_data[2] = {5.75, 3.25};  // loc = {loc_x, loc_y}

    // Encrypt the inputs
    int length = 16;  // Assuming a 16-bit encryption
    int32_t encoded_x = encodeDouble(length, x_data);
    int32_t encoded_y = encodeDouble(length, y_data);

    LweSample* x = encryptBoolean(encoded_x, length, params, key);
    LweSample* y = encryptBoolean(encoded_y, length, params, key);

    std::vector<LweSample*> loc(2);
    for (int i = 0; i < 2; i++) {
        int32_t encoded_loc = encodeDouble(length, loc_data[i]);
        loc[i] = encryptBoolean(encoded_loc, length, params, key);
    }

    for (int np : thread_counts) {
        if (np > 0) {
            double elapsed_opt = testBB2(x, y, loc, length, bk, np);
            times_bb2.push_back(elapsed_opt);
        }

        double elapsed_optgpu = testBB2(x, y, loc, length, bk, np, true);
        times_bb2optgpu.push_back(elapsed_optgpu);

        // Print progress
        std::cout << "Finished num_threads=" << np << std::endl;
    }

    // Clean up ciphertexts
    delete_gate_bootstrapping_ciphertext_array(length, x);
    delete_gate_bootstrapping_ciphertext_array(length, y);
    for (auto& l : loc) {
        delete_gate_bootstrapping_ciphertext_array(length, l);
    }

    // Clean up keys
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
}

int main() {
    // Create the result directory if it doesn't exist
    std::filesystem::create_directory("result");

    // Open CSV file to write results for BB2
    std::ofstream file_bb2("result/result_BB2_128.csv");
    file_bb2 << "num_threads,BB2OPT time (s),BB2OptGPU time (s)\n";

    std::vector<int> thread_counts = {1, 2, 3, 4, 5, 6, 7, 8};  // Define the number of threads
    std::vector<double> times_bb2;
    std::vector<double> times_bb2optgpu;

    // Run the test for BB2
    runTestForBB2(thread_counts, times_bb2, times_bb2optgpu);

    // Write the results to the CSV files
    for (size_t i = 0; i < thread_counts.size(); i++) {
        file_bb2 << thread_counts[i] << ",";
        if (i < times_bb2.size()) {
            file_bb2 << times_bb2[i] << ",";
        } else {
            file_bb2 << ",";
        }
        file_bb2 << times_bb2optgpu[i] << "\n";
    }

    file_bb2.close();

    std::cout << "Test completed and results saved to result/result_BB2_128.csv" << std::endl;
    return 0;
}


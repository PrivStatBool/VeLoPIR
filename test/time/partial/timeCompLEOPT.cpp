#include <iostream>
#include <chrono>
#include <fstream>
#include <vector>
#include <filesystem>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include "utils.h"
#include "optimized/HomCompOPT.h"
#include "native/HomComp.h"

// Function to perform the test and return the elapsed time
double testHomCompLE(LweSample* a, LweSample* b, int length, const TFheGateBootstrappingCloudKeySet* bk, int np) {
    LweSample* result = new_gate_bootstrapping_ciphertext_array(1, bk->params);

    // Start timer
    auto start = std::chrono::high_resolution_clock::now();

    if (np == 0) {
        HomCompLE(result, a, b, length, bk);  // Non-optimized version
    } else {
        HomCompLeOPT(result, a, b, length, bk, np);  // Optimized version with np threads
    }

    // Stop timer
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(1, result);

    return elapsed.count();
}

// Function to perform the test on GPU and return the elapsed time
double testHomCompLEGPU(LweSample* a, LweSample* b, int length, const TFheGateBootstrappingCloudKeySet* bk, int num_of_cores) {
    LweSample* result = new_gate_bootstrapping_ciphertext_array(1, bk->params);

    // Start timer
    auto start = std::chrono::high_resolution_clock::now();

    // Run the GPU version
    if (num_of_cores == 0) {
        HomCompLE(result, a, b, length, bk);  // Non-optimized version
    } else {
        HomCompLeGPU(result, a, b, length, bk, num_of_cores);  // Optimized version with np threads
    }

    // Stop timer
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(1, result);

    return elapsed.count();
}

int main() {
    // Initialize parameters for a security level of 128 bits
    auto params = initializeParams(128);
    auto key = generateKeySet(params);
    const TFheGateBootstrappingCloudKeySet* bk = &key->cloud;

    // Create the result directory if it doesn't exist
    std::filesystem::create_directory("result");

    // Open a CSV file to write results
    std::ofstream file("result/HomCompLE_128.csv");
    file << "num_threads,16-bit (s) - CPU,32-bit (s) - CPU,16-bit (s) - GPU,32-bit (s) - GPU\n";

    std::vector<int> lengths = {16, 32};
    std::vector<int> np_values = {0, 4, 8, 12, 16, 20, 24, 28, 32};

    // Example input values to be encoded and encrypted
    double data1 = 5.75;
    double data2 = 3.25;

    for (int np : np_values) {
        file << np;

        for (int length : lengths) {
            // Encode and encrypt the inputs
            int32_t encoded1 = encodeDouble(length, data1);
            int32_t encoded2 = encodeDouble(length, data2);
            LweSample* a = encryptBoolean(encoded1, length, params, key);
            LweSample* b = encryptBoolean(encoded2, length, params, key);

            // Run the comparison test on CPU
            double elapsed_cpu = testHomCompLE(a, b, length, bk, np);
            file << "," << elapsed_cpu;

            // Clean up ciphertexts
            delete_gate_bootstrapping_ciphertext_array(length, a);
            delete_gate_bootstrapping_ciphertext_array(length, b);

            std::cout << "Finished num_threads=" << np << " for " << length << "-bit on CPU" << std::endl;
        }

        // GPU version for both lengths
        for (int length : lengths) {
            // Encode and encrypt the inputs
            int32_t encoded1 = encodeDouble(length, data1);
            int32_t encoded2 = encodeDouble(length, data2);
            LweSample* a = encryptBoolean(encoded1, length, params, key);
            LweSample* b = encryptBoolean(encoded2, length, params, key);

            // Run the comparison test on GPU
            double elapsed_gpu = testHomCompLEGPU(a, b, length, bk, np);
            file << "," << elapsed_gpu;

            // Clean up ciphertexts
            delete_gate_bootstrapping_ciphertext_array(length, a);
            delete_gate_bootstrapping_ciphertext_array(length, b);

            std::cout << "Finished GPU version for " << length << "-bit" << std::endl;
        }

        file << "\n";
    }

    file.close();

    // Clean up keys
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    std::cout << "Test completed and results saved to result/HomCompLE_128.csv" << std::endl;
    return 0;
}


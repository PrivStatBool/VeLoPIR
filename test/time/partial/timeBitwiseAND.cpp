#include <iostream>
#include <chrono>
#include <fstream>
#include <vector>
#include <filesystem>  // For creating directories
#include "tfhe/tfhe.h"
#include "tfhe/tfhe_io.h"
#include "utils.h"
#include "optimized/HomSupOPT.h"
#include "native/HomSup.h"

double testHomBitwiseAND(int serviceLength, int np, const TFheGateBootstrappingSecretKeySet* key, const TFheGateBootstrappingCloudKeySet* bk, int version) {
    // Example text string as the service
    std::string serviceText = "this is some text";

    // Convert the text string to a binary string with the given serviceLength
    std::string binaryString = textToBinaryString(serviceText, serviceLength);

    // Encrypt the binary string
    LweSample* v = new_gate_bootstrapping_ciphertext_array(1, bk->params);
    LweSample* ct = encryptBinaryString(binaryString, key, bk);

    // Start timer
    auto start = std::chrono::high_resolution_clock::now();

    // Run the selected version
    if (version == 0) {
        HomBitwiseAND(v, ct, serviceLength, bk); // Vanilla version
    } else if (version == 1) {
        HomBitwiseANDOPT(v, ct, serviceLength, bk, np); // Optimized (threaded) version
    } else if (version == 2) {
        HomBitwiseANDGPU(v, ct, serviceLength, bk, np); // GPU version with np cores
    }

    // Stop timer
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(1, v);
    delete_gate_bootstrapping_ciphertext_array(serviceLength, ct);

    return elapsed.count();
}

int main() {
    auto params = initializeParams(128);
    auto key = generateKeySet(params);
    const TFheGateBootstrappingCloudKeySet* bk = &key->cloud;

    // Create the result directory if it doesn't exist
    std::filesystem::create_directory("result");

    // Open a CSV file to write results
    std::ofstream file("result/bitwiseGPUandResult.csv");
    file << "serviceLength,np=0 (vanilla),np=16 (thread),np=32 (thread),GPU=8, GPU=16,GPU=32,GPU=48\n";

    // Define service lengths and number of threads for CPU and GPU testing
    std::vector<int> serviceLengths = {16, 32, 48, 64};
    std::vector<int> np_values = {16, 32};  // CPU threads
    std::vector<int> np_cores = {8, 16, 32, 48};  // GPU cores

    for (int length : serviceLengths) {
        file << length;

        // Run the vanilla version (np = 0)
        double elapsed = testHomBitwiseAND(length, 0, key, bk, 0);
        file << "," << elapsed;

        // Run the optimized (threaded) versions with np=16 and np=32
        for (int np : np_values) {
            elapsed = testHomBitwiseAND(length, np, key, bk, 1);
            file << "," << elapsed;
        }

        // Run the GPU version for np=16, 32, 48
        for (int np : np_cores) {
            elapsed = testHomBitwiseAND(length, np, key, bk, 2);
            file << "," << elapsed;
        }

        file << "\n";

        // Print progress
        std::cout << "Finished serviceLength=" << length << std::endl;
    }

    file.close();

    // Clean up keys
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    std::cout << "Test completed and results saved to result/bitwiseGPUandResult.csv" << std::endl;
    return 0;
}


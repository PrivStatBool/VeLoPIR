#include <iostream>
#include <chrono>
#include <fstream>
#include <vector>
#include <filesystem>
#include <random>
#include "tfhe/tfhe.h"
#include "tfhe/tfhe_io.h"
#include "native/HomSup.h"
#include "optimized/HomSupOPT.h"
#include "utils.h"

// Function to generate a random binary string of a given length
std::string generateRandomBinaryString(int length) {
    std::string binaryString = "";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 1);

    for (int i = 0; i < length; i++) {
        binaryString += std::to_string(dis(gen));
    }

    return binaryString;
}

// Function to generate a random ciphertext array
std::vector<LweSample*> generateRandomCtArray(int num_elements, int lengthService, const TFheGateBootstrappingSecretKeySet* key, const TFheGateBootstrappingCloudKeySet* bk) {
    std::vector<LweSample*> ct_array(num_elements);

    for (int i = 0; i < num_elements; i++) {
        std::string binaryString = generateRandomBinaryString(lengthService);
        ct_array[i] = encryptBinaryString(binaryString, key, bk);
    }

    return ct_array;
}

// Function to measure the time for HomSum or HomSumOPT
double measureHomSumTime(std::vector<LweSample*>& ct_array, int num_elements, int lengthService, const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads) {
    auto start = std::chrono::high_resolution_clock::now();

    if (num_of_threads == 0) {
        HomSum(ct_array, num_elements, lengthService, bk);  // Non-optimized version without threading
    } else {
        HomSumOPT(ct_array, num_elements, lengthService, bk, num_of_threads);  // Optimized version with threading
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    return elapsed.count();
}

// Function to measure the time for HomSumGPU
double measureHomSumGPUTime(std::vector<LweSample*>& ct_array, int num_elements, int lengthService, const TFheGateBootstrappingCloudKeySet* bk, int num_of_cores) {
    auto start = std::chrono::high_resolution_clock::now();

    // Run the GPU version
    HomSumGPU(ct_array, num_elements, lengthService, bk, num_of_cores);

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    return elapsed.count();
}

int main() {
    // Security parameters
    int security_param = 128;
    int lengthService = 16;

    // Initialize TFHE parameters and keys
    auto params = initializeParams(security_param);
    auto key = generateKeySet(params);
    const TFheGateBootstrappingCloudKeySet* bk = &key->cloud;

    // Create the result directory if it doesn't exist
    std::filesystem::create_directory("result");

    // Open a CSV file to write results
    std::ofstream file("result/sum_128.csv");
    file << "num_elements,HomSum(s),np=16 (CPU),np=32 (CPU),GPU=16,GPU=32,GPU=48\n";

    // Set the number of elements (M values) and number of threads/cores for CPU and GPU testing
    std::vector<int> num_elements_list = {16, 32, 48, 64};  // M values
    std::vector<int> thread_counts = {16, 32};  // CPU cores
    std::vector<int> gpu_cores = {16, 32, 48};  // GPU cores

    for (int num_elements : num_elements_list) {
        file << num_elements;

        // Generate the random ciphertext array
        auto ct_array = generateRandomCtArray(num_elements, lengthService, key, bk);

        // Measure HomSum (no parallelism, baseline)
        double elapsed = measureHomSumTime(ct_array, num_elements, lengthService, bk, 0);
        file << "," << elapsed;
        std::cout << "Finished HomSum for num_elements=" << num_elements << ", time=" << elapsed << "s" << std::endl;

        // Measure HomSumOPT with different CPU core counts (n_p = 16, 32)
        for (int num_of_threads : thread_counts) {
            elapsed = measureHomSumTime(ct_array, num_elements, lengthService, bk, num_of_threads);
            file << "," << elapsed;
            std::cout << "Finished HomSumOPT with " << num_of_threads << " threads for num_elements=" << num_elements << ", time=" << elapsed << "s" << std::endl;
        }

        // Measure HomSumGPU with different GPU core counts (n_p = 16, 32, 48)
        for (int num_of_cores : gpu_cores) {
            elapsed = measureHomSumGPUTime(ct_array, num_elements, lengthService, bk, num_of_cores);
            file << "," << elapsed;
            std::cout << "Finished HomSumGPU with " << num_of_cores << " cores for num_elements=" << num_elements << ", time=" << elapsed << "s" << std::endl;
        }

        file << "\n";

        // Clean up the ciphertext array
        for (auto& ct : ct_array) {
            delete_gate_bootstrapping_ciphertext_array(lengthService, ct);
        }
    }

    file.close();

    // Clean up keys
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    std::cout << "Test completed and results saved to result/sum_128.csv" << std::endl;
    return 0;
}


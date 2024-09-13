#include <iostream>
#include <chrono>
#include <fstream>
#include <vector>
#include <filesystem>
#include <string>
#include <cstdlib>
#include "tfhe/tfhe.h"
#include "tfhe/tfhe_io.h"
#include "utils.h"
#include "optimized/HomLocOPT.h"

// Function to generate a random encrypted database
std::vector<std::vector<LweSample*>> generateRandEncDB(int M, int lengthInterval, int lengthService, const TFheGateBootstrappingSecretKeySet* key, const TFheGateBootstrappingCloudKeySet* bk) {
    std::vector<std::vector<LweSample*>> database(M, std::vector<LweSample*>(5));

    for (int i = 0; i < M; i++) {
        // Generate and encrypt random location coordinates
        for (int j = 0; j < 4; j++) {
            double randomValue = static_cast<double>(rand() % 1000) / 100.0;  // Random double value
            int32_t encodedValue = encodeDouble(lengthInterval, randomValue);
            database[i][j] = encryptBoolean(encodedValue, lengthInterval, bk->params, key);
        }

        // Encrypt a random service value (as a string)
        std::string serviceText = "service";  // Example text
        std::string binaryString = textToBinaryString(serviceText, lengthService);
        database[i][4] = encryptBinaryString(binaryString, key, bk);
    }

    return database;
}

int main() {
    // Parameters
    int security_param = 128;
    int lengthInterval = 16;  // Fixed length for interval values
    int M = 12;  // Fixed number of records
    int num_of_threads = 32;  // Full thread usage

    // Initialize TFHE parameters and keys
    auto params = initializeParams(security_param);
    auto key = generateKeySet(params);
    const TFheGateBootstrappingCloudKeySet* bk = &key->cloud;

    // Encrypted x and y coordinates for the query
    double queryX_value = 37.5;  // Example query value
    double queryY_value = 126.9; // Example query value
    int32_t queryX = encodeDouble(lengthInterval, queryX_value);
    int32_t queryY = encodeDouble(lengthInterval, queryY_value);
    LweSample* enc_x = encryptBoolean(queryX, lengthInterval, params, key);
    LweSample* enc_y = encryptBoolean(queryY, lengthInterval, params, key);

    // Create the result directory if it doesn't exist
    std::filesystem::create_directory("result");

    // Open a CSV file to write results
    std::ofstream file("result/generalTimeLocBB1_lengthService2.csv");
    file << "lengthService,NONE,PARALLEL_LOOP_HOMSUM,PARALLEL_LOOP_HOMSUM_BB1_BITWISE,ALL\n";

    // Varying lengthService values
//    std::vector<int> lengthService_values = {16, 32, 48, 64, 80, 96, 112};
    std::vector<int> lengthService_values = {112};

    // Measure time for each parallelization mode
    std::vector<ParallelizationMode> modes = {
        ParallelizationMode::NONE,
        ParallelizationMode::PARALLEL_LOOP_HOMSUM,
        ParallelizationMode::PARALLEL_LOOP_HOMSUM_BB1_BITWISE,
        ParallelizationMode::ALL
    };

    for (int lengthService : lengthService_values) {
        // Generate the encrypted database
        auto enc_database = generateRandEncDB(M, lengthInterval, lengthService, key, bk);

        file << lengthService;

        for (auto mode : modes) {
            // Start timing
            auto start = std::chrono::high_resolution_clock::now();

            // Perform the HomLocPIRbb1OPT function
            LweSample* result = HomLocPIRbb1OPT(enc_x, enc_y, enc_database, lengthInterval, lengthService, bk, mode, num_of_threads);

            // Stop timing
            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> elapsed = end - start;

            file << "," << elapsed.count();

            // Clean up the result
            delete_gate_bootstrapping_ciphertext_array(lengthService, result);
            std::cout << "Finished lengthService=" << lengthService << ", mode=" << static_cast<int>(mode) << ", time=" << elapsed.count() << "s" << std::endl;
        }

        file << "\n";

        // Clean up the encrypted database
        for (auto& vec : enc_database) {
            for (auto& ct : vec) {
                delete_gate_bootstrapping_ciphertext_array(lengthInterval, ct);
            }
        }
    }

    file.close();

    // Clean up the encrypted x and y coordinates
    delete_gate_bootstrapping_ciphertext_array(lengthInterval, enc_x);
    delete_gate_bootstrapping_ciphertext_array(lengthInterval, enc_y);

    // Clean up keys
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    std::cout << "Test completed and results saved to result/generalTimeLocBB1_Service.csv" << std::endl;

    return 0;
}


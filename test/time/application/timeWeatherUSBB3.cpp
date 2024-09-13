#include <iostream>
#include <chrono>
#include <fstream>
#include <vector>
#include <filesystem>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include "utils.h"
#include "optimized/HomLocOPT.h"
#include "optimized/HomBBOPT.h"

// Function to test and time HomLocPIRbb3OPT
double test_HomLocPIRbb3OPT(ParallelizationMode mode, const std::string& mode_name,
                            const LweSample* enc_id,
                            const std::vector<std::vector<LweSample*>>& encryptedDB,
                            int inputLength, int serviceLength, 
                            const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads) {
    std::cout << "Testing mode: " << mode_name << std::endl;

    // Start timing
    auto start = std::chrono::high_resolution_clock::now();

    // Perform HomLocPIRbb3OPT
    LweSample* result = HomLocPIRbb3OPT(enc_id, encryptedDB, inputLength, serviceLength, bk, mode, num_of_threads);

    // Stop timing
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(serviceLength, result);

    return elapsed.count();  // Return elapsed time in seconds
}

int main() {
    // Security parameters
    int security_param = 128;
    int inputLength = 9;  // Length for identifier values
    int serviceLength = 128;   // Length for service values (adjust based on your data)

    // Initialize TFHE parameters and keys
    auto params = initializeParams(security_param);
    auto key = generateKeySet(params);
    const TFheGateBootstrappingCloudKeySet* bk = &key->cloud;

    // Create the result directory if it doesn't exist
    std::filesystem::create_directory("result");

    // Open a CSV file to write results
    std::ofstream file("result/LocPIRbb3_timing_weather_US.csv");
    file << "Mode,Time(s)\n";  // CSV header

    // Provide the path to the CSV file
    std::string filename = std::string(DATA_DIR) + "/pir_weather_data_unique.csv";

    // Load the data from the CSV file
    std::vector<std::vector<std::string>> data = loadDataFromCSVbb3(filename);
    printLoadedData(data);

    // Encrypt the database
    std::vector<std::vector<LweSample*>> encryptedDB = encryptDBbb3(data, inputLength, serviceLength, params, key, bk);

    std::cout << "Size of data: " << data.size() << std::endl;

    // Encrypted identifier for the query
    int query_id = 1;  // Example query identifier
    LweSample* enc_id = encryptBoolean(query_id, inputLength, params, key);

    // Test all parallelization modes and record timings
    double time_NONE = test_HomLocPIRbb3OPT(ParallelizationMode::NONE, "NONE", enc_id, encryptedDB, inputLength, serviceLength, bk, 1);
    file << "NONE," << time_NONE << "\n";

    double time_PARALLEL_LOOP_HOMSUM = test_HomLocPIRbb3OPT(ParallelizationMode::PARALLEL_LOOP_HOMSUM, "PARALLEL_LOOP_HOMSUM", enc_id, encryptedDB, inputLength, serviceLength, bk, 4);
    file << "PARALLEL_LOOP_HOMSUM," << time_PARALLEL_LOOP_HOMSUM << "\n";

    double time_PARALLEL_LOOP_HOMSUM_BB1_BITWISE = test_HomLocPIRbb3OPT(ParallelizationMode::PARALLEL_LOOP_HOMSUM_BB1_BITWISE, "PARALLEL_LOOP_HOMSUM_BB1_BITWISE", enc_id, encryptedDB, inputLength, serviceLength, bk, 4);
    file << "PARALLEL_LOOP_HOMSUM_BB1_BITWISE," << time_PARALLEL_LOOP_HOMSUM_BB1_BITWISE << "\n";

    double time_ALL = test_HomLocPIRbb3OPT(ParallelizationMode::ALL, "ALL", enc_id, encryptedDB, inputLength, serviceLength, bk, 4);
    file << "ALL," << time_ALL << "\n";

    file.close();

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(inputLength, enc_id);
    cleanUpEncryptedDB(encryptedDB, inputLength, serviceLength);
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    std::cout << "Test completed and results saved to result/LocPIRbb3_timing_weather_US.csv" << std::endl;
    return 0;
}


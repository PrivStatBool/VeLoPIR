#include <iostream>
#include <chrono>
#include <fstream>
#include <vector>
#include <filesystem>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include "utils.h"
#include "native/HomComp.h"
#include "optimized/HomBBOPT.h"
#include "optimized/HomLocOPT.h" 

double test_HomLocPIRbb1OPT(ParallelizationMode mode, const std::string& mode_name,
                               const LweSample* enc_x, const LweSample* enc_y,
                               const std::vector<std::vector<LweSample*>>& encryptedDB,
                               int inputLength, int serviceLength, 
                               const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads) {
    std::cout << "Testing mode: " << mode_name << std::endl;

    // Start timing
    auto start = std::chrono::high_resolution_clock::now();

    // Perform HomLocPIRbb1OPT
    LweSample* result = HomLocPIRbb1OPT(enc_x, enc_y, encryptedDB, inputLength, serviceLength, bk, mode, num_of_threads);

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
    int inputLength = 16;  // Length for interval values (x, y, x_left, x_right, y_left, y_right)
    int serviceLength = 22;   // Length for service values

    // Initialize TFHE parameters and keys
    auto params = initializeParams(security_param);
    auto key = generateKeySet(params);
    const TFheGateBootstrappingCloudKeySet* bk = &key->cloud;

    // Create the result directory if it doesn't exist
    std::filesystem::create_directory("result");

    // Open a CSV file to write results
    std::ofstream file("result/LocPIRbb1_timing_us.csv");
    file << "Mode,Time(s)\n";  // CSV header

    // Provide the path to the CSV file
    std::string filename = std::string(DATA_DIR) + "/us_coordinate_with_confirmed.csv";

    // Load the data from the CSV file
    std::vector<std::vector<std::string>> data = loadDataFromCSV(filename);
    printLoadedData(data);

    // Encode the data
    std::vector<std::vector<int32_t>> encodedDB = encodeDB(data, inputLength);
    printEncodedDB(encodedDB, inputLength, serviceLength);

    // Encrypt the database
    std::vector<std::vector<LweSample*>> encryptedDB = encryptDB(encodedDB, inputLength, serviceLength, params, key);

    std::cout << "Size of data: " << data.size() << std::endl;

    // Encrypted x and y coordinates for the query
    double queryX_value = 40.7128;  // Example query value (you can change this)
    double queryY_value = -74.0060; // Example query value (you can change this)

    int32_t queryX = encodeDouble(inputLength, queryX_value);
    int32_t queryY = encodeDouble(inputLength, queryY_value);
    LweSample* enc_x = encryptBoolean(queryX, inputLength, params, key);
    LweSample* enc_y = encryptBoolean(queryY, inputLength, params, key);

    // Test all parallelization modes and record timings
    double time_NONE = test_HomLocPIRbb1OPT(ParallelizationMode::NONE, "NONE", enc_x, enc_y, encryptedDB, inputLength, serviceLength, bk, 1);
    file << "NONE," << time_NONE << "\n";

    double time_PARALLEL_LOOP_HOMSUM = test_HomLocPIRbb1OPT(ParallelizationMode::PARALLEL_LOOP_HOMSUM, "PARALLEL_LOOP_HOMSUM", enc_x, enc_y, encryptedDB, inputLength, serviceLength, bk, 4);
    file << "PARALLEL_LOOP_HOMSUM," << time_PARALLEL_LOOP_HOMSUM << "\n";

    double time_PARALLEL_LOOP_HOMSUM_BB1_BITWISE = test_HomLocPIRbb1OPT(ParallelizationMode::PARALLEL_LOOP_HOMSUM_BB1_BITWISE, "PARALLEL_LOOP_HOMSUM_BB1_BITWISE", enc_x, enc_y, encryptedDB, inputLength, serviceLength, bk, 4);
    file << "PARALLEL_LOOP_HOMSUM_BB1_BITWISE," << time_PARALLEL_LOOP_HOMSUM_BB1_BITWISE << "\n";

    double time_ALL = test_HomLocPIRbb1OPT(ParallelizationMode::ALL, "ALL", enc_x, enc_y, encryptedDB, inputLength, serviceLength, bk, 4);
    file << "ALL," << time_ALL << "\n";

    file.close();

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(inputLength, enc_x);
    delete_gate_bootstrapping_ciphertext_array(inputLength, enc_y);
    cleanUpEncryptedDB(encryptedDB, inputLength, serviceLength);
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    std::cout << "Test completed and results saved to result/LocPIRbb1_timing_us.csv" << std::endl;

    return 0;
}


#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include "utils.h"
#include "optimized/HomLocOPT.h"
#include "optimized/HomBBOPT.h"

// Function to test HomLocPIRbb2OPT with different parallelization modes
void test_HomLocPIRbb2OPT(ParallelizationMode mode, const std::string& mode_name,
                          const LweSample* enc_x, const LweSample* enc_y,
                          const std::vector<std::vector<LweSample*>>& encryptedDB,
                          int inputLength, int serviceLength, 
                          const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads,
                          const TFheGateBootstrappingSecretKeySet* key) {
    std::cout << "Testing mode: " << mode_name << std::endl;

    // Perform HomLocPIRbb2OPT
    LweSample* result = HomLocPIRbb2OPT(enc_x, enc_y, encryptedDB, inputLength, serviceLength, bk, mode, num_of_threads);

    // Decrypt the result
    std::string decryptedResultBinary = decryptBinaryString(result, serviceLength, key);

    // Convert binary result to text (since the service is a string)
    std::string decryptedResultText = binaryStringToText(decryptedResultBinary);

    // Output the result
    std::cout << "Decrypted result value: " << decryptedResultText << std::endl;

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(serviceLength, result);
}

int main() {
    // Security parameters
    int security_param = 128;
    int inputLength = 16;  // Length for x and y coordinates

    // Initialize TFHE parameters and keys
    auto params = initializeParams(security_param);
    auto key = generateKeySet(params);
    const TFheGateBootstrappingCloudKeySet* bk = &key->cloud;

    // Provide the path to the CSV file
    std::string filename = std::string(DATA_DIR) + "/gdacs_data.csv";

    // Load the data from the CSV file
    std::vector<std::vector<std::string>> data = loadDataFromCSV(filename);
    printLoadedData(data);
    
    int serviceLength = calculateServiceLengthBB2(data);
    std::cout << "serviceLength: " << calculateServiceLengthBB2(data) << std::endl;

    // Encrypt the database
    std::vector<std::vector<LweSample*>> encryptedDB = encryptDBbb2(data, inputLength, serviceLength, params, key, bk);

    std::cout << "Size of data: " << data.size() << std::endl;

    // Encrypted coordinates for the query (example query value, you can change this)
    double queryX_value = 37.5;  // Example query value
    double queryY_value = 126.9; // Example query value

    int32_t queryX = encodeDouble(inputLength, queryX_value);
    int32_t queryY = encodeDouble(inputLength, queryY_value);
    LweSample* enc_x = encryptBoolean(queryX, inputLength, params, key);
    LweSample* enc_y = encryptBoolean(queryY, inputLength, params, key);

    // Test all parallelization modes
    test_HomLocPIRbb2OPT(ParallelizationMode::NONE, "NONE", enc_x, enc_y, encryptedDB, inputLength, serviceLength, bk, 1, key);
    test_HomLocPIRbb2OPT(ParallelizationMode::PARALLEL_LOOP_HOMSUM, "PARALLEL_LOOP_HOMSUM", enc_x, enc_y, encryptedDB, inputLength, serviceLength, bk, 4, key);
    test_HomLocPIRbb2OPT(ParallelizationMode::PARALLEL_LOOP_HOMSUM_BB1_BITWISE, "PARALLEL_LOOP_HOMSUM_BB2_BITWISE", enc_x, enc_y, encryptedDB, inputLength, serviceLength, bk, 4, key);
    test_HomLocPIRbb2OPT(ParallelizationMode::ALL, "ALL", enc_x, enc_y, encryptedDB, inputLength, serviceLength, bk, 4, key);

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(inputLength, enc_x);
    delete_gate_bootstrapping_ciphertext_array(inputLength, enc_y);
    cleanUpEncryptedDB(encryptedDB, inputLength, serviceLength);
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    return 0;
}



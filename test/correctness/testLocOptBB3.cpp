#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include "utils.h"
#include "optimized/HomLocOPT.h"
#include "optimized/HomBBOPT.h"

// Function to test HomLocPIRbb3OPT with different parallelization modes
void test_HomLocPIRbb3OPT(ParallelizationMode mode, const std::string& mode_name,
                          const LweSample* enc_id,
                          const std::vector<std::vector<LweSample*>>& encryptedDB,
                          int inputLength, int serviceLength, 
                          const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads,
                          const TFheGateBootstrappingSecretKeySet* key) {
    std::cout << "Testing mode: " << mode_name << std::endl;

    // Perform HomLocPIRbb3OPT
    LweSample* result = HomLocPIRbb3OPT(enc_id, encryptedDB, inputLength, serviceLength, bk, mode, num_of_threads);

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
    int inputLength = 9;  // Length for identifier values
    int serviceLength = 128;   // Length for service values (adjusted based on your data)

    // Initialize TFHE parameters and keys
    auto params = initializeParams(security_param);
    auto key = generateKeySet(params);
    const TFheGateBootstrappingCloudKeySet* bk = &key->cloud;

    // Provide the path to the CSV file
    std::string filename = std::string(DATA_DIR) + "/pir_weather_data_unique.csv";

    // Load the data from the CSV file
    std::vector<std::vector<std::string>> data = loadDataFromCSVbb3(filename);
    printLoadedData(data);

    // Encrypt the database
    std::vector<std::vector<LweSample*>> encryptedDB = encryptDBbb3(data, inputLength, serviceLength, params, key, bk);

    std::cout << "Size of data: " << data.size() << std::endl;

    // Encrypted identifier for the query (example query value, you can change this)
    int query_id = 1;  // Example query identifier
    LweSample* enc_id = encryptBoolean(query_id, inputLength, params, key);

    // Test all parallelization modes
    test_HomLocPIRbb3OPT(ParallelizationMode::NONE, "NONE", enc_id, encryptedDB, inputLength, serviceLength, bk, 1, key);
    test_HomLocPIRbb3OPT(ParallelizationMode::PARALLEL_LOOP_HOMSUM, "PARALLEL_LOOP_HOMSUM", enc_id, encryptedDB, inputLength, serviceLength, bk, 4, key);
    test_HomLocPIRbb3OPT(ParallelizationMode::PARALLEL_LOOP_HOMSUM_BB1_BITWISE, "PARALLEL_LOOP_HOMSUM_BB1_BITWISE", enc_id, encryptedDB, inputLength, serviceLength, bk, 4, key);
    test_HomLocPIRbb3OPT(ParallelizationMode::ALL, "ALL", enc_id, encryptedDB, inputLength, serviceLength, bk, 4, key);

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(inputLength, enc_id);
    cleanUpEncryptedDB(encryptedDB, inputLength, serviceLength);
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    return 0;
}


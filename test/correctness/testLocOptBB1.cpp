#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include "utils.h"
#include "native/HomComp.h"
#include "optimized/HomBBOPT.h"
#include "optimized/HomLocOPT.h" 

void test_HomLocPIRbb1OPT(ParallelizationMode mode, const std::string& mode_name,
                             const LweSample* enc_x, const LweSample* enc_y,
                             const std::vector<std::vector<LweSample*>>& encryptedDB,
                             int inputLength, int serviceLength, 
                             const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads,
                             const TFheGateBootstrappingSecretKeySet* key) {
    std::cout << "Testing mode: " << mode_name << std::endl;

    // Perform HomLocPIRbb1OPT
    LweSample* result = HomLocPIRbb1OPT(enc_x, enc_y, encryptedDB, inputLength, serviceLength, bk, mode, num_of_threads);

    // Decrypt the result
    std::vector<int> decryptedResultBinary = decryptToBinaryVector(result, serviceLength, key);

    // Convert binary result to integer
    int resultValue = 0;
    for (size_t i = 0; i < decryptedResultBinary.size(); ++i) {
        resultValue += decryptedResultBinary[i] << i;
    }

    // Output the result
    std::cout << "Decrypted result value: " << resultValue << std::endl;

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(serviceLength, result);
}

int main() {
    // Security parameters
    int security_param = 128;
    int inputLength = 16;  // Length for interval values (x, y, x_left, x_right, y_left, y_right)
    int serviceLength = 9;   // Length for service values

    // Initialize TFHE parameters and keys
    auto params = initializeParams(security_param);
    auto key = generateKeySet(params);
    const TFheGateBootstrappingCloudKeySet* bk = &key->cloud;

    // Provide the path to the CSV file
    std::string filename = std::string(DATA_DIR) + "/covid_bb1.csv";

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
    double queryX_value = 37.5;  // Example query value (you can change this)
    double queryY_value = 126.9; // Example query value (you can change this)

    int32_t queryX = encodeDouble(inputLength, queryX_value);
    int32_t queryY = encodeDouble(inputLength, queryY_value);
    LweSample* enc_x = encryptBoolean(queryX, inputLength, params, key);
    LweSample* enc_y = encryptBoolean(queryY, inputLength, params, key);

    // Test all parallelization modes
    test_HomLocPIRbb1OPT(ParallelizationMode::NONE, "NONE", enc_x, enc_y, encryptedDB, inputLength, serviceLength, bk, 1, key);
    test_HomLocPIRbb1OPT(ParallelizationMode::PARALLEL_LOOP_HOMSUM, "PARALLEL_LOOP_HOMSUM", enc_x, enc_y, encryptedDB, inputLength, serviceLength, bk, 4, key);
    test_HomLocPIRbb1OPT(ParallelizationMode::PARALLEL_LOOP_HOMSUM_BB1_BITWISE, "PARALLEL_LOOP_HOMSUM_BB1_BITWISE", enc_x, enc_y, encryptedDB, inputLength, serviceLength, bk, 4, key);
    test_HomLocPIRbb1OPT(ParallelizationMode::ALL, "ALL", enc_x, enc_y, encryptedDB, inputLength, serviceLength, bk, 4, key);

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(inputLength, enc_x);
    delete_gate_bootstrapping_ciphertext_array(inputLength, enc_y);
    cleanUpEncryptedDB(encryptedDB, inputLength, serviceLength);
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    return 0;
}


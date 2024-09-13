#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include "utils.h" 
#include "native/HomLocVan.h" 

int main() {
    // Security parameters
    int security_param = 128;
    int inputLength = 32;  // Length for interval values (x, y, x_left, x_right, y_left, y_right)
    int serviceLength = 16;   // Length for service values

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

    // Perform HomLocPIRbb1
    LweSample* result = HomLocPIRbb1(enc_x, enc_y, encryptedDB, inputLength, serviceLength, bk);

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
    delete_gate_bootstrapping_ciphertext_array(inputLength, enc_x);
    delete_gate_bootstrapping_ciphertext_array(inputLength, enc_y);
    cleanUpEncryptedDB(encryptedDB, inputLength, serviceLength);
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    return 0;
}


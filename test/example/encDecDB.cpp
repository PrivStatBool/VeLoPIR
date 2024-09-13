#include <iostream>
#include <vector>
#include <string>
#include "utils.h"  // Include the utils.h file for all the functions and utilities


int main() {
    // Provide the path to the CSV file
    std::string filename = std::string(DATA_DIR) + "/covid_bb1.csv";

    // Load the data from the CSV file
    std::vector<std::vector<std::string>> data = loadDataFromCSV(filename);

    // Print the loaded data
    printLoadedData(data);

    // Set encoding parameters
    const int inputLength = 32;  // Length of binary representation for coordinates
    const int serviceLength = 24;  // Length of binary representation for service data

    // Initialize parameters and keys
    auto params = initializeParams(128);
    auto key = generateKeySet(params);
    const TFheGateBootstrappingCloudKeySet* bk = &key->cloud;

    // Encode the data
    std::vector<std::vector<int32_t>> encodedDB = encodeDB(data, inputLength);

    // Print the encoded database
    printEncodedDB(encodedDB, inputLength, serviceLength);

    // Encrypt the data
    std::vector<std::vector<LweSample*>> encryptedDB = encryptDB(encodedDB, inputLength, serviceLength, params, key);

    // Decrypt the encrypted database
    std::vector<std::vector<std::vector<int>>> decryptedDB = decryptDB(encryptedDB, inputLength, serviceLength, key);

    // Print the decrypted database (binary representation)
    printDecryptedDB(decryptedDB, inputLength, serviceLength);

    // Decode the decrypted database to the original data
    std::vector<std::vector<std::string>> decodedDB = decodeDB(decryptedDB, inputLength, serviceLength);

    // Print the decoded data
    printLoadedData(decodedDB);

    // Clean up encrypted database and keys
    cleanUpEncryptedDB(encryptedDB, inputLength, serviceLength);
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    return 0;
}


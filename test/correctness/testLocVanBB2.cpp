#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include "tfhe/tfhe.h"
#include "tfhe/tfhe_io.h"
#include "utils.h"

int main() {
    // Security parameters
    int security_param = 128;

    // Initialize TFHE parameters and keys
    auto params = initializeParams(security_param);
    auto key = generateKeySet(params);
    const TFheGateBootstrappingCloudKeySet* bk = &key->cloud;

    // Provide the path to the CSV file
    std::string filename = std::string(DATA_DIR) + "/pir_weather_data_unique.csv";

    // Load the data from the CSV file
    std::vector<std::vector<std::string>> data = loadDataFromCSV(filename);
    printLoadedData(data);

    // Calculate inputLength based on the number of data entries
    int inputLength = calculateInputLength(data.size());

    // Calculate the maximum service length based on the data content
    int serviceLength = calculateServiceLength(data);

    // Encrypt the database
    std::vector<std::vector<LweSample*>> encryptedDB = encryptDBbb3(data, inputLength, serviceLength, params, key, bk);

    // Output the encrypted database or proceed with further processing
    std::cout << "Database encrypted successfully." << std::endl;

    // Clean up: remember to delete ciphertexts and keys once you're done
    for (auto& row : encryptedDB) {
        delete_gate_bootstrapping_ciphertext_array(inputLength, row[0]);  // Identifier
        delete_gate_bootstrapping_ciphertext_array(serviceLength, row[1]);  // Service Data
    }
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    return 0;
}


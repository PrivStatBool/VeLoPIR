#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include "utils.h"
#include "native/HomLocVan.h"  // Assume HomLocPIRbb3 is declared here

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
    std::vector<std::vector<std::string>> data = loadDataFromCSVbb3(filename);
    printLoadedData(data);

    // Calculate inputLength based on the number of data entries
    int inputLength = calculateInputLength(data.size());

    // Calculate the maximum service length based on the data content
    int serviceLength = calculateServiceLength(data);

    // Encrypt the database
    std::vector<std::vector<LweSample*>> encryptedDB = encryptDBbb3(data, inputLength, serviceLength, params, key, bk);

    std::cout << "Database encrypted successfully." << std::endl;

    // Encrypt a query identifier
    int query = 1;  // Example query
    LweSample* enc_id = encryptBoolean(query, inputLength, params, key);

    // Perform HomLocPIRbb3
    LweSample* result = HomLocPIRbb3(enc_id, encryptedDB, inputLength, serviceLength, bk);

    // Decrypt the result
    std::string decryptedBinaryString = decryptBinaryString(result, serviceLength, key);

    // Convert binary string to text
    std::string decryptedResultText = binaryStringToText(decryptedBinaryString);

    // Output the result
    std::cout << "Decrypted result value: " << decryptedResultText << std::endl;

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(serviceLength, result);
    delete_gate_bootstrapping_ciphertext_array(inputLength, enc_id);
    cleanUpEncryptedDB(encryptedDB, inputLength, serviceLength);
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    return 0;
}

#include "native/HomSup.h"
#include "native/HomBB.h" 
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <vector>
#include <iostream>
#include <cassert>

LweSample* HomLocPIRbb1(const LweSample* enc_x, const LweSample* enc_y, 
                        const std::vector<std::vector<LweSample*>>& enc_database, 
                        const int inputLength, const int serviceLength, 
                        const TFheGateBootstrappingCloudKeySet* bk) {

    int M = enc_database.size();  // Number of records in the database

    // Vector to store the filtered data (service values)
    std::vector<LweSample*> filtered_data(M);

    // Initialize each element of filtered_data with a new ciphertext array
    for (int i = 0; i < M; i++) {
        filtered_data[i] = new_gate_bootstrapping_ciphertext_array(serviceLength, bk->params);
    }
    for (int i = 0; i < M; i++) {
        // Step 1: Extract location and perform validation using BB1
        std::vector<LweSample*> loc = {enc_database[i][0], enc_database[i][1], enc_database[i][2], enc_database[i][3]};

        LweSample* validation_result = new_gate_bootstrapping_ciphertext_array(1, bk->params);
        BB1(validation_result, enc_x, enc_y, loc, inputLength, bk);

        // Step 2: Zero Out Unrelated Data (only for the service field)
        LweSample* filtered_service = HomBitwiseAND(validation_result, enc_database[i][4], serviceLength, bk);
        for (int j = 0; j < serviceLength; j++) {
            bootsCOPY(&filtered_data[i][j], &filtered_service[j], bk);
        }
        delete_gate_bootstrapping_ciphertext_array(1, validation_result);  // Cleanup
        delete_gate_bootstrapping_ciphertext_array(serviceLength, filtered_service);  // Cleanup
    }

    // Step 3: Aggregation of the filtered service values
    LweSample* result = HomSum(filtered_data, M, serviceLength, bk);

    // Clean up filtered data
    for (int i = 0; i < M; i++) {
        delete_gate_bootstrapping_ciphertext_array(serviceLength, filtered_data[i]);
    }

    return result;  // Return the aggregated result
}

LweSample* HomLocPIRbb2(const LweSample* enc_x, const LweSample* enc_y, 
                        const std::vector<std::vector<LweSample*>>& enc_database, 
                        const int lengthInterval, const int lengthService, 
                        const TFheGateBootstrappingCloudKeySet* bk) {

    int M = enc_database.size();  // Number of records in the database

    // Vector to store the filtered data (service values)
    std::vector<LweSample*> filtered_data(M);

    for (int i = 0; i < M; i++) {
        // Step 1: Extract location and perform validation using BB2
        std::vector<LweSample*> loc = {enc_database[i][0], enc_database[i][1]};

        LweSample* validation_result = new_gate_bootstrapping_ciphertext_array(1, bk->params);
        BB2(validation_result, enc_x, enc_y, loc, lengthInterval, bk);

        // Step 2: Zero Out Unrelated Data (only for the service field)
        filtered_data[i] = HomBitwiseAND(validation_result, enc_database[i][2], lengthService, bk);

        delete_gate_bootstrapping_ciphertext_array(1, validation_result);  // Cleanup
    }

    // Step 3: Aggregation of the filtered service values
    LweSample* result = HomSum(filtered_data, M, lengthService, bk);

    // Clean up filtered data
    for (int i = 0; i < M; i++) {
        delete_gate_bootstrapping_ciphertext_array(lengthService, filtered_data[i]);
    }

    return result;  // Return the aggregated result
}

LweSample* HomLocPIRbb3(const LweSample* enc_id, 
                        const std::vector<std::vector<LweSample*>>& enc_database,
                        const int lengthInterval, const int lengthService,
                        const TFheGateBootstrappingCloudKeySet* bk) {

    int M = enc_database.size();  // Number of records in the database

    // Vector to store the filtered data (service values)
    std::vector<LweSample*> filtered_data(M);

    for (int i = 0; i < M; i++) {
        // Step 1: Extract the encrypted identifier and perform validation using BB3
        LweSample* targetId = enc_database[i][0];  // The encrypted identifier for the current record

        LweSample* validation_result = new_gate_bootstrapping_ciphertext_array(1, bk->params);
        BB3(validation_result, enc_id, targetId, lengthInterval, bk);  // Perform the comparison

        // Step 2: Zero Out Unrelated Data (only for the service field)
        filtered_data[i] = HomBitwiseAND(validation_result, enc_database[i][1], lengthService, bk);

        delete_gate_bootstrapping_ciphertext_array(1, validation_result);  // Cleanup
    }

    // Step 3: Aggregation of the filtered service values
    LweSample* result = HomSum(filtered_data, M, lengthService, bk);

    // Clean up filtered data
    for (int i = 0; i < M; i++) {
        delete_gate_bootstrapping_ciphertext_array(lengthService, filtered_data[i]);
    }

    return result;  // Return the aggregated result
}


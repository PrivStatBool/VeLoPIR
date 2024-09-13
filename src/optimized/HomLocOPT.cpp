#include "tfhe/tfhe.h"
#include "tfhe/tfhe_io.h"
#include "utils.h"
#include "native/HomLocVan.h"
#include "native/HomBB.h"
#include "optimized/HomCompOPT.h"
#include "optimized/HomBBOPT.h"
#include "optimized/HomSupOPT.h"
#include "optimized/HomLocOPT.h"
#include "native/HomSup.h"

LweSample* HomLocPIRbb1OPT(const LweSample* enc_x, const LweSample* enc_y, 
                               const std::vector<std::vector<LweSample*>>& enc_database, 
                               const int inputLength, const int serviceLength, 
                               const TFheGateBootstrappingCloudKeySet* bk, 
                               ParallelizationMode mode, int num_of_threads) {
    int M = enc_database.size();  // Number of records in the database
    LweSample** filtered_data = new LweSample*[M];  // Use raw array for GPU processing

    // Initialize each element of filtered_data with a new ciphertext array
    for (int i = 0; i < M; i++) {
        filtered_data[i] = new_gate_bootstrapping_ciphertext_array(serviceLength, bk->params);
    }

    if (mode != ParallelizationMode::NONE) {
        // Offload the outer loop to the GPU if parallelization is enabled
        #pragma omp target teams distribute parallel for map(to: enc_x[0:inputLength], enc_y[0:inputLength], bk[0:1]) map(tofrom: filtered_data[0:M])
        for (int i = 0; i < M; i++) {
            // GPU parallel region
            std::vector<LweSample*> loc = {enc_database[i][0], enc_database[i][1], enc_database[i][2], enc_database[i][3]};
            LweSample* validation_result = new_gate_bootstrapping_ciphertext_array(1, bk->params);

            // Apply BB1 and filtering based on the mode
            if (mode == ParallelizationMode::ALL) {
                BB1OptGPU(validation_result, enc_x, enc_y, loc, inputLength, bk, num_of_threads);
            } else if (mode == ParallelizationMode::PARALLEL_LOOP_HOMSUM_BB1_BITWISE) {
                BB1OPT(validation_result, enc_x, enc_y, loc, inputLength, bk, num_of_threads);
            } else {
                BB1(validation_result, enc_x, enc_y, loc, inputLength, bk);
            }

            // Apply HomBitwiseAND based on the mode
            LweSample* filtered_service = nullptr;
            if (mode == ParallelizationMode::PARALLEL_LOOP_HOMSUM_BB1_BITWISE || mode == ParallelizationMode::ALL) {
                filtered_service = HomBitwiseANDGPU(validation_result, enc_database[i][4], serviceLength, bk, num_of_threads);
            } else {
                filtered_service = HomBitwiseAND(validation_result, enc_database[i][4], serviceLength, bk);
            }

            // Copy the filtered_service result to filtered_data
            for (int j = 0; j < serviceLength; j++) {
                bootsCOPY(&filtered_data[i][j], &filtered_service[j], bk);
            }

            delete_gate_bootstrapping_ciphertext_array(1, validation_result);  // Cleanup
            delete_gate_bootstrapping_ciphertext_array(serviceLength, filtered_service);  // Cleanup
        }
    } else {
        // Non-parallel version of the main loop
        for (int i = 0; i < M; i++) {
            std::vector<LweSample*> loc = {enc_database[i][0], enc_database[i][1], enc_database[i][2], enc_database[i][3]};
            LweSample* validation_result = new_gate_bootstrapping_ciphertext_array(1, bk->params);

            BB1(validation_result, enc_x, enc_y, loc, inputLength, bk);

            LweSample* filtered_service = HomBitwiseAND(validation_result, enc_database[i][4], serviceLength, bk);

            for (int j = 0; j < serviceLength; j++) {
                bootsCOPY(&filtered_data[i][j], &filtered_service[j], bk);
            }

            delete_gate_bootstrapping_ciphertext_array(1, validation_result);  
            delete_gate_bootstrapping_ciphertext_array(serviceLength, filtered_service);  
        }
    }

    // Convert filtered_data array to std::vector<LweSample*>
    std::vector<LweSample*> filtered_data_vector(filtered_data, filtered_data + M);

    // Perform HomSum or HomSumGPU based on the mode
    LweSample* result;
    if (mode == ParallelizationMode::NONE) {
        result = HomSum(filtered_data_vector, M, serviceLength, bk);
    } else {
        result = HomSumGPU(filtered_data_vector, M, serviceLength, bk, 32);
    }

    // Clean up filtered data
    for (int i = 0; i < M; i++) {
        delete_gate_bootstrapping_ciphertext_array(serviceLength, filtered_data[i]);
    }

    // Deallocate the filtered_data array
    delete[] filtered_data;

    return result;  // Return the aggregated result
}

LweSample* HomLocPIRbb2OPT(const LweSample* enc_x, const LweSample* enc_y, 
                           const std::vector<std::vector<LweSample*>>& enc_database, 
                           const int lengthInterval, const int lengthService, 
                           const TFheGateBootstrappingCloudKeySet* bk, 
                           ParallelizationMode mode, int num_of_threads) {

    int M = enc_database.size();  // Number of records in the database
    LweSample** filtered_data = new LweSample*[M];  // Use raw array for GPU processing

    // Initialize each element of filtered_data with a new ciphertext array
    for (int i = 0; i < M; i++) {
        filtered_data[i] = new_gate_bootstrapping_ciphertext_array(lengthService, bk->params);
    }

    if (mode != ParallelizationMode::NONE) {
        // Offload the outer loop to the GPU if parallelization is enabled
        #pragma omp target teams distribute parallel for map(to: enc_x[0:lengthInterval], enc_y[0:lengthInterval], bk[0:1]) map(tofrom: filtered_data[0:M])
        for (int i = 0; i < M; i++) {
            // GPU parallel region
            std::vector<LweSample*> loc = {enc_database[i][0], enc_database[i][1]};
            LweSample* validation_result = new_gate_bootstrapping_ciphertext_array(1, bk->params);

            // Apply BB2 and filtering based on the mode
            if (mode == ParallelizationMode::ALL) {
                BB2OptGPU(validation_result, enc_x, enc_y, loc, lengthInterval, bk, num_of_threads);
            } else if (mode == ParallelizationMode::PARALLEL_LOOP_HOMSUM_BB1_BITWISE) {
                BB2OPT(validation_result, enc_x, enc_y, loc, lengthInterval, bk, num_of_threads);
            } else {
                BB2(validation_result, enc_x, enc_y, loc, lengthInterval, bk);
            }

            // Apply HomBitwiseAND based on the mode
            LweSample* filtered_service = nullptr;
            if (mode == ParallelizationMode::PARALLEL_LOOP_HOMSUM_BB1_BITWISE || mode == ParallelizationMode::ALL) {
                filtered_service = HomBitwiseANDGPU(validation_result, enc_database[i][2], lengthService, bk, num_of_threads);
            } else {
                filtered_service = HomBitwiseAND(validation_result, enc_database[i][2], lengthService, bk);
            }

            // Copy the filtered_service result to filtered_data
            for (int j = 0; j < lengthService; j++) {
                bootsCOPY(&filtered_data[i][j], &filtered_service[j], bk);
            }

            delete_gate_bootstrapping_ciphertext_array(1, validation_result);  // Cleanup
            delete_gate_bootstrapping_ciphertext_array(lengthService, filtered_service);  // Cleanup
        }
    } else {
        // Non-parallel version of the main loop
        for (int i = 0; i < M; i++) {
            std::vector<LweSample*> loc = {enc_database[i][0], enc_database[i][1]};
            LweSample* validation_result = new_gate_bootstrapping_ciphertext_array(1, bk->params);

            BB2(validation_result, enc_x, enc_y, loc, lengthInterval, bk);

            LweSample* filtered_service = HomBitwiseAND(validation_result, enc_database[i][2], lengthService, bk);

            for (int j = 0; j < lengthService; j++) {
                bootsCOPY(&filtered_data[i][j], &filtered_service[j], bk);
            }

            delete_gate_bootstrapping_ciphertext_array(1, validation_result);  // Cleanup
            delete_gate_bootstrapping_ciphertext_array(lengthService, filtered_service);  // Cleanup
        }
    }

    // Convert filtered_data array to std::vector<LweSample*>
    std::vector<LweSample*> filtered_data_vector(filtered_data, filtered_data + M);

    // Perform HomSum or HomSumGPU based on the mode
    LweSample* result;
    if (mode == ParallelizationMode::NONE) {
        result = HomSum(filtered_data_vector, M, lengthService, bk);
    } else {
        result = HomSumGPU(filtered_data_vector, M, lengthService, bk, 32);
    }

    // Clean up filtered data
    for (int i = 0; i < M; i++) {
        delete_gate_bootstrapping_ciphertext_array(lengthService, filtered_data[i]);
    }

    // Deallocate the filtered_data array
    delete[] filtered_data;

    return result;  
}

LweSample* HomLocPIRbb3OPT(const LweSample* enc_id, 
                           const std::vector<std::vector<LweSample*>>& enc_database,
                           const int lengthInterval, const int lengthService,
                           const TFheGateBootstrappingCloudKeySet* bk, 
                           ParallelizationMode mode, int num_of_threads) {

    int M = enc_database.size();  

    LweSample** filtered_data = new LweSample*[M];  

    // Initialize each element of filtered_data with a new ciphertext array
    for (int i = 0; i < M; i++) {
        filtered_data[i] = new_gate_bootstrapping_ciphertext_array(lengthService, bk->params);
    }

    if (mode != ParallelizationMode::NONE) {
        // Offload the outer loop to the GPU if parallelization is enabled
        #pragma omp target teams distribute parallel for map(to: enc_id[0:lengthInterval], bk[0:1]) map(tofrom: filtered_data[0:M])
        for (int i = 0; i < M; i++) {
            // GPU parallel region
            LweSample* targetId = enc_database[i][0];  // The encrypted identifier for the current record
            LweSample* validation_result = new_gate_bootstrapping_ciphertext_array(1, bk->params);

            // Apply BB3 and filtering based on the mode
            if (mode == ParallelizationMode::ALL) {
                BB3OptGPU(validation_result, enc_id, targetId, lengthInterval, bk, num_of_threads);
            } else {
                BB3(validation_result, enc_id, targetId, lengthInterval, bk);
            }

            // Apply HomBitwiseAND based on the mode
            LweSample* filtered_service = nullptr;
            if (mode == ParallelizationMode::PARALLEL_LOOP_HOMSUM_BB1_BITWISE || mode == ParallelizationMode::ALL) {
                filtered_service = HomBitwiseANDGPU(validation_result, enc_database[i][1], lengthService, bk, num_of_threads);
            } else {
                filtered_service = HomBitwiseAND(validation_result, enc_database[i][1], lengthService, bk);
            }

            // Copy the filtered_service result to filtered_data
            for (int j = 0; j < lengthService; j++) {
                bootsCOPY(&filtered_data[i][j], &filtered_service[j], bk);
            }

            delete_gate_bootstrapping_ciphertext_array(1, validation_result);  
            delete_gate_bootstrapping_ciphertext_array(lengthService, filtered_service);  
        }
    } else {
        // Non-parallel version of the main loop
        for (int i = 0; i < M; i++) {
            LweSample* targetId = enc_database[i][0];  
            LweSample* validation_result = new_gate_bootstrapping_ciphertext_array(1, bk->params);

            BB3(validation_result, enc_id, targetId, lengthInterval, bk);

            LweSample* filtered_service = HomBitwiseAND(validation_result, enc_database[i][1], lengthService, bk);

            for (int j = 0; j < lengthService; j++) {
                bootsCOPY(&filtered_data[i][j], &filtered_service[j], bk);
            }

            delete_gate_bootstrapping_ciphertext_array(1, validation_result);  
            delete_gate_bootstrapping_ciphertext_array(lengthService, filtered_service);  
        }
    }

    // Convert filtered_data array to std::vector<LweSample*>
    std::vector<LweSample*> filtered_data_vector(filtered_data, filtered_data + M);

    // Perform HomSum or HomSumGPU based on the mode
    LweSample* result;
    if (mode == ParallelizationMode::NONE) {
        result = HomSum(filtered_data_vector, M, lengthService, bk);
    } else {
        result = HomSumGPU(filtered_data_vector, M, lengthService, bk, 32);
    }

    // Clean up filtered data
    for (int i = 0; i < M; i++) {
        delete_gate_bootstrapping_ciphertext_array(lengthService, filtered_data[i]);
    }

    // Deallocate the filtered_data array
    delete[] filtered_data;

    return result;  
}




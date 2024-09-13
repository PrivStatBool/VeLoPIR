#ifndef HOM_LOC_OPT_H
#define HOM_LOC_OPT_H

#include "tfhe/tfhe.h"
#include "tfhe/tfhe_io.h"
#include <vector>

enum class ParallelizationMode {
    NONE,                            // No parallelization
    PARALLEL_LOOP_HOMSUM,            // Parallelization of the main loop over M + GPU-accelerated HomSum
    PARALLEL_LOOP_HOMSUM_BB1_BITWISE,// Parallelization of the main loop over M + GPU-accelerated HomSum + BB1OPT + HomBitwiseAND
    ALL                              // Parallelization of the main loop over M + GPU-accelerated HomSum + HomBitwiseAND + BB1OptGPU
};

LweSample* HomLocPIRbb1OPT(const LweSample* enc_x, const LweSample* enc_y, 
                               const std::vector<std::vector<LweSample*>>& enc_database, 
                               const int inputLength, const int serviceLength, 
                               const TFheGateBootstrappingCloudKeySet* bk, 
                               ParallelizationMode mode, int num_of_threads);

LweSample* HomLocPIRbb2OPT(const LweSample* enc_x, const LweSample* enc_y, 
                           const std::vector<std::vector<LweSample*>>& enc_database, 
                           const int lengthInterval, const int lengthService, 
                           const TFheGateBootstrappingCloudKeySet* bk, 
                           ParallelizationMode mode, int num_of_threads); 
 
LweSample* HomLocPIRbb3OPT(const LweSample* enc_id, 
                           const std::vector<std::vector<LweSample*>>& enc_database,
                           const int lengthInterval, const int lengthService,
                           const TFheGateBootstrappingCloudKeySet* bk, 
                           ParallelizationMode mode, int num_of_threads); 


#endif // HOM_LOC_OPT_H


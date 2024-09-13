#ifndef HOMSUP_OPT_H
#define HOMSUP_OPT_H

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <vector>

// Optimized version of HomBitwiseAND using parallelization
LweSample* HomBitwiseANDOPT(LweSample* v, LweSample* ct, const int lengthService, const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads);
LweSample* HomBitwiseANDGPU(LweSample* v, LweSample* ct, const int lengthService, const TFheGateBootstrappingCloudKeySet* bk, int num_of_cores);
LweSample* HomSumOPT(std::vector<LweSample*>& ct_array, const int num_elements, const int lengthService, const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads);
LweSample* HomSumGPU(std::vector<LweSample*>& ct_array, const int num_elements, const int lengthService, const TFheGateBootstrappingCloudKeySet* bk, int num_of_cores); 



#endif // HOMSUP_OPT_H


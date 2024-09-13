#ifndef HOMBBOPT_H
#define HOMBBOPT_H

#include <tfhe/tfhe.h>
#include <vector>

// BB1 Outer 
void BB1OPT(LweSample* res, const LweSample* x, const LweSample* y, 
            const std::vector<LweSample*>& loc, const int length, 
            const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads);

// BB1 Inner
void BB1OptGPU(LweSample* res, const LweSample* x, const LweSample* y, 
               const std::vector<LweSample*>& loc, const int length, 
               const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads); 


// BB2 Outer
void BB2OPT(LweSample* res, const LweSample* x, const LweSample* y, 
            const std::vector<LweSample*>& loc, const int length, 
            const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads);

// BB2 Inner
void BB2OptGPU(LweSample* res, const LweSample* x, const LweSample* y, 
               const std::vector<LweSample*>& loc, const int length, 
               const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads);

void BB3OptGPU(LweSample* res, const LweSample* id, const LweSample* targetId, const int length, const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads);
 
 
#endif // HOMBBOPT_H


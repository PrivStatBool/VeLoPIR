#ifndef HOMBB_H
#define HOMBB_H

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <vector>

void BB1(LweSample* res, const LweSample* x, const LweSample* y, 
         const std::vector<LweSample*>& loc, const int length, const TFheGateBootstrappingCloudKeySet* bk);
void BB2(LweSample* res, const LweSample* x, const LweSample* y, 
         const std::vector<LweSample*>& loc, const int length, const TFheGateBootstrappingCloudKeySet* bk);
void BB3(LweSample* res, const LweSample* id, const LweSample* targetId, const int length, const TFheGateBootstrappingCloudKeySet* bk); 

#endif // HOMBB_H


#ifndef HOMCOMPOPT_H_
#define HOMCOMPOPT_H_

void HomCompLeOPT(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads); 
void HomCompLOPT(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads); 
void HomEquiOPT(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk, int num_of_threads); 
void HomCompLeGPU(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk, int num_of_cores); 
void HomCompLGPU(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk, int num_of_cores); 
void HomEquiGPU(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk, int num_of_cores); 

#endif

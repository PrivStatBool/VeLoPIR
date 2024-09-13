#ifndef HOMLOCPIR_H
#define HOMLOCPIR_H

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <vector>

// Location-Based PIR function using BB1
LweSample* HomLocPIRbb1(const LweSample* enc_x, const LweSample* enc_y, 
                        const std::vector<std::vector<LweSample*>>& enc_database, 
                        const int lengthInterval, const int lengthService, 
                        const TFheGateBootstrappingCloudKeySet* bk);

LweSample* HomLocPIRbb2(const LweSample* enc_x, const LweSample* enc_y, 
                        const std::vector<std::vector<LweSample*>>& enc_database, 
                        const int lengthInterval, const int lengthService, 
                        const TFheGateBootstrappingCloudKeySet* bk); 

LweSample* HomLocPIRbb3(const LweSample* enc_id, 
                        const std::vector<std::vector<LweSample*>>& enc_database,
                        const int lengthInterval, const int lengthService,
                        const TFheGateBootstrappingCloudKeySet* bk); 

#endif // HOMLOCPIR_H


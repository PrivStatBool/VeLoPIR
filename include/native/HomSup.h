#ifndef HOMSUP_H
#define HOMSUP_H

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>

// Perform bitwise AND between a single-bit ciphertext `v` and each bit of a ciphertext array `ct`
LweSample* HomBitwiseAND(const LweSample* v, const LweSample* ct, const int length, const TFheGateBootstrappingCloudKeySet* bk);

// Sum up an array of ciphertexts using XOR to perform bitwise addition
LweSample* HomSum(const std::vector<LweSample*>& ct_array, const int num_elements, const int lengthService, const TFheGateBootstrappingCloudKeySet* bk);

#endif // HOMSUP_H


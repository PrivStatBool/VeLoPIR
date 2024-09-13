#ifndef UTILS_H
#define UTILS_H

#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <vector>
#include <string>

// Initialization functions
TFheGateBootstrappingParameterSet* initializeParams(int minimum_lambda);
TFheGateBootstrappingSecretKeySet* generateKeySet(TFheGateBootstrappingParameterSet* params);

// Encoding and decoding functions
int32_t encodeDouble(int length, double data);
double decodeDouble(const std::vector<int>& binaryVector);

// Encryption and decryption functions
LweSample* encryptBoolean(int32_t plaintext, int length, const TFheGateBootstrappingParameterSet* params, const TFheGateBootstrappingSecretKeySet* key);
std::vector<int> decryptToBinaryVector(const LweSample* ciphertext, int length, const TFheGateBootstrappingSecretKeySet* key);


// Text to String
std::string textToBinaryString(const std::string& text, int serviceLength);
std::string binaryStringToText(const std::string& binaryString);

// Binary String to LweSample
LweSample* encryptBinaryString(const std::string& binaryString, const TFheGateBootstrappingSecretKeySet* key, const TFheGateBootstrappingCloudKeySet* bk); 
std::string decryptBinaryString(const LweSample* ciphertext, int length, const TFheGateBootstrappingSecretKeySet* key);

// Data loading and output functions
void outputToCSV(const std::vector<std::vector<double>>& data, const std::string& fileName);

// Encrypt & Encode Database
std::vector<std::vector<std::string>> loadDataFromCSV(const std::string& filename); 
std::vector<std::vector<int32_t>> encodeDB(const std::vector<std::vector<std::string>>& data, int inputLength); 
std::vector<std::vector<LweSample*>> encryptDB(const std::vector<std::vector<int32_t>>& encodedDB,
                                               int inputLength, int serviceLength,
                                               const TFheGateBootstrappingParameterSet* params,
                                               const TFheGateBootstrappingSecretKeySet* key); 

// Decrypt & Decode Database
std::vector<std::vector<std::vector<int>>> decryptDB(const std::vector<std::vector<LweSample*>>& encryptedDB,
                                                     int inputLength, int serviceLength,
                                                     const TFheGateBootstrappingSecretKeySet* key); 
std::vector<std::vector<std::string>> decodeDB(const std::vector<std::vector<std::vector<int>>>& decryptedDB,
                                               int inputLength, int serviceLength); 

// Util database  
void printLoadedData(const std::vector<std::vector<std::string>>& data); 
void printEncodedDB(const std::vector<std::vector<int32_t>>& encodedDB, int inputLength, int serviceLength); 
void printDecryptedDB(const std::vector<std::vector<std::vector<int>>>& decryptedDB,
                      int inputLength, int serviceLength); 
void cleanUpEncryptedDB(std::vector<std::vector<LweSample*>>& encryptedDB, int inputLength, int serviceLength); 

// for BB3
int calculateInputLength(int dataSize);
int calculateServiceLength(const std::vector<std::vector<std::string>>& data); 
std::vector<std::vector<LweSample*>> encryptDBbb3(const std::vector<std::vector<std::string>>& data,
                                                  int inputLength,
                                                  int serviceLength,
                                                  const TFheGateBootstrappingParameterSet* params,
                                                  const TFheGateBootstrappingSecretKeySet* key,
                                                  const TFheGateBootstrappingCloudKeySet* bk); 
 
std::vector<std::vector<std::string>> loadDataFromCSVbb3(const std::string& filename); 

// for BB3
std::vector<std::vector<LweSample*>> encryptDBbb2(const std::vector<std::vector<std::string>>& data,
                                                  int inputLength,
                                                  int serviceLength,
                                                  const TFheGateBootstrappingParameterSet* params,
                                                  const TFheGateBootstrappingSecretKeySet* key,
                                                  const TFheGateBootstrappingCloudKeySet* bk); 
 
int calculateServiceLengthBB2(const std::vector<std::vector<std::string>>& data); 

#endif // UTILS_H


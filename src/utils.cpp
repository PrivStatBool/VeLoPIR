#include "utils.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cmath>
#include <vector>
#include <random>
#include <string>
#include <bitset>

// Initialization functions
TFheGateBootstrappingParameterSet* initializeParams(int minimum_lambda) {
    return new_default_gate_bootstrapping_parameters(minimum_lambda);
}

TFheGateBootstrappingSecretKeySet* generateKeySet(TFheGateBootstrappingParameterSet* params) {
    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed, 3);
    return new_random_gate_bootstrapping_secret_keyset(params);
}

// Encoding and decoding functions
int32_t encodeDouble(int length, double data) {
    if (length % 2 != 0) {
        std::cerr << "Length must be even for the specified bit allocation." << std::endl;
        return 0;
    }

    int fractionalBits = length / 2 - 1;
    double scale = pow(2.0, fractionalBits);
    double scaledData = round(data * scale);

    int32_t encodedData;
    if (scaledData >= 0) {
        encodedData = static_cast<int32_t>(scaledData);
    } else {
        encodedData = static_cast<int32_t>(pow(2, length - 1) + scaledData);
    }

    encodedData &= (1 << (length - 1)) - 1;

    if (data < 0) {
        encodedData |= 1 << (length - 1);
    }

    return encodedData;
}

double decodeDouble(const std::vector<int>& binaryVector) {
    int length = binaryVector.size();
    bool isNegative = binaryVector[length - 1] == 1;
    int32_t value = 0;
    double result;

    if (isNegative) {
        for (int i = 0; i < length - 1; i++) {
            value += (!binaryVector[i]) << i;
        }
        value = (value + 1) & ((1 << (length - 1)) - 1);
    } else {
        for (int i = 0; i < length - 1; i++) {
            value += binaryVector[i] << i;
        }
    }

    result = value / pow(2.0, (length / 2) - 1);
    if (isNegative) {
        result = -result;
    }

    return result;
}

// Encryption and decryption functions
LweSample* encryptBoolean(int32_t plaintext, int length, const TFheGateBootstrappingParameterSet* params, const TFheGateBootstrappingSecretKeySet* key) {
    LweSample* ciphertext = new_gate_bootstrapping_ciphertext_array(length, params);
    for (int i = 0; i < length; i++) 
        bootsSymEncrypt(&ciphertext[i], (plaintext >> i) & 1, key);
    return ciphertext;
}

std::vector<int> decryptToBinaryVector(const LweSample* ciphertext, int length, const TFheGateBootstrappingSecretKeySet* key) {
    std::vector<int> binaryVector(length);
    for(int i = 0; i < length; i++) {
        binaryVector[i] = bootsSymDecrypt(&ciphertext[i], key);
    }
    return binaryVector;
}

// Function to convert a text string to a binary string
std::string textToBinaryString(const std::string& text, int serviceLength) {
    std::string binaryString = "";
    
    for (char c : text) {
        std::string binaryChar = std::bitset<8>(c).to_string();  
        binaryString += binaryChar;
    }

    // Truncate or pad the binary string to match serviceLength
    if (binaryString.length() > serviceLength) {
        binaryString = binaryString.substr(0, serviceLength);  
    } else {
        binaryString = std::string(serviceLength - binaryString.length(), '0') + binaryString;  
    }

    return binaryString;
}

std::string binaryStringToText(const std::string& binaryString) {
    std::string text = "";

    // Process 8 bits at a time, as each character is represented by 8 bits
    for (size_t i = 0; i < binaryString.length(); i += 8) {
        std::string byte = binaryString.substr(i, 8);
        char chr = static_cast<char>(std::bitset<8>(byte).to_ulong());
        text += chr;
    }

    return text;
}

// Function to encrypt a binary string
LweSample* encryptBinaryString(const std::string& binaryString, const TFheGateBootstrappingSecretKeySet* key, const TFheGateBootstrappingCloudKeySet* bk) {
    int length = binaryString.length();
    LweSample* ciphertext = new_gate_bootstrapping_ciphertext_array(length, bk->params);
    
    for (int i = 0; i < length; i++) {
        int bit = binaryString[i] - '0';  // Convert '0' or '1' to integer
        bootsSymEncrypt(&ciphertext[i], bit, key);
    }
    
    return ciphertext;
}

std::string decryptBinaryString(const LweSample* ciphertext, int length, const TFheGateBootstrappingSecretKeySet* key) {
    std::string binaryString = "";

    for (int i = 0; i < length; i++) {
        int bit = bootsSymDecrypt(&ciphertext[i], key);
        binaryString += std::to_string(bit);
    }

    return binaryString;
}

// Encryption of Database
std::vector<std::vector<std::string>> loadDataFromCSV(const std::string& filename) {
    std::vector<std::vector<std::string>> data;
    std::string line;
    std::ifstream file(filename);

    if (file.is_open()) {
        bool isHeader = true;  
        while (std::getline(file, line)) {
            std::stringstream linestream(line);
            std::string cell;
            std::vector<std::string> row;

            if (isHeader) {
                isHeader = false;  
                continue;
            }

            std::getline(linestream, cell, ',');

            while (std::getline(linestream, cell, ',')) {
                row.push_back(cell);
            }

            data.push_back(row);
        }
        file.close();
    } else {
        std::cerr << "Unable to open file: " << filename << std::endl;
    }

    return data;
}

// Function to print the loaded data for testing
void printLoadedData(const std::vector<std::vector<std::string>>& data) {
    std::cout << "Loaded Data:" << std::endl;
    for (const auto& row : data) {
        for (const auto& cell : row) {
            std::cout << cell << " ";
        }
        std::cout << std::endl;
    }
}

// Function to encode the dataset
std::vector<std::vector<int32_t>> encodeDB(const std::vector<std::vector<std::string>>& data, int inputLength) {
    std::vector<std::vector<int32_t>> encodedDB;

    for (const auto& row : data) {
        std::vector<int32_t> encodedRow;
        for (size_t i = 0; i < row.size(); ++i) {
            if (i < row.size() - 1) {
                // Convert the string to a double and encode it
                double value = std::stod(row[i]);
                int32_t encodedValue = encodeDouble(inputLength, value);
                encodedRow.push_back(encodedValue);
            } else {
                // Handle the service column: convert the string to an integer directly
                int32_t serviceValue = std::stoi(row[i]);
                encodedRow.push_back(serviceValue);
            }
        }
        encodedDB.push_back(encodedRow);
    }

    return encodedDB;
}

// Function to print the encoded database in binary representation
void printEncodedDB(const std::vector<std::vector<int32_t>>& encodedDB, int inputLength, int serviceLength) {
    std::cout << "Encoded Database (Binary Representation):" << std::endl;
    for (const auto& row : encodedDB) {
        for (size_t i = 0; i < row.size(); ++i) {
            int length = (i < row.size() - 1) ? inputLength : serviceLength;
            std::cout << std::bitset<32>(row[i]).to_string().substr(32 - length) << " ";
        }
        std::cout << std::endl;
    }
}

std::vector<std::vector<LweSample*>> encryptDB(const std::vector<std::vector<int32_t>>& encodedDB,
                                               int inputLength, int serviceLength,
                                               const TFheGateBootstrappingParameterSet* params,
                                               const TFheGateBootstrappingSecretKeySet* key) {
    std::vector<std::vector<LweSample*>> encryptedDB;

    for (const auto& row : encodedDB) {
        std::vector<LweSample*> encryptedRow;
        for (size_t i = 0; i < row.size(); ++i) {
            int length = (i < row.size() - 1) ? inputLength : serviceLength;
            LweSample* enc_value = encryptBoolean(row[i], length, params, key);
            encryptedRow.push_back(enc_value);
        }
        encryptedDB.push_back(encryptedRow);
    }

    return encryptedDB;
}

// Utility function to clean up encrypted database
void cleanUpEncryptedDB(std::vector<std::vector<LweSample*>>& encryptedDB, int inputLength, int serviceLength) {
    for (auto& row : encryptedDB) {
        for (size_t i = 0; i < row.size(); ++i) {
            int length = (i < row.size() - 1) ? inputLength : serviceLength;
            delete_gate_bootstrapping_ciphertext_array(length, row[i]);
        }
    }
}

// Function to decrypt the encrypted database
std::vector<std::vector<std::vector<int>>> decryptDB(const std::vector<std::vector<LweSample*>>& encryptedDB,
                                                     int inputLength, int serviceLength,
                                                     const TFheGateBootstrappingSecretKeySet* key) {
    std::vector<std::vector<std::vector<int>>> decryptedDB;

    for (const auto& row : encryptedDB) {
        std::vector<std::vector<int>> decryptedRow;
        for (size_t i = 0; i < row.size(); ++i) {
            int length = (i < row.size() - 1) ? inputLength : serviceLength;
            std::vector<int> binaryVector = decryptToBinaryVector(row[i], length, key);
            decryptedRow.push_back(binaryVector);
        }
        decryptedDB.push_back(decryptedRow);
    }

    return decryptedDB;
}

// Function to print the decrypted database (binary representation)
void printDecryptedDB(const std::vector<std::vector<std::vector<int>>>& decryptedDB,
                      int inputLength, int serviceLength) {
    std::cout << "Decrypted Database (Binary Representation):" << std::endl;
    for (const auto& row : decryptedDB) {
        for (size_t i = 0; i < row.size(); ++i) {
            int length = (i < row.size() - 1) ? inputLength : serviceLength;
            for (int bit : row[i]) {
                std::cout << bit;
            }
            std::cout << " ";
        }
        std::cout << std::endl;
    }
}

std::vector<std::vector<std::string>> decodeDB(const std::vector<std::vector<std::vector<int>>>& decryptedDB,
                                               int inputLength, int serviceLength) {
    std::vector<std::vector<std::string>> decodedDB;

    for (const auto& row : decryptedDB) {
        std::vector<std::string> decodedRow;
        for (size_t i = 0; i < row.size(); ++i) {
            if (i < row.size() - 1) {
                // Decode location coordinates
                double decodedValue = decodeDouble(row[i]);
                decodedRow.push_back(std::to_string(decodedValue));
            } else {
                // Decode service column (assuming it's an integer)
                int serviceValue = 0;
                for (size_t j = 0; j < serviceLength; ++j) {
                    serviceValue += row[i][j] * (1 << j);
                }
                decodedRow.push_back(std::to_string(serviceValue));
            }
        }
        decodedDB.push_back(decodedRow);
    }

    return decodedDB;
}

void outputToCSV(const std::vector<std::vector<double>>& data, const std::string& fileName) {
    std::ofstream file(fileName);
    file << "num_threads,8-bit,16-bit,32-bit\n";
    for (const auto& row : data) {
        for (size_t i = 0; i < row.size(); ++i) {
            file << row[i];
            if (i < row.size() - 1) {
                file << ",";
            }
        }
        file << "\n";
    }
    file.close();
}

// Function to calculate the number of bits required to represent an integer value
int calculateInputLength(int dataSize) {
    return static_cast<int>(std::ceil(std::log2(dataSize)));
}

// Function to determine the maximum bit size for the service data
int calculateServiceLength(const std::vector<std::vector<std::string>>& data) {
    int maxServiceLength = 0;
    for (const auto& entry : data) {
        int currentLength = entry[1].length() * 8;  
        if (currentLength > maxServiceLength) {
            maxServiceLength = currentLength;
        }
    }
    return maxServiceLength;
}

// Function to encrypt the database
std::vector<std::vector<LweSample*>> encryptDBbb3(const std::vector<std::vector<std::string>>& data,
                                                  int inputLength,
                                                  int serviceLength,
                                                  const TFheGateBootstrappingParameterSet* params,
                                                  const TFheGateBootstrappingSecretKeySet* key,
                                                  const TFheGateBootstrappingCloudKeySet* bk) {
    int dataSize = data.size();
    std::vector<std::vector<LweSample*>> encryptedDatabase(dataSize, std::vector<LweSample*>(2));

    for (int i = 0; i < dataSize; i++) {
        // Encrypt the identifier (first column)
        int32_t identifier = i;  
        encryptedDatabase[i][0] = encryptBoolean(identifier, inputLength, params, key);

        // Encrypt the service data (second column)
        std::string binaryString = textToBinaryString(data[i][1], serviceLength);
        encryptedDatabase[i][1] = encryptBinaryString(binaryString, key, bk);
    }

    return encryptedDatabase;
}

std::vector<std::vector<std::string>> loadDataFromCSVbb3(const std::string& filename) {
    std::vector<std::vector<std::string>> data;
    std::ifstream file(filename);

    if (file.is_open()) {
        std::string line;

        // Skip the first line (header)
        std::getline(file, line);

        // Process the remaining lines
        while (std::getline(file, line)) {
            std::istringstream ss(line);
            std::string city, encoding, service;

            // Extract the first column (Station.City) and discard it
            std::getline(ss, city, ',');

            // Extract the second column (City Encoding)
            std::getline(ss, encoding, ',');

            // Extract the third column (Service) - the rest of the line
            std::getline(ss, service);

            service = service.substr(service.find_first_not_of(" \""));

            service = service.substr(0, service.find_last_not_of(" \"") + 1);

            data.push_back({encoding, service});
        }
        file.close();
    }

    return data;
}

// Function to encrypt the database
std::vector<std::vector<LweSample*>> encryptDBbb2(const std::vector<std::vector<std::string>>& data,
                                                  int inputLength,
                                                  int serviceLength,
                                                  const TFheGateBootstrappingParameterSet* params,
                                                  const TFheGateBootstrappingSecretKeySet* key,
                                                  const TFheGateBootstrappingCloudKeySet* bk) {
    int dataSize = data.size();
    std::vector<std::vector<LweSample*>> encryptedDatabase(dataSize, std::vector<LweSample*>(3));

    for (int i = 0; i < dataSize; i++) {
        // Encrypt the x-coordinate (first column)
        double x_value = std::stod(data[i][0]);
        int32_t encoded_x = encodeDouble(inputLength, x_value);
        encryptedDatabase[i][0] = encryptBoolean(encoded_x, inputLength, params, key);

        // Encrypt the y-coordinate (second column)
        double y_value = std::stod(data[i][1]);
        int32_t encoded_y = encodeDouble(inputLength, y_value);
        encryptedDatabase[i][1] = encryptBoolean(encoded_y, inputLength, params, key);

        // Encrypt the service data (third column)
        std::string binaryString = textToBinaryString(data[i][2], serviceLength);
        encryptedDatabase[i][2] = encryptBinaryString(binaryString, key, bk);
    }

    return encryptedDatabase;
}

int calculateServiceLengthBB2(const std::vector<std::vector<std::string>>& data) {
    int maxServiceLength = 0;
    for (const auto& entry : data) {
        int currentLength = entry[2].length() * 8;  
        if (currentLength > maxServiceLength) {
            maxServiceLength = currentLength;
        }
    }
    return maxServiceLength;
}

#include <vector>
#include <string>
#include <iostream>
#include <bitset>
#include <sstream>
#include <cmath>
#include "utils.h"

int main() {
    // Sample data similar to what was loaded
    std::vector<std::vector<std::string>> data = {
        {"37.4758", "37.6195", "126.8831", "127.1331", "427"},
        {"35.1692", "35.2199", "128.8821", "129.2104", "33"},
        {"35.7467", "35.9743", "128.4280", "128.6909", "61"},
        {"37.4127", "37.5941", "126.5876", "126.7894", "74"},
        {"35.0732", "35.2361", "126.7050", "126.9533", "5"},
        {"36.2615", "36.4508", "127.2998", "127.5076", "13"},
        {"35.3710", "36.6745", "129.0731", "129.3644", "9"},
        {"36.5018", "36.6970", "127.1430", "127.4080", "6"},
        {"33.2948", "33.5149", "126.1874", "126.8493", "6"},
    };

    // Set encoding parameters
    const int inputLength = 32;  // Length of binary representation for coordinates
    const int serviceLength = 24;  // Length of binary representation for service data

    // Encode the data
    std::vector<std::vector<int32_t>> encodedDB = encodeDB(data, inputLength);

    // Print the encoded data in binary representation
    printEncodedDB(encodedDB, inputLength, serviceLength);

    return 0;
}


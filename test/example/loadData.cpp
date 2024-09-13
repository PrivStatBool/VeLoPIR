#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include "utils.h"


int main() {
    // Provide the path to the CSV file
    std::string filename = std::string(DATA_DIR) + "/covid_bb1.csv";

    // Load the data from the CSV file
    std::vector<std::vector<std::string>> data = loadDataFromCSV(filename);

    // Print the loaded data to verify
    printLoadedData(data);

    return 0;
}


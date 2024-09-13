#include <iostream>
#include "utils.h"

int main() {
    std::string testString = "this is some text";
    int serviceLength = 64;  // Example service length

    // Convert the text string to a binary string
    std::string binaryString = textToBinaryString(testString, serviceLength);

    // Print the original text and the resulting binary string
    std::cout << "Original text: " << testString << std::endl;
    std::cout << "Binary string (" << serviceLength << " bits): " << binaryString << std::endl;

    return 0;
}


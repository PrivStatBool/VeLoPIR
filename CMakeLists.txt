cmake_minimum_required(VERSION 3.10)
project(locPIR)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include directories
include_directories(include)

# Define the path to the data directory relative to the project root
set(DATA_DIR "${CMAKE_SOURCE_DIR}/data/")

# Add a preprocessor definition to pass the data directory path to the code
add_compile_definitions(DATA_DIR="${DATA_DIR}")

set(BUILD_DIR "${CMAKE_BINARY_DIR}/test/correctness")


# Add the library with all related source files
add_library(locPIR 
    src/utils.cpp 
    src/native/HomComp.cpp 
    src/native/HomBB.cpp 
    src/native/HomSup.cpp 
    src/native/HomLocVan.cpp 
    src/optimized/HomCompOPT.cpp 
    src/optimized/HomSupOPT.cpp 
    src/optimized/HomBBOPT.cpp 
    src/optimized/HomLocOPT.cpp
) 

# Find the TFHE library
find_library(TFHE_LIB tfhe-spqlios-fma)

# Find OpenMP
find_package(OpenMP REQUIRED)

if(OpenMP_CXX_FOUND)
    # Determine if the compiler is GCC or Clang
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        # For GCC, ensure nvptx offloading is enabled and disable LTO
        target_compile_options(locPIR PUBLIC -fopenmp -foffload=nvptx-none -fno-lto)
        target_link_options(locPIR PUBLIC -fno-lto)
        message(STATUS "Using GCC with OpenMP GPU offloading")
    elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
        # For Clang, enable the appropriate CUDA offloading
        target_compile_options(locPIR PUBLIC -fopenmp -fopenmp-targets=nvptx64-nvidia-cuda)
        message(STATUS "Using Clang with OpenMP GPU offloading")
    else()
        message(WARNING "Unknown compiler. Falling back to standard OpenMP.")
        target_compile_options(locPIR PUBLIC -fopenmp)
    endif()
    target_link_libraries(locPIR PUBLIC ${TFHE_LIB} OpenMP::OpenMP_CXX)
else()
    message(FATAL_ERROR "OpenMP not found.")
    target_link_libraries(locPIR PUBLIC ${TFHE_LIB})
endif()

# Add subdirectories for tests or demos
add_subdirectory(test)


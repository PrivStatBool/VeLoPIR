add_executable(testSup testSup.cpp)
target_link_libraries(testSup locPIR)

add_executable(testSupOPT testSupOPT.cpp)
target_link_libraries(testSupOPT locPIR)

add_executable(testBB1 testBB1.cpp)
target_link_libraries(testBB1 locPIR)

add_executable(testBB2 testBB2.cpp)
target_link_libraries(testBB2 locPIR)

add_executable(testBB3 testBB3.cpp)
target_link_libraries(testBB3 locPIR)

add_executable(testBB1opt testBB1opt.cpp)
target_link_libraries(testBB1opt locPIR)

add_executable(testCompGPU testCompGPU.cpp)
target_link_libraries(testCompGPU locPIR)


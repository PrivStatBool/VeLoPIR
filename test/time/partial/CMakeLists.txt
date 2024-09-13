add_executable(timeEquiOPT timeEquiOPT.cpp)
target_link_libraries(timeEquiOPT locPIR)

add_executable(timeCompLEOPT timeCompLEOPT.cpp)
target_link_libraries(timeCompLEOPT locPIR)

add_executable(timeCompLOPT timeCompLOPT.cpp)
target_link_libraries(timeCompLOPT locPIR)

add_executable(timeBB1OPT timeBB1OPT.cpp)
target_link_libraries(timeBB1OPT locPIR)

add_executable(timeBB2OPT timeBB2OPT.cpp)
target_link_libraries(timeBB2OPT locPIR)

add_executable(timeSum timeSum.cpp)
target_link_libraries(timeSum locPIR)

add_executable(timeBitwiseAND timeBitwiseAND.cpp)
target_link_libraries(timeBitwiseAND locPIR)


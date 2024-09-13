add_subdirectory(partial)

add_executable(testLocVanBB1 testLocVanBB1.cpp)
target_link_libraries(testLocVanBB1 locPIR)

add_executable(testLocOptBB1 testLocOptBB1.cpp)
target_link_libraries(testLocOptBB1 locPIR)

add_executable(testLocVanBB2 testLocVanBB2.cpp)
target_link_libraries(testLocVanBB2 locPIR)

add_executable(testLocVanBB3 testLocVanBB3.cpp)
target_link_libraries(testLocVanBB3 locPIR)

add_executable(testLocOptBB3 testLocOptBB3.cpp)
target_link_libraries(testLocOptBB3 locPIR)

add_executable(testLocOptBB2 testLocOptBB2.cpp)
target_link_libraries(testLocOptBB2 locPIR)


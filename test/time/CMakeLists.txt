add_subdirectory(partial)
add_subdirectory(application)

add_executable(timeLocBB1_M timeLocBB1_M.cpp)
target_link_libraries(timeLocBB1_M locPIR)

add_executable(timeLocBB1_Service timeLocBB1_Service.cpp)
target_link_libraries(timeLocBB1_Service locPIR)



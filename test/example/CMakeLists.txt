add_executable(loadData loadData.cpp)
target_link_libraries(loadData locPIR)

add_executable(encodeData encodeData.cpp)
target_link_libraries(encodeData locPIR)

add_executable(decodeData decodeData.cpp)
target_link_libraries(decodeData locPIR)

add_executable(encDecDB encDecDB.cpp)
target_link_libraries(encDecDB locPIR)

add_executable(convertTextBin convertTextBin.cpp)
target_link_libraries(convertTextBin locPIR)

add_executable(testEnc testEnc.cpp)
target_link_libraries(testEnc locPIR)



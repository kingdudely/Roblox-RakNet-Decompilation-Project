cmake_minimum_required(VERSION 3.20)
project(rbxraknet LANGUAGES CXX)

# std::expected pulls this to C++23 (the one place C++20 falls short). g++ 13+ and
# MSVC 19.36+ both provide <expected>.
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  add_compile_options(/W4 /permissive-)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# The MinGW OpenSSL that ships with this toolchain lives under a non-standard
# prefix; hint find_package there if the caller has not set OPENSSL_ROOT_DIR.
if(NOT DEFINED OPENSSL_ROOT_DIR AND EXISTS "C:/ProgramData/mingw64/mingw64/opt/include/openssl")
  set(OPENSSL_ROOT_DIR "C:/ProgramData/mingw64/mingw64/opt")
endif()
find_package(OpenSSL REQUIRED)

add_library(rbxraknet STATIC
  src/datagram.cpp
  src/aead.cpp
  src/session.cpp
  src/packet_registry.cpp
  src/decoder.cpp
)
target_include_directories(rbxraknet PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
# Only libcrypto is needed (EVP); libssl is not linked.
target_link_libraries(rbxraknet PUBLIC OpenSSL::Crypto)

enable_testing()

add_executable(test_frame tests/test_frame.cpp)
target_link_libraries(test_frame PRIVATE rbxraknet)
target_include_directories(test_frame PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)

add_executable(test_aead tests/test_aead.cpp)
target_link_libraries(test_aead PRIVATE rbxraknet)
target_include_directories(test_aead PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)

add_executable(test_roundtrip tests/test_roundtrip.cpp)
target_link_libraries(test_roundtrip PRIVATE rbxraknet)
target_include_directories(test_roundtrip PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)

add_test(NAME frame COMMAND test_frame)
add_test(NAME aead COMMAND test_aead)
add_test(NAME roundtrip COMMAND test_roundtrip)

# frame and roundtrip need the capture, which isn't in the repo. they exit 2 when
# it's missing, so report that as skipped instead of failed.
set_tests_properties(frame roundtrip PROPERTIES SKIP_RETURN_CODE 2)

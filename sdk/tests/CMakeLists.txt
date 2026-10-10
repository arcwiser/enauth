cmake_minimum_required(VERSION 3.20)
project(enauth_sdk_security_tests LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "The EnAuth C++ SDK security tests require Windows.")
endif()

add_executable(enauth-sdk-security-tests
    security_tests.cpp
    ../enauth.cpp
    ../crypto_win.cpp
    ../hwid.cpp
)
target_include_directories(enauth-sdk-security-tests PRIVATE ..)
target_compile_features(enauth-sdk-security-tests PRIVATE cxx_std_17)
target_compile_definitions(enauth-sdk-security-tests PRIVATE
    ENAUTH_TESTING
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
target_link_libraries(enauth-sdk-security-tests PRIVATE winhttp bcrypt crypt32)

if(MSVC)
    target_compile_options(enauth-sdk-security-tests PRIVATE /W4 /permissive- /GS /sdl)
    target_link_options(enauth-sdk-security-tests PRIVATE /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /guard:cf)
endif()

enable_testing()
add_test(NAME enauth-sdk-security COMMAND enauth-sdk-security-tests)

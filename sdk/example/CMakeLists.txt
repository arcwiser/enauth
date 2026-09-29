cmake_minimum_required(VERSION 3.20)
project(enauth_example LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "The EnAuth C++ SDK currently supports Windows only.")
endif()

add_executable(enauth-example
    main.cpp
    ../enauth.cpp
    ../crypto_win.cpp
    ../hwid.cpp
)

target_include_directories(enauth-example PRIVATE ..)
target_compile_features(enauth-example PRIVATE cxx_std_17)
target_compile_definitions(enauth-example PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    $<$<CONFIG:Release>:ENAUTH_ENABLE_ANTI_DEBUG>
)
target_link_libraries(enauth-example PRIVATE winhttp bcrypt crypt32)

if(MSVC)
    target_compile_options(enauth-example PRIVATE
        /W4 /permissive- /GS /sdl
        $<$<CONFIG:Release>:/O2>
        $<$<CONFIG:Release>:/guard:cf>
    )
    target_link_options(enauth-example PRIVATE
        $<$<CONFIG:Release>:/DYNAMICBASE>
        $<$<CONFIG:Release>:/NXCOMPAT>
        $<$<CONFIG:Release>:/HIGHENTROPYVA>
        $<$<CONFIG:Release>:/guard:cf>
    )
endif()

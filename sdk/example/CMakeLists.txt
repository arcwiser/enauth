cmake_minimum_required(VERSION 3.20)
project(enauth_example LANGUAGES CXX)

option(ENAUTH_ENABLE_ANTI_DEBUG
    "Enable the SDK's local anti-debug integrity checks"
    ON)
option(ENAUTH_ENABLE_SPECTRE
    "Compile with MSVC Spectre mitigations (requires the optional Spectre libraries)"
    ON)
option(ENAUTH_ALLOW_PLACEHOLDERS
    "Allow configuring before the example credentials are replaced"
    OFF)

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/main.cpp" ENAUTH_EXAMPLE_SOURCE)
if(NOT ENAUTH_ALLOW_PLACEHOLDERS AND
   ENAUTH_EXAMPLE_SOURCE MATCHES "REPLACE_WITH_(APPLICATION_ID|RESPONSE_SIGNING_PUBLIC_KEY)")
    message(FATAL_ERROR
        "Replace the EnAuth application ID and response signing public key in main.cpp. "
        "Use -DENAUTH_ALLOW_PLACEHOLDERS=ON only for an intentional non-functional build.")
endif()

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
    $<$<BOOL:${ENAUTH_ENABLE_ANTI_DEBUG}>:ENAUTH_ENABLE_ANTI_DEBUG>
)
target_link_libraries(enauth-example PRIVATE winhttp bcrypt crypt32)

if(MSVC)
    target_compile_options(enauth-example PRIVATE
        /W4 /permissive- /GS /sdl
        $<$<CONFIG:Release>:/O2 /GL>
        $<$<AND:$<CONFIG:Release>,$<BOOL:${ENAUTH_ENABLE_SPECTRE}>>:/Qspectre>
        $<$<CONFIG:Release>:/guard:cf>
    )
    target_link_options(enauth-example PRIVATE
        $<$<CONFIG:Release>:/DYNAMICBASE>
        $<$<CONFIG:Release>:/NXCOMPAT>
        $<$<CONFIG:Release>:/HIGHENTROPYVA>
        $<$<CONFIG:Release>:/guard:cf>
        $<$<CONFIG:Release>:/LTCG>
        $<$<CONFIG:Release>:/CETCOMPAT>
    )
endif()

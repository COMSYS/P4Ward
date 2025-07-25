cmake_minimum_required(VERSION 3.10)
project(authentication_client)

set(CMAKE_C_COMPILER "clang")  # Use Clang compiler

# Add the executable
add_executable(authentication_client "auth.c" "auth-headers.c" "crypto-algorithms/md5.c" "crypto-algorithms/sha1.c" "crypto-algorithms/sha256.c" "SHA3IUF/sha3.c")
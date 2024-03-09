cmake_minimum_required(VERSION 3.0)
project(password-secret)

file(GLOB SOURCES "lib/*.c")

add_library(password-secret SHARED ${SOURCES})
target_include_directories(password-secret PUBLIC "include")
target_compile_options(password-secret PRIVATE -Wall -Wextra -Werror -pedantic -std=c99 -O3 -fPIC -flto)
target_link_options(password-secret PRIVATE -flto)


add_library(password-secret-static STATIC ${SOURCES})
target_include_directories(password-secret-static PUBLIC "include")
target_compile_options(password-secret-static PRIVATE -Wall -Wextra -Werror -pedantic -std=c99 -O3 -fPIC)
set_target_properties(password-secret-static PROPERTIES OUTPUT_NAME password-secret)

add_executable(pwkeygen "tools/pwkeygen.c")
target_link_libraries(pwkeygen password-secret-static)
target_compile_options(pwkeygen PRIVATE -Wall -Wextra -Werror -pedantic -std=c99 -O3 -fPIC -flto)
target_include_directories(pwkeygen PUBLIC "include")
target_link_options(pwkeygen PRIVATE -flto)
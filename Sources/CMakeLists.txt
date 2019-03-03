cmake_minimum_required(VERSION 2.8)

project(calt)

# 查找当前目录下的所有源文件
# 并将名称保存到 DIR_LIB_SRCS 变量
aux_source_directory(. DIR_LIB_SRCS)

find_package(OpenSSL REQUIRED)
if ( NOT OpenSSL_FOUND )
    message (FATAL_ERROR "Packege OpenSSL NOT Found!")
else()
    set(OpenSSL_USE_STATIC_LIBS TRUE)
endif (NOT OpenSSL_FOUND)

# message(STATUS "${OpenSSL_INCLUDE_DIR}, ${OpenSSL_LIBRARY_DIRS}, ${OpenSSL_FOUND}, ${OPENSSL_CRYPTO_LIBRARY}, ${OPENSSL_SSL_LIBRARY}, ${OPENSSL_LIBRARIES}")

# 生成链接库
add_library (Sources_file ${DIR_LIB_SRCS})
target_link_libraries(Sources_file ${OPENSSL_LIBRARIES} )
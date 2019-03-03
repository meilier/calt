cmake_minimum_required(VERSION 2.8)

project(calt)

set(BOOST_MIN_VERSION "1.55")
set(OPENSSL_ROOT_DIR "/usr/include/openssl")

add_definitions(-std=c++1z)

find_package( Boost ${BOOST_MIN_VERSION} REQUIRED system )
if ( NOT Boost_FOUND )
    message (FATAL_ERROR "Packege Boost NOT Found!")
endif (NOT Boost_FOUND)

find_package( Threads )
if ( NOT Threads_FOUND )
    message (FATAL_ERROR "Packege Threads NOT Found!")
endif (NOT Threads_FOUND)

include_directories(
    ${Boost_INCLUDE_DIR} 
    include
    Headers
    Sources
    pca/Headers
)

add_subdirectory(${CMAKE_SOURCE_DIR}/Sources)

link_directories( ${Boost_LIBRARY_DIRS} )

link_directories(${CMAKE_SOURCE_DIR}/pca)


# chat & v2
add_executable( master "Sources/master/main.cpp" )
add_executable( client "Sources/client/main.cpp")

target_link_libraries( master ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} Sources_file -lsoclient)
target_link_libraries( client ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} Sources_file -lsoclient)

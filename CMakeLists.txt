cmake_minimum_required (VERSION 2.6)
project (unitn_crypto_fintech)

add_subdirectory (libsnark)
# TODO: Avoid including libsnark the second time with '.'
include_directories (libsnark/depends/libff libsnark .)

option(
	UCF_DEBUG
	"Enable debug output"
	OFF
)

# TODO: Allow user to select curve, this always uses BN128
add_definitions(
	-DBINARY_OUTPUT -DBN_SUPPORT_SNARK=1 -DCURVE_BN128 -DMONTGOMERY_OUTPUT
	-DUSE_ASM
)

# Multithreading support
add_definitions(-DMULTICORE=8)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fopenmp")

if(UCF_DEBUG)
	add_definitions(-DDEBUG)
endif()

add_executable (
	main_test

	tests/main.cpp
	utils/random.cpp
)
target_link_libraries (
	main_test

	snark
	gtest
)

# - Config file for the Palisade package
# It defines the following variables
#  PALISADE_INCLUDE_DIRS - include directories for Palisade
#  PALISADE_LIBRARIES    - libraries to link against

get_filename_component(PALISADE_CMAKE_DIR "${CMAKE_CURRENT_LIST_FILE}" PATH)

# Our library dependencies (contains definitions for IMPORTED targets)
if(NOT Palisade_BINARY_DIR)
  include("${PALISADE_CMAKE_DIR}/PalisadeTargets.cmake")
endif()

# These are IMPORTED targets created by PalisadeTargets.cmake
set(PALISADE_INCLUDE "/Users/yunhaowang/Desktop/ObliviousMessageRetrieval/include/palisade")
set(PALISADE_LIBDIR "/Users/yunhaowang/Desktop/ObliviousMessageRetrieval/lib")
set(PALISADE_LIBRARIES PALISADEcore;PALISADEpke;PALISADEbinfhe  -Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument)
set(PALISADE_STATIC_LIBRARIES   -Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument)
set(PALISADE_SHARED_LIBRARIES PALISADEcore;PALISADEpke;PALISADEbinfhe  -Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument)
set(BASE_PALISADE_VERSION 1.11.7)


set(OPENMP_INCLUDES "/opt/homebrew/opt/libomp/include" )
set(OPENMP_LIBRARIES "/opt/homebrew/opt/libomp/lib" )

set(PALISADE_CXX_FLAGS " -Wall -Werror -O3  -DPALISADE_VERSION=1.11.7  -Wno-unused-private-field -Wno-shift-op-parentheses -DMATHBACKEND=2 -Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument -Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument -Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument")
set(PALISADE_C_FLAGS " -Wall -Werror -O3  -DPALISADE_VERSION=1.11.7 -DMATHBACKEND=2 -Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument -Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument -Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument")

if( "OFF" STREQUAL "Y" )
	set(PALISADE_CXX_FLAGS "${PALISADE_CXX_FLAGS} -DWITH_NTL" )
	set(PALISADE_C_FLAGS "${PALISADE_C_FLAGS} -DWITH_NTL")
endif()

set (PALISADE_EXE_LINKER_FLAGS "  ")

# CXX info
set(PALISADE_CXX_STANDARD "11")
set(PALISADE_CXX_COMPILER_ID "AppleClang")
set(PALISADE_CXX_COMPILER_VERSION "13.0.0.13000029")

# Build Options
set(PALISADE_STATIC "OFF")
set(PALISADE_SHARED "ON")
set(PALISADE_TCM "OFF")
set(PALISADE_WITH_INTEL_HEXL "OFF")
set(PALISADE_OPENMP "ON")
set(PALISADE_NATIVE_SIZE "64")
set(PALISADE_CKKS_M_FACTOR "1")
set(PALISADE_NATIVEOPT "OFF")

# Math Backend
if("ON")
	set(PALISADE_BACKEND "BE2")
elseif("ON")
	set(PALISADE_BACKEND "BE4")
elseif("OFF")
	set(PALISADE_BACKEND "NTL")
endif()

# Build Details
set(PALISADE_EMSCRIPTEN "")
set(PALISADE_ARCHITECTURE "arm64")
set(PALISADE_BACKEND_FLAGS_BASE "-DMATHBACKEND=2")

# Compile Definitions

if( "ON" )
	set(PALISADE_BINFHE_COMPILE_DEFINITIONS "_compile_defs-NOTFOUND")
	set(PALISADE_CORE_COMPILE_DEFINITIONS "_compile_defs-NOTFOUND")
	set(PALISADE_PKE_COMPILE_DEFINITIONS "_compile_defs-NOTFOUND")
	set(PALISADE_COMPILE_DEFINITIONS
			${PALISADE_BINFHE_COMPILE_DEFINITIONS}
			${PALISADE_CORE_COMPILE_DEFINITIONS}
			${PALISADE_PKE_COMPILE_DEFINITIONS})
endif()

if( "OFF" )
	set(PALISADE_BINFHE_COMPILE_DEFINITIONS_STATIC "")
	set(PALISADE_CORE_COMPILE_DEFINITIONS_STATIC "")
	set(PALISADE_PKE_COMPILE_DEFINITIONS_STATIC "")
	set(PALISADE_COMPILE_DEFINITIONS_STATIC
			${PALISADE_BINFHE_COMPILE_DEFINITIONS_STATIC}
			${PALISADE_CORE_COMPILE_DEFINITIONS_STATIC}
			${PALISADE_PKE_COMPILE_DEFINITIONS_STATIC})
endif()

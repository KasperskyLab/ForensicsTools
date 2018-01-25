cmake_minimum_required(VERSION 3.9)

project(parse_evtx)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR})

IF (MINGW OR WIN32 )
	SET(CMAKE_EXECUTABLE_SUFFIX ".exe")
	SET(CMAKE_SHARED_LIBRARY_SUFFIX ".dll")
	SET(CMAKE_SYSTEM_NAME "Windows")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msse -msse2 -msse3")
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -msse -msse2 -msse3")

	IF ( CMAKE_BUILD_TYPE STREQUAL "Release" )
		SET(OPTIMIZE_FLAGS " ${OPTIMIZE_FLAGS} -O3  -fomit-frame-pointer -D__CRT__NO_INLINE=1")
	ENDIF ( CMAKE_BUILD_TYPE STREQUAL "Release" )

	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OPTIMIZE_FLAGS} -D_POSIX_THREAD_SAFE_FUNCTIONS  -Wno-ignored-attributes -Wno-deprecated-declarations -static-libgcc -static-libstdc++ -std=gnu99 -DWINVER=0x0601 -D_WIN32_WINNT=0x0601")
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OPTIMIZE_FLAGS} -D_POSIX_THREAD_SAFE_FUNCTIONS -Wno-ignored-attributes -Wno-deprecated-declarations -std=gnu++11 -static-libgcc -static-libstdc++ -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 -D__STDC_FORMAT_MACROS ")

ENDIF()

IF ( NOT (MINGW OR WIN32 ) )
	IF ( ( ${CMAKE_C_COMPILER_ID} STREQUAL "GNU" ) ) 
		IF (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 4.5)
			SET(GNU_FLAGS "-Wno-address-of-packed-member -Wno-extended-offsetof  -Wno-ignored-attributes -Wno-unused-result  -pedantic -pedantic-errors -Werror ")
		ENDIF()
	ENDIF()

	IF ( ( ${CMAKE_C_COMPILER_ID} STREQUAL "Clang" ) ) 
		SET(GNU_FLAGS "-Wno-address-of-packed-member -Wno-extended-offsetof  -Wno-ignored-attributes -Wno-unused-result  -pedantic -pedantic-errors -Werror ")
	ENDIF()

	SET(GNU_FLAGS "${GNU_FLAGS} -Wno-unused-function -Wno-deprecated-declarations -Wno-missing-noreturn -Wformat -Wno-variadic-macros -D__STDC_FORMAT_MACROS")

	SET(OPTIMIZE_FLAGS "   -fstack-protector -D_FORTIFY_SOURCE=2 ")
	IF ( CMAKE_BUILD_TYPE STREQUAL "Release" )
			SET(OPTIMIZE_FLAGS " ${OPTIMIZE_FLAGS} -O3 -msse4 -mfpmath=sse -fomit-frame-pointer")
			SET(OPTIMIZE_FLAGS " ${OPTIMIZE_FLAGS} -march=core2  ")
	ENDIF ( CMAKE_BUILD_TYPE STREQUAL "Release" )
	SET( FPIC_FLAG "-fPIC" )
	IF ( ${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
		SET(GNU_FLAGS " ${GNU_FLAGS}  -D_GNU_SOURCE -D_LARGEFILE64_SOURCE -D_DEFAULT_SOURCE ")
	ENDIF ( ${CMAKE_SYSTEM_NAME} STREQUAL "Linux")

	IF ( ${CMAKE_C_COMPILER_ID} STREQUAL "GNU" )
		SET(C_STD "-std=gnu99")
	ELSE ()
		SET(C_STD "-std=c11")
	ENDIF()

	SET(CXX_STD "-std=c++0x")

	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OPTIMIZE_FLAGS}  ${GNU_FLAGS} ${C_STD} -Wimplicit -Wimplicit-function-declaration -Wimplicit-int -Wunused-value  -Wmissing-braces  -Wunused-variable ${FPIC_FLAG}")
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OPTIMIZE_FLAGS} ${GNU_FLAGS}  ${CXX_STD}  -fno-operator-names -Wmissing-braces -Wno-deprecated-register -fPIC")
ENDIF()



SET(ALL_SOURCES forensics)
subdirs( ${ALL_SOURCES} )


#ifndef igmacro_h_included
#define igmacro_h_included

#include <assert.h>
#include <time.h>
#include <stdlib.h>


#if !defined(__FreeBSD__) && !defined(__APPLE__)

#if defined(_WIN32)
#include <windows.h>

#endif

static void	srandomdev(void)	
{
#ifdef __linux__
	srandom(time(NULL));
#else
	srand(time(NULL));
#endif
}

#ifndef __linux__
static long	random(void)	
{
	return rand();
}
#endif

#endif

#ifndef _WIN32
#define STATIC_INLINE static inline
#else
#define STATIC_INLINE
#endif

#define NORETURN __attribute__((noreturn))

#define ZERO_STRUCT(str) memset(&str, 0, sizeof(str))

#define MACRO_FUNC(return_type, name) STATIC_INLINE return_type name
#define PRIVATE_FUNC(return_type, name) static return_type name

#define PUBLIC_FUNC(return_type, name) return_type name

#define PUBLIC_METHOD(type_name, return_type, name, ...) return_type name (const void* pvThis, __VA_ARGS__)
#define PUBLIC_METHOD_NOPARAMS(type_name, return_type, name) return_type name (const void* pvThis)

#define PUBLIC_METHOD_START(type_name)	type_name *This = (type_name*)pvThis; (void)This;

#ifndef NDEBUG
#define DEBUG_PRINTF(...) printf(__VA_ARGS__)
#define ASSERT_INT_EQ(expr, value)	{	int iExpr = expr; assert(iExpr == value); }
#define ASSERT_BOOL(expr)	{	int iExpr = expr; assert(iExpr); }

#else
#define DEBUG_PRINTF(...)
#define ASSERT_INT_EQ(expr, value)	(void)expr
#define ASSERT_BOOL(expr)	(void)expr
#endif

enum
{
	eLOOP_NEXT	= 1,
	eLOOP_STOP	= 2,
	eLOOP_OK	= 3
};

#define LOOP_MACRO_FUNC(name) static inline int name
#define LOOP_NEXT()	return eLOOP_NEXT
#define LOOP_STOP()	return eLOOP_STOP
#define LOOP_OK()	return eLOOP_OK

#define INVOKE_LOOP_MACRO_FUNC(name, ...)	\
			{\
				int iRet = name(__VA_ARGS__);\
				if (iRet == eLOOP_NEXT)\
					continue;\
				else if (iRet == eLOOP_STOP)\
					break;\
			}


#ifdef __cplusplus

#define EXTERN_C_BEGIN extern "C" {
#define EXTERN_C_END }

#else /* #ifdef __cplusplus */

#define EXTERN_C_BEGIN
#define EXTERN_C_END

#endif

#ifndef GCC_PACKED
	#ifndef _MSC_VER
		#define GCC_PACKED __attribute__((__packed__, aligned(1)))
	#else
		#define GCC_PACKED 
	#endif
#endif

#define ARRAY_COUNT(arr) ( sizeof(arr) / sizeof(arr[0]) )

#endif


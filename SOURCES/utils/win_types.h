#ifndef win_types_h_included
#define win_types_h_included

#define _CRT_SECURE_NO_WARNINGS	1
#define _CRT_NONSTDC_NO_DEPRECATE 1


#ifdef _WIN32
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT 
#endif

#include "igmacro.h"

#ifdef _WIN32

#include <windows.h>
#include <sys/types.h>
// #include <stdint.h>
#include <windef.h>

#ifdef _MSC_VER
typedef unsigned __int64 uint64_t;
typedef __int64 int64_t;
typedef signed int int32_t;
typedef DWORD uint32_t;
typedef WORD uint16_t;
typedef BYTE uint8_t;
#else
#include <stdint.h>
#endif

EXTERN_C_BEGIN
extern char	*optarg;		/* argument associated with option */
EXTERN_C_END

typedef int socklen_t;
typedef uint16_t in_port_t;
typedef uint32_t in_addr_t;

#define random rand
#define strncasecmp _strnicmp

// #ifndef GCC_PACKED
// #define GCC_PACKED
// #endif

#ifndef __MINGW64_VERSION_MAJOR
	#define snprintf _snprintf
#endif

#define ioctl ioctlsocket

#define sleep(x) Sleep(x*1000)

EXTERN_C_BEGIN
int getopt(int nargc, char * const nargv[],  const char* ostr);
EXTERN_C_END

#if defined (_MSC_VER)

#define asm __asm
#define strdup _strdup
/*#define open _open
#define read _read
#define close _close*/
#define isnan _isnan

#include <math.h>
#include <float.h>

static int isinf(double value)
{
	return !isnan(value) && isnan(value - value);
}

static int signbit(double value)
{
	return ( _copysign(1.0, value) < 0.0 ? 1 : 0 );
}

#endif

#else

#include <sys/types.h>
#include <stdint.h>

typedef uint64_t ULONGLONG;
typedef uint32_t DWORD;
typedef uint16_t WORD;
typedef uint8_t  BYTE;

#define O_BINARY 0
// #define GCC_PACKED __attribute__((__packed__))
#define closesocket close

#define MAX_PATH 260

#endif

#ifdef _WIN32
/*-
 * Copyright (c) 2009 David Schultz <das@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __MINGW64_VERSION_MAJOR
#include <string.h>

static size_t
strnlen(const char *s, size_t maxlen)
{
	size_t len;

	for (len = 0; len < maxlen; len++, s++) {
		if (!*s)
			break;
	}
	return (len);
}

#endif

#endif

#endif


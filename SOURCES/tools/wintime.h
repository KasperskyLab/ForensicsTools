/*
 *       Filename:  wintime.h
 *         Author:  Igor Soumenkov , igosha@kaspersky.com, Kaspersky Lab
 *    Description:  Utility for converting windows timestamps in unix timestamps
 */

#ifndef wintime_h_included
#define wintime_h_included

#include <stdint.h>
#include <inttypes.h>

// SystemTimeToVariantTime

static uint64_t UnixTimeFromFileTime(uint64_t fileTime)
{
	return ( fileTime - 11644473600000ULL * 10000) / 10000000;
}

#endif


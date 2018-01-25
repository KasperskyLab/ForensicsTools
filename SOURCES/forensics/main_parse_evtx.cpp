/*
 * =====================================================================================
 *       Filename:  parse_evtx.cpp
 *    Description:  Parse EVTX format files
 *        Created:  09.01.2018 16:59:43
 *         Author:  Igor Soumenkov (igosha), igosha@kaspersky.com
 * =====================================================================================
 */
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>
#include <utils/win_types.h>
#include "eventlist.h"

// #define PRINT_TAGS

#include <tools/wintime.h>

#pragma pack(push, 1)

#define EVTX_HEADER_MAGIC	"ElfFile"

typedef struct
{
	char		magic[8];
	uint64_t	numberOfChunksAllocated;
	uint64_t	numberOfChunksUsed;
	uint64_t	checksum;
	uint32_t	flags;
	uint32_t	version;
	uint64_t	fileSize;
	uint8_t		reserved[0x1000 - 0x30];
}
EvtxHeader;

#define EVTX_CHUNK_HEADER_MAGIC	"ElfChnk"

typedef struct
{
	char		magic[8];
	uint64_t	firstRecordNumber;
	uint64_t	lastRecordNumber;
	uint64_t	firstRecordNumber2;
	uint64_t	lastRecordNumber2;
	uint32_t	chunkHeaderSize;
	uint8_t		reserved[0x80 - 0x2C];
	uint8_t		reserved2[0x200 - 0x80];
}
EvtxChunkHeader;

#define EVTX_CHUNK_SIZE		0x10000

typedef struct
{
	uint32_t	magic;
	uint32_t	size;
	uint64_t	number;
	uint64_t	timestamp;
}
EvtxRecordHeader;


typedef struct
{
	uint32_t	d1;
	uint16_t	w1;
	uint16_t	w2;
	uint8_t		b1[8];
}
EvtxGUID;
#pragma pack(pop)

typedef enum
{
	StateNormal		=	1,
	StateInAttribute	=	2,
}
XmlParseState;

typedef struct sParseContext
{
	sParseContext*	chunkContext;
	const uint8_t*	data;
	size_t		dataLen;
	size_t		offset;
	size_t		offsetFromChunkStart;
	XmlParseState	state;
	unsigned int	currentTemplateIdx;
	char		cachedValue[256];
}
ParseContext;

static bool	ParseBinXml(ParseContext* ctx, size_t inFileOffset);

static bool	HaveEnoughData(ParseContext* ctx, size_t numBytes)
{
	return ( ctx->offset + numBytes <= ctx->dataLen );
}

static void	SkipBytes(ParseContext* ctx, size_t numBytes)
{
	ctx->offset += numBytes;
}

template<class c>
static bool	ReadData(ParseContext* ctx, c* result, size_t count = 1)
{
	if ( !HaveEnoughData(ctx, sizeof(*result) * count) )
		return false;
	for (size_t idx = 0; idx < count; idx++)
	{
		result[idx] = *(c*)(ctx->data + ctx->offset);
		ctx->offset += sizeof(*result);
	}
	return true;
}

#define MAX_IDS			256
#define MAX_NUM_ARGS		256
#define INVALID_TEMPLATE_IDX	((unsigned int)-1)

typedef struct sTemplateArgPair
{
	sTemplateArgPair*	next;
	char*			key;
	uint16_t		type;
	uint16_t		argIdx;
}
TemplateArgPair;

typedef struct	sTemplateFixedPair
{
	sTemplateFixedPair*	next;
	char*			key;
	char*			value;
}
TemplateFixedPair;

typedef struct
{
	uint32_t		shortID;
	TemplateFixedPair	fixedRoot;
	TemplateArgPair		argsRoot;
}
TemplateDescription;

template <class c>
static void InitRoot(c* root)
{
	root->next = NULL;
}

template<class c>
static c* AddPair(c* root)
{
	c*	item	=	(c*)malloc(sizeof(c));
	if ( item != NULL )
	{
		item->next = root->next;
		root->next = item;
	}
	return item;
}

static void	FreePair(TemplateFixedPair* item)
{
	free(item->key);
	free(item->value);
	free(item);
}

static void	FreePair(TemplateArgPair* item)
{
	free(item->key);
	free(item);
}

template <class c>
static void ResetRoot(c* root)
{
	c*	nextItem	=	NULL;

	for (c* ptr = root->next; ptr != NULL; ptr = nextItem)
	{
		nextItem = ptr->next;
		FreePair(ptr);
	}

	root->next = NULL;
}

static void InitTemplateDescription(TemplateDescription* item)
{
	InitRoot(&item->fixedRoot);
	InitRoot(&item->argsRoot);
	item->shortID = 0;
}

static void ResetTemplateDescription(TemplateDescription* item)
{
	ResetRoot(&item->fixedRoot);
	ResetRoot(&item->argsRoot);
	item->shortID = 0;
}

static uint32_t			knownIDs[MAX_IDS] 	=	{ 0 };
static TemplateDescription	templates[MAX_IDS];
static unsigned int		numIDs			=	0;

#define MAX_NAME_STACK_DEPTH	20
#define INVALID_STACK_DEPTH 	((ssize_t)-1)

typedef struct
{
	char	name[256];
}
NameStackElement;


#define countof(arr) ( sizeof(arr) / sizeof(*arr) )

static void	InitTemplates(void)
{
	for (size_t idx = 0; idx < countof(templates); idx++)
		InitTemplateDescription(&templates[idx]);
}

static ssize_t		nameStackPtr	=	INVALID_STACK_DEPTH;
static NameStackElement	nameStack[MAX_NAME_STACK_DEPTH];

const char**	eventDescriptionHashTable	=	NULL;
const char*	logonTypes[]	= { NULL, NULL, "Interactive", "Network", "Batch", "Service", NULL, "Unlock", "NetworkCleartext", "NewCredentials", "RemoteInteractive", "CachedInteractive"};

static void	RegisterFixedPair(unsigned int templateIdx, const char* key, const char* value)
{
	TemplateFixedPair*	newPair	=	AddPair(&templates[templateIdx].fixedRoot);
	if ( newPair == NULL )
		return;
	newPair->key = strdup(key);
	newPair->value = strdup(value);
}


static void	RegisterArgPair(unsigned int templateIdx, const char* key, uint16_t type, uint16_t argIdx)
{
	TemplateArgPair*	newPair	=	AddPair(&templates[templateIdx].argsRoot);
	if ( newPair == NULL )
		return;
	// broken record 3420028194 (security.evtx)
	newPair->key = strdup(key == NULL ? "" : key);
	newPair->type = type;
	newPair->argIdx = argIdx;
}


static void	PushName(const char* name)
{
	if ( nameStackPtr >= MAX_NAME_STACK_DEPTH )
		return;
	nameStackPtr++;
	strncpy(nameStack[nameStackPtr].name, name, sizeof(nameStack[nameStackPtr].name));
	nameStack[nameStackPtr].name[ sizeof(nameStack[nameStackPtr].name) - 1 ]  = 0;
}

static void	PopName(void)
{
	if ( nameStackPtr > INVALID_STACK_DEPTH )
		nameStackPtr--;
}

static const char*	GetName(void)
{
	if ( nameStackPtr <= INVALID_STACK_DEPTH )
		return NULL;
	return nameStack[nameStackPtr].name;
}


static const char*	GetUpperName(void)
{
	if ( nameStackPtr <= INVALID_STACK_DEPTH )
		return NULL;
	if ( nameStackPtr < 1 )
		return NULL;

	return nameStack[nameStackPtr - 1].name;
}

static bool	IsKnownID(uint32_t	id, unsigned int* templateIdx)
{
	for (unsigned int idx = 0; idx < numIDs; idx++)
	{
		if ( knownIDs[idx] == id )
		{
			if ( templateIdx != NULL )
				*templateIdx = idx;
			return true;
		}
	}
	return false;
}

static bool	RegisterID(uint32_t	id, unsigned int* templateIdx)
{
	if ( numIDs >= MAX_IDS )
		return false;
	knownIDs[numIDs] = id;
	templates[numIDs].shortID = id;
	*templateIdx = numIDs;
	numIDs++;
	return true;
}

static void	ResetTemplates(void)
{
	for (size_t idx = 0; idx < numIDs; idx++)
		ResetTemplateDescription(&templates[idx]);

	numIDs = 0;
}

static void	SetState(ParseContext* ctx, XmlParseState newState)
{
	if ( newState == ctx->state )
		return;

	if ( ctx->state == StateInAttribute )
		PopName();

	ctx->state = newState;
}

static void	UTF16ToUTF8(uint16_t w, char* buffer, size_t* bufferUsed, size_t bufferSize)
{
	uint32_t	charLength	=	1;
	uint8_t		msb		=	0;
	uint8_t		mask		=	0;

	if ( w > 0x7F )
	{
		charLength++;
		msb |= 0x80 + 0x40;
		mask = 0xFF;
	}
	if ( w > 0x7FF )
	{
		charLength++;
		msb |= 0x20;
		mask = 0x1F;
	}
	if ( w > 0xFFFF )
	{
		charLength++;
		msb |= 0x10;
		mask = 0x0F;
	}

	if ( *bufferUsed + charLength >= bufferSize )
		return;	/*  no buffer overruns */

	if ( charLength == 1 )
	{
		buffer[*bufferUsed] = w;
		(*bufferUsed)++;
		return;
	}

	// printf("\n%04X -> ", (uint16_t)w);

	for (uint32_t charIndex = charLength - 1; charIndex > 0; charIndex--)
	{
		buffer[*bufferUsed + charIndex] = 0x80 | ( w & 0x3F );
		// printf(" ... [%X] %02X ", charIndex, buffer[*bufferUsed + charIndex]);
		w >>= 6;
	}

	buffer[*bufferUsed] = msb | ( w & mask );

#if 0
	for (uint32_t idx = 0; idx < charLength; idx++)
		printf("%02X ", (uint8_t)buffer[*bufferUsed + idx]);
	printf("\n");
#endif

	*bufferUsed += charLength;
}

static bool	ReadPrefixedUnicodeString(ParseContext* ctx, char* nameBuffer, size_t nameBufferSize, bool isNullTerminated)
{
	uint16_t	nameCharCnt;
	size_t		nameBufferUsed	=	0;
	size_t		idx		=	0;

	if ( !ReadData(ctx, &nameCharCnt) )
		return false;

	// TODO : convert UTF-16 to UTF-8
	for (idx = 0; idx < nameCharCnt && idx*2 < ( nameBufferSize - 1 ) ; idx ++)
	{
		uint16_t	w;

		if ( !ReadData(ctx, &w) )
			return false;
		UTF16ToUTF8(w, nameBuffer, &nameBufferUsed, nameBufferSize);
	}

	if ( nameBufferUsed >= nameBufferSize )
		nameBufferUsed = nameBufferSize - 1;
	nameBuffer[nameBufferUsed] = 0;

	SkipBytes(ctx, (nameCharCnt - idx + ( isNullTerminated ? 1 : 0 ))*2);

	return true;
}

static bool	ReadName(ParseContext* ctx, char* nameBuffer, size_t nameBufferSize)
{
	uint16_t	nameHash;
	uint32_t	chunkOffset;
	uint32_t	d;
	ParseContext	temporaryCtx(*ctx->chunkContext);
	ParseContext*	ctxPtr		=	ctx;

	if ( nameBufferSize < 2 )
		return false;
	nameBuffer[0] = 0;
	if ( !ReadData(ctx, &chunkOffset) )
		return false;
	if ( ctx->offset + ctx->offsetFromChunkStart != chunkOffset )
	{
		// printf("!!!!!! %08X %08X\n", chunkOffset, (uint32_t)(ctx->offset + ctx->offsetFromChunkStart));
		ctxPtr = &temporaryCtx;
		ctxPtr->offset = chunkOffset;
	}

	if ( !ReadData(ctxPtr, &d) )
		return false;
	if ( !ReadData(ctxPtr, &nameHash) )
		return false;
	if ( !ReadPrefixedUnicodeString(ctxPtr, nameBuffer, nameBufferSize, true) )
		return false;

	return true;
}

static const char*	GetProperKeyName(ParseContext* ctx)
{
	const char*	key;
	const char*	upperName;

	key = GetName();

	// printf("Key: %s Upper: %s\n", key, GetUpperName());

	upperName = GetUpperName();

	if ( ( upperName != NULL ) &&
		!strcmp(key, "Data") &&
		!strcmp(upperName, "EventData") &&
		ctx->cachedValue[0] != 0 )
	{
		key = ctx->cachedValue;
	}

	return key;
}

static bool	ParseValueText(ParseContext* ctx)
{
	uint8_t		stringType;
	char		valueBuffer[256];
	const char*	upperName;
	const char*	key;

	if ( !ReadData(ctx, &stringType) )
		return false;
	if ( !ReadPrefixedUnicodeString(ctx, valueBuffer, sizeof(valueBuffer), false) )
		return false;
	// printf("******* %s=%s", GetName(), valueBuffer);

	key = GetProperKeyName(ctx);
	upperName = GetUpperName();

	if ( ( key != NULL ) &&
		( ( upperName == NULL ) ||
		strcmp(key, "Name") ||
		strcmp(GetUpperName(), "Data") ) )
	{
		RegisterFixedPair(ctx->currentTemplateIdx, key, valueBuffer);
	}

	SetState(ctx, StateNormal);

	strncpy(ctx->cachedValue, valueBuffer, sizeof(valueBuffer));
	ctx->cachedValue[sizeof(ctx->cachedValue)-1] = 0;

	return true;
}

static bool	ParseAttributes(ParseContext* ctx)
{
	char		nameBuffer[256];

	if ( !ReadName(ctx, nameBuffer, sizeof(nameBuffer)) )
		return false;
	// printf(" %s", nameBuffer);

	PushName(nameBuffer);
	SetState(ctx, StateInAttribute);

	return true;
}

static bool	ParseOpenStartElement(ParseContext* ctx, bool hasAttributes)
{
	uint8_t		b;
	uint16_t	w;
	uint32_t	elementLength;
	uint32_t	attributeListLength	=	0;
	char		nameBuffer[256];

	if ( !ReadData(ctx, &w) )
		return false;
	if ( !ReadData(ctx, &elementLength) )
		return false;
	if ( !ReadName(ctx, nameBuffer, sizeof(nameBuffer)) )
		return false;
	if ( hasAttributes )
	{
		if ( !ReadData(ctx, &attributeListLength) )
			return false;
	}
#ifdef PRINT_TAGS
	printf("<%s [%08X] ", nameBuffer, attributeListLength);
	fflush(stdout);
#endif

	PushName(nameBuffer);

	return true;
}

static bool	ParseCloseStartElement(ParseContext* ctx)
{
	SetState(ctx, StateNormal);
#ifdef PRINT_TAGS
	printf(">");
	fflush(stdout);
#endif
	return true;
}

static bool	ParseCloseElement(ParseContext* ctx)
{
	SetState(ctx, StateNormal);
	PopName();

#ifdef PRINT_TAGS
	printf("</>");
	fflush(stdout);
#endif
	return true;
}

static void	DumpTemplateContents(ParseContext* ctx, unsigned int templateIdx)
{
	return ;

	printf("********************* TEMPLATE BEGIN ************************\n");
	printf("Short ID: %08X\n", templates[templateIdx].shortID);
	for ( TemplateFixedPair* ptr = templates[templateIdx].fixedRoot.next; ptr != NULL; ptr = ptr->next )
	{
		printf(" %s = %s\n", ptr->key, ptr->value);
	}
	for ( TemplateArgPair* ptr = templates[templateIdx].argsRoot.next; ptr != NULL; ptr = ptr->next )
	{
		printf(" %s { arg %04X type %04X } \n", ptr->key, ptr->argIdx, ptr->type);
	}
	printf("********************* TEMPLATE END   ************************\n");
}

static bool	ParseTemplateInstance(ParseContext* ctx)
{
	uint8_t		b;
	uint32_t	numArguments;
	uint32_t	shortID;
	uint32_t	tempResLen;
	uint32_t	totalArgLen		=	0;

	if ( !ReadData(ctx, &b) )
		return false;
	if ( b != 0x01 )
		return false;
	if ( !ReadData(ctx, &shortID) )
		return false;
	if ( !ReadData(ctx, &tempResLen) )
		return false;
	if ( !ReadData(ctx, &numArguments) )
		return false;

	// printf("OK, template %08X\n", shortID);

	if ( !IsKnownID(shortID, &ctx->currentTemplateIdx) )
	//if ( numArguments == 0x00000000 )
	{
		uint8_t		longID[16];
		uint32_t	templateBodyLen;
		ParseContext	templateCtx;

		/* template definition follows */
		if ( !ReadData(ctx, &longID[0], sizeof(longID)) )
			return false;
		if ( !ReadData(ctx, &templateBodyLen) )
			return false;
		// printf("Template body, len %08X\n", templateBodyLen);

		templateCtx.data = ctx->data + ctx->offset;
		templateCtx.dataLen = templateBodyLen; /* mm_min ... */
		templateCtx.offset = 0;
		templateCtx.chunkContext = ctx;
		templateCtx.offsetFromChunkStart = ctx->offset + ctx->offsetFromChunkStart;
		templateCtx.cachedValue[0] = 0;

		RegisterID(shortID, &templateCtx.currentTemplateIdx);

		if ( !ParseBinXml(&templateCtx, 0) )
			return false;

		SkipBytes(ctx, templateBodyLen);

		if ( !ReadData(ctx, &numArguments) )
			return false;

		ctx->currentTemplateIdx = templateCtx.currentTemplateIdx;

		DumpTemplateContents(ctx, ctx->currentTemplateIdx);
	}

	// printf("Number of arguments: %08X\n", numArguments);

	for ( TemplateFixedPair* ptr = templates[ctx->currentTemplateIdx].fixedRoot.next; ptr != NULL; ptr = ptr->next )
	{
		bool	alreadyPrinted	=	false;

		if ( !strcmp(ptr->key, "EventID") )
		{
			uint16_t	eventID	=	strtoul(ptr->value, NULL, 10);
			if ( ( eventID != 0 ) && ( eventDescriptionHashTable[eventID] != NULL ) )
			{
				printf("'%s':%u (%s), ", ptr->key, eventID, eventDescriptionHashTable[eventID]);
				alreadyPrinted = true;
			}
		}

		if ( !alreadyPrinted )
			printf("'%s':'%s', ", ptr->key, ptr->value);
	}

	// printf("\n");

	size_t		argumentMapCount	=	numArguments * 2;
	uint16_t*	argumentMap		=	(uint16_t*)malloc(sizeof(*argumentMap)*argumentMapCount);

	if ( !ReadData(ctx, argumentMap, argumentMapCount) )
	{
		printf("Failed to read the arguments\n");
		free(argumentMap);
		return false;
	}

	for (uint64_t argumentIdx = 0; argumentIdx < numArguments; argumentIdx++)
	{
		uint16_t		argLen		=	argumentMap[argumentIdx*2];
		uint16_t		argType		=	argumentMap[argumentIdx*2 + 1];
		TemplateArgPair*	argPair		=	NULL;

	//	printf("\n %08X : [%02X %02X %02X] Arg %" PRIX64" type %08X len %08X\n",
	//			(uint32_t)ctx->offset, ctx->data[ctx->offset], ctx->data[ctx->offset+1], ctx->data[ctx->offset+2],
	//			argumentIdx, argType, argLen);
		for ( TemplateArgPair* ptr = templates[ctx->currentTemplateIdx].argsRoot.next; ptr != NULL; ptr = ptr->next )
		{
			if ( ptr->argIdx == argumentIdx )
			{
				argPair = ptr;
				break;
			}
		}

		if ( argPair == NULL )
		{
			// printf("Argument not found\n");
			SkipBytes(ctx, argLen);
		}
		else
		{
			uint8_t		v_b;
			uint16_t	v_w;
			uint32_t	v_d;
			uint64_t	v_q;
			time_t		unixTimestamp;
			struct tm	localtm;
			struct tm*	t;
			uint8_t		sid[2+6];
			EvtxGUID	guid;
			char*		stringBuffer;
			size_t		stringNumUsed	=	0;
			size_t		stringSize	=	0;

			switch(argType)
			{
			//// case 0x00:	/*  void */
				//break;
			case 0x01:	/*  String */
				stringSize = argLen*2+2;
				stringBuffer = (char*)malloc(stringSize);
				if ( stringBuffer == NULL )
					return false;
				for (size_t idx = 0; idx < argLen/2; idx++)
				{
					if ( !ReadData(ctx, &v_w) )
						return false;
					UTF16ToUTF8(v_w, stringBuffer, &stringNumUsed, stringSize);
				}
				if ( stringNumUsed >= stringSize )
					stringNumUsed = stringSize - 1;
				stringBuffer[stringNumUsed] = 0;
				printf("'%s':'%s', ", argPair->key, stringBuffer);
				free(stringBuffer);
				break;
			case 0x04:	/*  uint8_t */
				if ( !ReadData(ctx, &v_b) )
					return false;
				printf("'%s':%02u, ", argPair->key, v_b);
				break;
			case 0x06:	/*  uint16_t */
				if ( !ReadData(ctx, &v_w) )
					return false;

				if ( !strcmp(argPair->key, "EventID") && ( eventDescriptionHashTable[v_w] != NULL ))
					printf("'%s':%04u (%s), ", argPair->key, v_w, eventDescriptionHashTable[v_w]);
				else
					printf("'%s':%04u, ", argPair->key, v_w);
				break;
			case 0x08:	/*  uint32_t */
				if ( !ReadData(ctx, &v_d) )
					return false;

				if ( !strcmp(argPair->key, "LogonType") && ( v_d <= 11 ) && ( logonTypes[v_d] != NULL ))
					printf("'%s':%08u (%s), ", argPair->key, v_d, logonTypes[v_d]);
				else
					printf("'%s':%08u, ", argPair->key, v_d);
				break;
			case 0x0A:	/*  uint64_t */
				if ( !ReadData(ctx, &v_q) )
					return false;
				printf("'%s':%016" PRIu64 ", ", argPair->key, v_q);
				break;
			case 0x0E:	/*  binary */
				printf("'%s':", argPair->key);
				for (size_t idx = 0; idx < argLen; idx++)
				{
					if ( !ReadData(ctx, &v_b) )
						return false;
					printf("%02X", v_b);
				}
				printf(", ");
				break;
			case 0x0F:	/* GUID */
				if ( !ReadData(ctx, &guid) )
					return false;
				printf("'%s':%08X-%02X-%02X-%02X%02X%02X%02X%02X%02X%02X%02X, ", argPair->key,
						guid.d1, guid.w1, guid.w2,
						guid.b1[0], guid.b1[1], guid.b1[2], guid.b1[3],
						guid.b1[4], guid.b1[5], guid.b1[6], guid.b1[7]);
				break;
			case 0x14:	/*  HexInt32 */
				if ( !ReadData(ctx, &v_d) )
					return false;
				printf("'%s':%08" PRIX32", ", argPair->key, v_d);
				break;

			case 0x15:	/*  HexInt64 */
				if ( !ReadData(ctx, &v_q) )
					return false;
				printf("'%s':%016" PRIX64 ", ", argPair->key, v_q);
				break;
			case 0x11:	/*  FileTime */
				if ( !ReadData(ctx, &v_q) )
					return false;
				unixTimestamp = UnixTimeFromFileTime(v_q);
				t = gmtime_r(&unixTimestamp, &localtm);
				if ( t == NULL )
					printf("'%s':%016" PRIX64 ", ", argPair->key, v_q);
				else
					printf("'%s':%04u.%02u.%02u-%02u:%02u:%02u, ",
							argPair->key,
							t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
				break;
			case 0x13:	/*  SID */
				if ( argLen < sizeof(sid) )
					return false;
				if ( !ReadData(ctx, sid, sizeof(sid)) )
					return false;
				v_q = 0;
				for (size_t idx = 0; idx < 6; idx++)
				{
					v_q <<= 8;
					v_q |= sid[2+idx];
				}
				printf("'%s':S-%u-%" PRIu64 "", argPair->key, sid[0], v_q);
				for (size_t idx = sizeof(sid); idx + 4 <= argLen; idx += 4)
				{
					if ( !ReadData(ctx, &v_d) )
						return false;
					printf("-%u", v_d);
				}
				printf(", ");
				break;
			case 0x21:	/*  BinXml */
				{
					ParseContext	temporaryCtx(*ctx);
					temporaryCtx.dataLen = temporaryCtx.offset + argLen;
					if ( !ParseBinXml(&temporaryCtx, 0) )
						;//return false;
					// printf("=====<<<<< %08X\n", argLen);
					SkipBytes(ctx, argLen);
				}
				break;
			default:
				if ( argType != 0x00 )
					printf("'%s':'...//%04X[%04X]', ", argPair->key, argPair->type, argLen);
				SkipBytes(ctx, argLen);
				break;
			}
		}

		totalArgLen += argLen;
	}

	free(argumentMap);

	return true;
}


static bool	ParseOptionalSubstitution(ParseContext* ctx)
{
	uint16_t	substitutionID;
	uint8_t		valueType;

	if ( !ReadData(ctx, &substitutionID) )
		return false;
	if ( !ReadData(ctx, &valueType) )
		return false;
	if ( valueType == 0x00 )
	{
		if ( !ReadData(ctx, &valueType) )
			return false;
	}

	// printf("******* %s=<<param %X/type %X>> ", GetName(), substitutionID, valueType);
	RegisterArgPair(ctx->currentTemplateIdx, GetProperKeyName(ctx), valueType, substitutionID);
	SetState(ctx, StateNormal);

	return true;
}

static bool	ParseBinXmlPre(const uint8_t* data, size_t dataLen, size_t inFileOffset, size_t inChunkOffset)
{
	ParseContext	ctx;

	ctx.data = data;
	ctx.dataLen = dataLen;
	ctx.offset = inChunkOffset;
	ctx.currentTemplateIdx = INVALID_TEMPLATE_IDX;
	ctx.chunkContext = &ctx;
	ctx.offsetFromChunkStart = 0;
	ctx.cachedValue[0] = 0;

	return ParseBinXml(&ctx, inFileOffset);
}

static bool	ParseBinXml(ParseContext* ctx, size_t inFileOffset)
{
	bool	result	=	true;

	ctx->state = StateNormal;

	// printf("ParseBinXml(%08X, %08X)\n", (uint32_t)ctx->offset, (uint32_t)ctx->dataLen);

	while ( result && ( ctx->offset < ctx->dataLen ) )
	{
		uint8_t	tag	=	ctx->data[ctx->offset++];

		// printf("%08zX: %02X ", inFileOffset + ctx->offset, tag);
		// fflush(stdout);
		// printf("%08zX: %02X %02X %02X", inFileOffset + ctx->offset, tag, ctx->data[ctx->offset], ctx->data[ctx->offset+1]);

		switch(tag)
		{
		case 0x00:	/*  EOF */
			ctx->offset = ctx->dataLen;
			break;
		case 0x01:	/*  OpenStartElementToken */
			result = ParseOpenStartElement(ctx, false);
			break;
		case 0x41:
			result = ParseOpenStartElement(ctx, true);
			break;
		case 0x02:	/* CloseStartElementToken */
			result = ParseCloseStartElement(ctx);
			break;
		case 0x03:	/*  CloseEmptyElementToken */
		case 0x04:	/*  CloseElementToken */
			result = ParseCloseElement(ctx);
			break;
		case 0x05:	/*  ValueTextToken */
		case 0x45:
			result = ParseValueText(ctx);
			break;
		case 0x06:	/*  AttributeToken */
		case 0x46:
			result = ParseAttributes(ctx);
			break;
		case 0x07:	/* CDATASectionToken */
		case 0x47:
			break;
		case 0x08:	/* CharRefToken */
		case 0x48:
			break;
		case 0x09:	/*  EntityRefToken */
		case 0x49:
			break;
		case 0x0A:	/*  PITargetToken */
			break;
		case 0x0B:	/*  PIDataToken */
			break;
		case 0x0C: /*  TemplateInstanceToken */
			result = ParseTemplateInstance(ctx);
			break;
		case 0x0D:	/*  NormalSubstitutionToken */
		case 0x0E:	/*  OptionalSubstitutionToken */
			result = ParseOptionalSubstitution(ctx);
			break;
		case 0x0F: /*  FragmentHeaderToken */
			SkipBytes(ctx, 3);
			break;

		default:
			result = false;
			break;
		}

		// printf("\n");
	}

	return result;
}

static bool	ParseEVTXInt(int f)
{
	EvtxHeader	header;
	uint64_t	off	=	0;
	uint8_t*	chunk;
	bool		result	=	true;

	if ( read(f, &header, sizeof(header)) != sizeof(header) )
		return false;
	if ( header.version != 0x00030001)
		return false;

#ifdef PRINT_TAGS
	printf("Number of chunks: %" PRIu64 " %" PRIu64 " header sz %zu\n", header.numberOfChunksAllocated, header.numberOfChunksUsed, sizeof(header));
#endif

	off = sizeof(header);

	chunk = (uint8_t*)malloc(EVTX_CHUNK_SIZE);
	if ( chunk == NULL )
		return false;

	while ( result )
	{
		EvtxChunkHeader*	chunkHeader	=	(EvtxChunkHeader*)chunk;
		uint64_t		inRecordOff;

		ResetTemplates();

		if ( lseek(f, off, SEEK_SET) != off )
		{
			result = false;
			break;
		}
		if ( read(f, chunk, EVTX_CHUNK_SIZE) != EVTX_CHUNK_SIZE )
			break;

		if ( memcmp(chunkHeader->magic, EVTX_CHUNK_HEADER_MAGIC, sizeof(EVTX_CHUNK_HEADER_MAGIC)) )
		{
			// result = false;
			break;
		}

		// printf("Chunk %" PRIu64 " .. %" PRIu64 "\n", chunkHeader->firstRecordNumber, chunkHeader->lastRecordNumber);

		inRecordOff = sizeof(*chunkHeader);

		while ( result )
		{
			EvtxRecordHeader*	recordHeader	=	(EvtxRecordHeader*)(chunk + inRecordOff);
			time_t			unixTimestamp;
			struct tm		localtm;
			struct tm*		t;

			if ( inRecordOff + sizeof(*recordHeader) > EVTX_CHUNK_SIZE )
				break;

			if ( recordHeader->magic != 0x00002a2a )
			{
#ifdef PRINT_TAGS
				printf("Record header mismatch at %08X\n", (uint32_t)(off + inRecordOff));
#endif
				break;
			}

			unixTimestamp = UnixTimeFromFileTime(recordHeader->timestamp);
			t = gmtime_r(&unixTimestamp, &localtm);
			if ( t == NULL )
			{
				result = false;
				break;
			}

			// printf("%" PRIX64 ": Record %" PRIu64 " %04u.%02u.%02u-%02u:%02u:%02u ", inRecordOff, recordHeader->number, t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
			printf("Record #%" PRIu64 " %04u.%02u.%02u-%02u:%02u:%02u ", recordHeader->number, t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

			if ( !ParseBinXmlPre(chunk,
						EVTX_CHUNK_SIZE,
						off + inRecordOff + sizeof(*recordHeader),
						inRecordOff + sizeof(*recordHeader) ) )
			{
				if ( recordHeader->number >= chunkHeader->firstRecordNumber &&
						recordHeader->number <= chunkHeader->lastRecordNumber )
				{
					result = false;
				}
				break;
			}
			printf("\n");

			inRecordOff += recordHeader->size;
		}

		off += EVTX_CHUNK_SIZE;

		if ( inRecordOff > off )
		{
			result = false;
			break;
		}
	}

	return result;
}

static bool	ParseEVTX(const char* fileName)
{
	bool	result;
	int	f	=	open(fileName, O_RDONLY|O_BINARY);
	if ( f < 0 )
		return false;

	result = ParseEVTXInt(f);
	if ( !result )
		printf("Failed on %s\n", fileName);
	close(f);
	return result;
}

static void InitEventDescriptions(void)
{
	for (size_t idx = 0; idx < sizeof(eventDescriptions)/sizeof(eventDescriptions[0]); idx++)
	{
		char*		nptr	=	NULL;
		uint16_t	eventID	=	strtoul(eventDescriptions[idx], &nptr, 10);
		if ( ( nptr == NULL ) || ( eventID == 0 ) )
			continue;
		while (*nptr != ')' && *nptr != 0)
			nptr++;
		while (*nptr == ' ' || *nptr == ')')
			nptr++;
		// printf("%04u - %s\n", eventID, nptr);
		eventDescriptionHashTable[eventID] = nptr;
	}
}

#ifdef _WIN32

#ifndef __MINGW64_VERSION_MAJOR

extern "C"
{
BOOL (WINAPI *Wow64DisableWow64FsRedirection)(
  PVOID *OldValue
)	= (BOOL(WINAPI*)(PVOID*))GetProcAddress(GetModuleHandle(L"KERNEL32.DLL"), "Wow64DisableWow64FsRedirection");

BOOL (WINAPI * Wow64RevertWow64FsRedirection)(
  PVOID OldValue )
	= (BOOL(WINAPI*)(PVOID))GetProcAddress(GetModuleHandle(L"KERNEL32.DLL"), "Wow64RevertWow64FsRedirection");
}

#endif

#endif


int main(int argc, char* argv[])
{
	void*	redir;

#ifdef _WIN32
	if (Wow64DisableWow64FsRedirection != NULL )
		Wow64DisableWow64FsRedirection(&redir);
#endif

	eventDescriptionHashTable = (const char**)malloc(sizeof(const char*) * 65536 );
	memset(eventDescriptionHashTable, 0, sizeof(const char*)*65536);
	InitTemplates();
	InitEventDescriptions();
	for (int idx = 1; idx < argc; idx++)
		ParseEVTX(argv[idx]);
	free(eventDescriptionHashTable);

#ifdef _WIN32
	if (Wow64RevertWow64FsRedirection != NULL)
		Wow64RevertWow64FsRedirection(redir);
#endif

	return 0;
}


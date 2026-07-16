#ifndef _STDINT_H_
#define _STDINT_H_

typedef signed char int8_t;
typedef unsigned char uint8_t;

typedef short int16_t;
typedef unsigned short uint16_t;

typedef int int32_t;
typedef unsigned int uint32_t;

typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;

/* pointer-sized integer for 32-bit WinCE */
typedef unsigned int uintptr_t;
typedef int intptr_t;

#ifndef inline
#define inline __inline
#endif

#endif
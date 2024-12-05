#pragma once

#define CLDFLT_SIG 0x706D6C43ULL

#define CLDFLT_PARAM_TYPE_UINT64 6
#define CLDFLT_PARAM_TYPE_UINT8  7
#define CLDFLT_PARAM_TYPE_UINT16 8
#define CLDFLT_PARAM_TYPE_UINT32 10
#define CLDFLT_PARAM_TYPE_HANDLE 11

#define CLDFLT_MESSAGE_GET_PROCESS_RANGE_INFO 0xD001ULL 

#define CLDFLT_CRC32_CHECK 2

#define RVA_hPort 0x0

#pragma pack(push, 1)
typedef struct _CLDFLT_PARAMETER_MESSAGE {
    UINT16 type;
    UINT16 size;
    UINT32 ioff;
} CLDFLT_PARAMETER_MESSAGE, *PCLDFLT_PARAMETER_MESSAGE;

typedef struct _CLDFLT_HYDRATION_DATA {
    UINT32                   sig;
    UINT32                   checksum;
    UINT32                   nBytes;
    UINT16                   flags;
    UINT16                   nParam;
    CLDFLT_PARAMETER_MESSAGE params[23];
} CLDFLT_HYDRATION_DATA, *PCLDFLT_HYDRATION_DATA;
#pragma pack(pop)

typedef ULONG(NTAPI* __T_RtlComputeCrc32)(DWORD dwInitialValue, PBYTE Buffer, ULONG Length);
__T_RtlComputeCrc32 RtlComputeCrc32;

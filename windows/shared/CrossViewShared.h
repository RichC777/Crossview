#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

#define CV_DEVICE_NAME      L"\\Device\\CrossView"
#define CV_SYMLINK_NAME     L"\\DosDevices\\CrossView"
#define CV_USER_DEVICE      "\\\\.\\CrossView"
#define CV_SERVICE_NAME     L"CrossView"
#define CV_VERSION          0x00010000
#define CV_MAX_FINDINGS     256
#define CV_TITLE_LEN        96
#define CV_DETAIL_LEN       384
#define CV_EVIDENCE_LEN     160
#define CV_MODULE_LEN       32

#define CV_DEVICE_TYPE      0x9C40

#define IOCTL_CV_GET_VERSION    CTL_CODE(CV_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_CV_RUN_SCAN       CTL_CODE(CV_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_CV_GET_FINDINGS   CTL_CODE(CV_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)

#define CV_MOD_PROCESS      0x00000001u
#define CV_MOD_THREAD       0x00000002u
#define CV_MOD_TOKEN        0x00000004u
#define CV_MOD_DRIVER       0x00000008u
#define CV_MOD_BYOVD        0x00000010u
#define CV_MOD_CALLBACK     0x00000020u
#define CV_MOD_FILTER       0x00000040u
#define CV_MOD_ETW          0x00000080u
#define CV_MOD_HOOK         0x00000100u
#define CV_MOD_SSDT         0x00000200u
#define CV_MOD_IDT          0x00000400u
#define CV_MOD_DISPATCH     0x00000800u
#define CV_MOD_NETWORK      0x00001000u
#define CV_MOD_OBJECT       0x00002000u
#define CV_MOD_BUGCHECK     0x00004000u
#define CV_MOD_INTEGRITY    0x00008000u

#define CV_PROFILE_QUICK      (CV_MOD_PROCESS | CV_MOD_TOKEN | CV_MOD_CALLBACK | CV_MOD_ETW | CV_MOD_BYOVD | CV_MOD_INTEGRITY | CV_MOD_DRIVER)
#define CV_PROFILE_FUDMODULE  (CV_PROFILE_QUICK | CV_MOD_FILTER | CV_MOD_BUGCHECK | CV_MOD_NETWORK | CV_MOD_TOKEN)
#define CV_PROFILE_FULL       0xFFFFFFFFu

typedef enum _CV_SEVERITY {
    CvSevInfo = 0,
    CvSevLow,
    CvSevMedium,
    CvSevHigh,
    CvSevCritical,
    CvSevClean
} CV_SEVERITY;

typedef struct _CV_VERSION_INFO {
    ULONG Version;
    ULONG NtBuildNumber;
    ULONG Features;
    UCHAR DriverReady;
    UCHAR OffsetsResolved;
    USHORT Reserved;
} CV_VERSION_INFO;

typedef struct _CV_SCAN_REQUEST {
    ULONG Modules;
} CV_SCAN_REQUEST;

typedef struct _CV_FINDING {
    ULONG Severity;
    CHAR  Module[CV_MODULE_LEN];
    CHAR  Technique[16];
    CHAR  Title[CV_TITLE_LEN];
    CHAR  Detail[CV_DETAIL_LEN];
    CHAR  Evidence[CV_EVIDENCE_LEN];
} CV_FINDING;

typedef struct _CV_SCAN_RESULT {
    ULONG FindingCount;
    ULONG ElapsedMs;
    ULONG BuildNumber;
    ULONG ModulesRun;
    CV_FINDING Findings[CV_MAX_FINDINGS];
} CV_SCAN_RESULT;

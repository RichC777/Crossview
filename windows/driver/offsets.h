#pragma once
#include <ntddk.h>

typedef struct _CV_OFFSETS {
    ULONG Build;
    ULONG ActiveProcessLinks;
    ULONG UniqueProcessId;
    ULONG Token;
    ULONG ImageFileName;
    ULONG Protection;
    ULONG InheritedFrom;
    BOOLEAN Valid;
} CV_OFFSETS;

NTSTATUS CvResolveOffsets(CV_OFFSETS *Out);
PEPROCESS CvProcessFromLinks(PLIST_ENTRY Entry, const CV_OFFSETS *Off);

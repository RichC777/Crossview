#include "offsets.h"

/*
 * Discover EPROCESS.ActiveProcessLinks without a hardcoded table.
 *
 * PsGetProcessId is exported. UniqueProcessId sits immediately before
 * ActiveProcessLinks on every NT build since XP. We confirm by walking
 * the circular list from PsInitialSystemProcess and checking that PID 4
 * and the current process both appear.
 */

#define CV_MAX_PROCESS_WALK  8192
#define CV_SCAN_MAX_OFF      0x800

static ULONG CvNtBuild(void)
{
    RTL_OSVERSIONINFOW vi;
    RtlZeroMemory(&vi, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (!NT_SUCCESS(RtlGetVersion(&vi))) {
        return 0;
    }
    return vi.dwBuildNumber;
}

NTSTATUS CvResolveOffsets(CV_OFFSETS *Out)
{
    ULONG i;
    PEPROCESS systemProc;
    PEPROCESS self;
    PUCHAR base;
    HANDLE sysPid;
    HANDLE selfPid;

    RtlZeroMemory(Out, sizeof(*Out));
    Out->Build = CvNtBuild();

    systemProc = PsInitialSystemProcess;
    self = PsGetCurrentProcess();
    if (!systemProc || !self) {
        return STATUS_NOT_FOUND;
    }

    sysPid = PsGetProcessId(systemProc);
    selfPid = PsGetProcessId(self);
    base = (PUCHAR)systemProc;

    for (i = 0x180; i < CV_SCAN_MAX_OFF; i += sizeof(PVOID)) {
        HANDLE *pidSlot = (HANDLE *)(base + i);
        PLIST_ENTRY links;
        PLIST_ENTRY head;
        PLIST_ENTRY it;
        ULONG steps = 0;
        BOOLEAN sawSystem = FALSE;
        BOOLEAN sawSelf = FALSE;

        if (*pidSlot != sysPid) {
            continue;
        }

        links = (PLIST_ENTRY)(base + i + sizeof(PVOID));
        if (!MmIsAddressValid(links) || !MmIsAddressValid(links->Flink) || !MmIsAddressValid(links->Blink)) {
            continue;
        }
        if (links->Flink == links || links->Blink == links) {
            continue;
        }

        head = links;
        it = links->Flink;
        while (it != head && steps < CV_MAX_PROCESS_WALK) {
            PUCHAR proc = (PUCHAR)it - (i + sizeof(PVOID));
            HANDLE pid;
            if (!MmIsAddressValid(proc) || !MmIsAddressValid(proc + i)) {
                break;
            }
            pid = *(HANDLE *)(proc + i);
            if (pid == sysPid) {
                sawSystem = TRUE;
            }
            if (pid == selfPid) {
                sawSelf = TRUE;
            }
            if (!MmIsAddressValid(it->Flink)) {
                break;
            }
            it = it->Flink;
            steps++;
        }

        if (it == head && sawSystem && sawSelf && steps > 2) {
            Out->UniqueProcessId = i;
            Out->ActiveProcessLinks = i + sizeof(PVOID);
            Out->ImageFileName = 0x5A8;
            Out->Token = 0;
            Out->Protection = 0;
            Out->InheritedFrom = 0;
            Out->Valid = TRUE;
            Out->InheritedFrom = i - sizeof(PVOID);
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

PEPROCESS CvProcessFromLinks(PLIST_ENTRY Entry, const CV_OFFSETS *Off)
{
    return (PEPROCESS)((PUCHAR)Entry - Off->ActiveProcessLinks);
}

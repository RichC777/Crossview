#include "offsets.h"

/*
 * Version-safe EPROCESS layout discovery (Win11 24H2/25H2, build 26100/26200).
 *
 * Prefer decoding displacements from exported helpers via MmGetSystemRoutineAddress
 * (real ntoskrnl body, not an IAT thunk in this .sys):
 *   PsGetProcessId                         -> UniqueProcessId
 *   PsGetProcessImageFileName              -> ImageFileName (15-byte array)
 *   PsGetProcessInheritedFromUniqueProcessId -> InheritedFromUniqueProcessId
 *
 * ActiveProcessLinks is UniqueProcessId + sizeof(PVOID) on every NT build since
 * XP. We prove that by walking the circular list from PsInitialSystemProcess.
 *
 * DriverEntry runs in System, so a walk that starts at Flink never revisits the
 * head PID. Count the head as System and require at least one other process.
 *
 * On this lab image (ntoskrnl 10.0.26100.9444 / NtBuild 26200) the export decode
 * yields UniqueProcessId=0x1D0, ActiveProcessLinks=0x1D8, ImageFileName=0x338,
 * InheritedFrom=0x2D0. Memory-scan fallback remains for builds without a
 * recognizable prologue.
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

static PVOID CvGetExport(const WCHAR *Name)
{
    UNICODE_STRING u;
    RtlInitUnicodeString(&u, Name);
    return MmGetSystemRoutineAddress(&u);
}

/*
 * Decode "mov rax, [rcx+imm]" / "lea rax, [rcx+imm]" from a tiny exported stub.
 * Accepts optional endbr64 (F3 0F 1E FA). Returns 0 on failure.
 */
static ULONG CvDecodeExportDisp(const void *Fn)
{
    const UCHAR *p;
    ULONG i = 0;

    if (!Fn || !MmIsAddressValid((PVOID)Fn)) {
        return 0;
    }
    p = (const UCHAR *)Fn;

    if (MmIsAddressValid((PVOID)(p + 4)) &&
        p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E && p[3] == 0xFA) {
        i = 4;
    }

    if (!MmIsAddressValid((PVOID)(p + i + 7))) {
        return 0;
    }

    /* mov rax, [rcx+imm32]  /  lea rax, [rcx+imm32] */
    if ((p[i] == 0x48 && p[i + 1] == 0x8B && p[i + 2] == 0x81) ||
        (p[i] == 0x48 && p[i + 1] == 0x8D && p[i + 2] == 0x81)) {
        ULONG imm = *(ULONG *)(p + i + 3);
        if (imm >= 0x80 && imm < CV_SCAN_MAX_OFF) {
            return imm;
        }
        return 0;
    }

    /* mov rax, [rcx+imm8]  /  lea rax, [rcx+imm8] */
    if ((p[i] == 0x48 && p[i + 1] == 0x8B && p[i + 2] == 0x41) ||
        (p[i] == 0x48 && p[i + 1] == 0x8D && p[i + 2] == 0x41)) {
        LONG imm8 = (LONG)(CHAR)p[i + 3];
        if (imm8 >= 0x80 && imm8 < (LONG)CV_SCAN_MAX_OFF) {
            return (ULONG)imm8;
        }
    }

    return 0;
}

static BOOLEAN CvValidateActiveLinks(ULONG UniquePidOff, PEPROCESS SystemProc)
{
    PUCHAR base = (PUCHAR)SystemProc;
    PLIST_ENTRY links;
    PLIST_ENTRY head;
    PLIST_ENTRY it;
    ULONG steps = 0;
    BOOLEAN sawOther = FALSE;
    HANDLE sysPid;

    if (!UniquePidOff || UniquePidOff + sizeof(PVOID) + sizeof(LIST_ENTRY) > CV_SCAN_MAX_OFF) {
        return FALSE;
    }
    if (!MmIsAddressValid(base + UniquePidOff)) {
        return FALSE;
    }

    sysPid = PsGetProcessId(SystemProc);
    if (*(HANDLE *)(base + UniquePidOff) != sysPid) {
        return FALSE;
    }

    links = (PLIST_ENTRY)(base + UniquePidOff + sizeof(PVOID));
    if (!MmIsAddressValid(links) ||
        !MmIsAddressValid(links->Flink) ||
        !MmIsAddressValid(links->Blink)) {
        return FALSE;
    }
    if (links->Flink == links || links->Blink == links) {
        return FALSE;
    }
    if (links->Flink->Blink != links || links->Blink->Flink != links) {
        return FALSE;
    }

    head = links;
    it = links->Flink;
    while (it != head && steps < CV_MAX_PROCESS_WALK) {
        PUCHAR proc = (PUCHAR)it - (UniquePidOff + sizeof(PVOID));
        HANDLE pid;

        if (!MmIsAddressValid(proc) || !MmIsAddressValid(proc + UniquePidOff)) {
            return FALSE;
        }
        pid = *(HANDLE *)(proc + UniquePidOff);
        if (pid != sysPid) {
            sawOther = TRUE;
        }
        if (!MmIsAddressValid(it->Flink)) {
            return FALSE;
        }
        if (it->Flink->Blink != it) {
            return FALSE;
        }
        it = it->Flink;
        steps++;
    }

    return (it == head && sawOther && steps > 2);
}

static ULONG CvScanUniqueProcessId(PEPROCESS SystemProc)
{
    ULONG i;
    PUCHAR base = (PUCHAR)SystemProc;
    HANDLE sysPid = PsGetProcessId(SystemProc);

    for (i = 0x180; i < CV_SCAN_MAX_OFF; i += sizeof(PVOID)) {
        if (!MmIsAddressValid(base + i)) {
            continue;
        }
        if (*(HANDLE *)(base + i) != sysPid) {
            continue;
        }
        if (CvValidateActiveLinks(i, SystemProc)) {
            return i;
        }
    }
    return 0;
}

NTSTATUS CvResolveOffsets(CV_OFFSETS *Out)
{
    PEPROCESS systemProc;
    ULONG uniqueOff = 0;
    ULONG imageOff = 0;
    ULONG inheritedOff = 0;

    RtlZeroMemory(Out, sizeof(*Out));
    Out->Build = CvNtBuild();

    systemProc = PsInitialSystemProcess;
    if (!systemProc) {
        return STATUS_NOT_FOUND;
    }

    uniqueOff = CvDecodeExportDisp(CvGetExport(L"PsGetProcessId"));
    if (!uniqueOff || !CvValidateActiveLinks(uniqueOff, systemProc)) {
        uniqueOff = CvScanUniqueProcessId(systemProc);
    }
    if (!uniqueOff) {
        return STATUS_NOT_FOUND;
    }

    imageOff = CvDecodeExportDisp(CvGetExport(L"PsGetProcessImageFileName"));
    inheritedOff = CvDecodeExportDisp(CvGetExport(L"PsGetProcessInheritedFromUniqueProcessId"));

    Out->UniqueProcessId = uniqueOff;
    Out->ActiveProcessLinks = uniqueOff + sizeof(PVOID);
    Out->ImageFileName = imageOff;       /* 0 if decode failed — optional */
    Out->InheritedFrom = inheritedOff;   /* 0 if decode failed — optional */
    Out->Token = 0;
    Out->Protection = 0;
    Out->Valid = TRUE;
    return STATUS_SUCCESS;
}

PEPROCESS CvProcessFromLinks(PLIST_ENTRY Entry, const CV_OFFSETS *Off)
{
    return (PEPROCESS)((PUCHAR)Entry - Off->ActiveProcessLinks);
}

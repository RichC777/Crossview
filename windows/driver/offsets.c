#include "offsets.h"

/*
 * Version-safe EPROCESS layout discovery (Win11 24H2/25H2, build 26100/26200).
 *
 * Prefer decoding displacements from exported helpers via MmGetSystemRoutineAddress
 * (real ntoskrnl body, not an IAT thunk in this .sys):
 *   PsGetProcessId                         -> UniqueProcessId
 *   PsGetProcessImageFileName              -> ImageFileName (15-byte array)
 *   PsGetProcessInheritedFromUniqueProcessId -> InheritedFromUniqueProcessId
 *   PsIsProtectedProcess / ...Light        -> Protection (PS_PROTECTION byte)
 *
 * Token is an EX_FAST_REF with no clean single-instruction accessor, so it is
 * resolved by cross-check instead of decode: PsReferencePrimaryToken hands back
 * the System process's real token pointer, and we find the EPROCESS slot whose
 * masked value matches. This validates the offset against an export the same way
 * the ActiveProcessLinks walk validates UniqueProcessId.
 *
 * ActiveProcessLinks is UniqueProcessId + sizeof(PVOID) on every NT build since
 * XP. We prove that by walking the circular list from PsInitialSystemProcess.
 *
 * DriverEntry runs in System, so a walk that starts at Flink never revisits the
 * head PID. Count the head as System and require at least one other process.
 *
 * On this lab image (ntoskrnl 10.0.26100.9444 / NtBuild 26200) the export decode
 * yields UniqueProcessId=0x1D0, ActiveProcessLinks=0x1D8, ImageFileName=0x338,
 * InheritedFrom=0x2D0. Token/Protection resolve by the cross-check/decode above.
 * Each optional offset is left 0 and soft-failed by callers when unresolved.
 * Memory-scan fallback remains for builds without a recognizable prologue.
 */

NTKERNELAPI PACCESS_TOKEN NTAPI PsReferencePrimaryToken(PEPROCESS Process);
NTKERNELAPI VOID NTAPI PsDereferencePrimaryToken(PACCESS_TOKEN PrimaryToken);

#define CV_MAX_PROCESS_WALK  8192
#define CV_SCAN_MAX_OFF      0x800
#define CV_FAST_REF_MASK     (~(ULONG_PTR)0xF)

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

/*
 * Scan a tiny exported stub for the first "movzx r32, byte ptr [rcx+imm]"
 * (0F B6 /r with an rcx base). PsIsProtectedProcess reads the Protection byte
 * this way. Returns 0 on failure.
 */
static ULONG CvScanByteDispRcx(const void *Fn, ULONG MaxScan)
{
    const UCHAR *p = (const UCHAR *)Fn;
    ULONG i;

    if (!p || !MmIsAddressValid((PVOID)p)) {
        return 0;
    }
    for (i = 0; i + 7 <= MaxScan; i++) {
        if (!MmIsAddressValid((PVOID)(p + i + 6))) {
            break;
        }
        if (p[i] != 0x0F || p[i + 1] != 0xB6) {
            continue;
        }
        /* modrm masked to (mod|rm), reg field ignored: [rcx+disp32] / [rcx+disp8] */
        if ((p[i + 2] & 0xC7) == 0x81) {
            ULONG imm = *(ULONG *)(p + i + 3);
            if (imm >= 0x80 && imm < CV_SCAN_MAX_OFF) {
                return imm;
            }
        } else if ((p[i + 2] & 0xC7) == 0x41) {
            LONG imm8 = (LONG)(CHAR)p[i + 3];
            if (imm8 >= 0x80 && imm8 < (LONG)CV_SCAN_MAX_OFF) {
                return (ULONG)imm8;
            }
        }
    }
    return 0;
}

/* The 15-byte ImageFileName of PsInitialSystemProcess is always "System". */
static BOOLEAN CvValidateImageName(PEPROCESS Proc, ULONG Off)
{
    const CHAR *name = (const CHAR *)((PUCHAR)Proc + Off);

    if (!Off || Off + 6 >= CV_SCAN_MAX_OFF) {
        return FALSE;
    }
    if (!MmIsAddressValid((PVOID)name) || !MmIsAddressValid((PVOID)(name + 6))) {
        return FALSE;
    }
    return (name[0] == 'S' && name[1] == 'y' && name[2] == 's' &&
            name[3] == 't' && name[4] == 'e' && name[5] == 'm');
}

/*
 * Cross-check Token: PsReferencePrimaryToken returns the System process's real
 * primary token, so the EPROCESS slot holding that pointer (EX_FAST_REF, low
 * bits masked) is the Token offset. Reversible — we drop the reference we took.
 */
static ULONG CvResolveTokenOffset(PEPROCESS SystemProc)
{
    PUCHAR base = (PUCHAR)SystemProc;
    PACCESS_TOKEN tok;
    ULONG_PTR tokPtr;
    ULONG i;
    ULONG found = 0;

    tok = PsReferencePrimaryToken(SystemProc);
    if (!tok) {
        return 0;
    }
    tokPtr = (ULONG_PTR)tok & CV_FAST_REF_MASK;

    for (i = 0x80; i + sizeof(PVOID) <= CV_SCAN_MAX_OFF; i += sizeof(PVOID)) {
        if (!MmIsAddressValid(base + i)) {
            continue;
        }
        if ((*(ULONG_PTR *)(base + i) & CV_FAST_REF_MASK) == tokPtr) {
            found = i;
            break;
        }
    }

    PsDereferencePrimaryToken(tok);
    return found;
}

/*
 * Decode Protection from PsIsProtectedProcess; require PsIsProtectedProcessLight
 * to agree when both decode. Bounds-checked; 0 (soft-fail) when unresolved.
 */
static ULONG CvResolveProtectionOffset(PEPROCESS SystemProc)
{
    ULONG a = CvScanByteDispRcx(CvGetExport(L"PsIsProtectedProcess"), 48);
    ULONG b = CvScanByteDispRcx(CvGetExport(L"PsIsProtectedProcessLight"), 48);
    ULONG off;

    if (a && b) {
        off = (a == b) ? a : 0;
    } else {
        off = a ? a : b;
    }
    if (!off || off + 1 > CV_SCAN_MAX_OFF) {
        return 0;
    }
    if (!MmIsAddressValid((PUCHAR)SystemProc + off)) {
        return 0;
    }
    return off;
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

    if (imageOff && !CvValidateImageName(systemProc, imageOff)) {
        imageOff = 0;
    }

    Out->UniqueProcessId = uniqueOff;
    Out->ActiveProcessLinks = uniqueOff + sizeof(PVOID);
    Out->ImageFileName = imageOff;       /* 0 if decode/validate failed — optional */
    Out->InheritedFrom = inheritedOff;   /* 0 if decode failed — optional */
    Out->Token = CvResolveTokenOffset(systemProc);        /* 0 if unresolved — optional */
    Out->Protection = CvResolveProtectionOffset(systemProc); /* 0 if unresolved — optional */
    Out->Valid = TRUE;
    return STATUS_SUCCESS;
}

PEPROCESS CvProcessFromLinks(PLIST_ENTRY Entry, const CV_OFFSETS *Off)
{
    return (PEPROCESS)((PUCHAR)Entry - Off->ActiveProcessLinks);
}

#include "scan.h"
#include <ntstrsafe.h>
#include <intrin.h>

/*
 * CROSSVIEW kernel scans â€” detection only.
 * Every walk is wrapped in SEH. We never write kernel memory.
 */

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

#define CV_SystemModuleInformation 11

typedef struct _CV_SYS_MODULE_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} CV_SYS_MODULE_ENTRY;

typedef struct _CV_SYS_MODULE_INFO {
    ULONG NumberOfModules;
    CV_SYS_MODULE_ENTRY Modules[1];
} CV_SYS_MODULE_INFO;

static const WCHAR *kLolDrivers[] = {
    L"dbutil_2_3.sys", L"DBUtilDrv2.sys", L"gdrv.sys", L"RTCore64.sys",
    L"AsIO.sys", L"AsIO2.sys", L"WinRing0x64.sys", L"iqvw64e.sys",
    L"capcom.sys", L"cpuz.sys", L"AMDRyzenMasterDriver.sys", L"atszio.sys",
    L"lha.sys", L"dbk64.sys", L"zam64.sys", L"MsIo64.sys",
    L"NTIOLib_X64.sys", L"phymemx64.sys", L"ene.sys", L"GLCKIO2.sys",
    NULL
};

static void CvAdd(
    CV_SCAN_RESULT *R,
    CV_SEVERITY Sev,
    const CHAR *Module,
    const CHAR *Tech,
    const CHAR *Title,
    const CHAR *Detail,
    const CHAR *Evidence)
{
    CV_FINDING *f;
    if (R->FindingCount >= CV_MAX_FINDINGS) {
        return;
    }
    f = &R->Findings[R->FindingCount++];
    RtlZeroMemory(f, sizeof(*f));
    f->Severity = (ULONG)Sev;
    RtlStringCbCopyA(f->Module, sizeof(f->Module), Module);
    RtlStringCbCopyA(f->Technique, sizeof(f->Technique), Tech);
    RtlStringCbCopyA(f->Title, sizeof(f->Title), Title);
    RtlStringCbCopyA(f->Detail, sizeof(f->Detail), Detail);
    RtlStringCbCopyA(f->Evidence, sizeof(f->Evidence), Evidence ? Evidence : "");
}

static void CvScanProcess(CV_SCAN_RESULT *R, const CV_OFFSETS *Off)
{
    ULONG walked = 0;
    PEPROCESS sys = PsInitialSystemProcess;
    PLIST_ENTRY head;
    PLIST_ENTRY it;

    if (!Off->Valid) {
        CvAdd(R, CvSevMedium, "process", "T2.b",
              "EPROCESS offsets unresolved",
              "Refusing ActiveProcessLinks walk on this build. User-mode views still run.",
              "CvResolveOffsets failed");
        return;
    }

    __try {
        head = (PLIST_ENTRY)((PUCHAR)sys + Off->ActiveProcessLinks);
        it = head->Flink;
        while (it != head && walked < 8192) {
            PEPROCESS proc = CvProcessFromLinks(it, Off);
            if (!MmIsAddressValid(proc)) {
                CvAdd(R, CvSevHigh, "process", "T2.b",
                      "Corrupt ActiveProcessLinks",
                      "List walk hit a non-canonical or paged-out EPROCESS. Possible DKOM.",
                      "MmIsAddressValid failed mid-walk");
                break;
            }
            walked++;
            if (!MmIsAddressValid(it->Flink)) {
                CvAdd(R, CvSevCritical, "process", "T2.b",
                      "Process list splice detected",
                      "Flink was not a valid kernel pointer. Classic FU-style unlink residue.",
                      "ActiveProcessLinks.Flink invalid");
                break;
            }
            it = it->Flink;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        CvAdd(R, CvSevHigh, "process", "T2.b",
              "Exception during process walk",
              "SEH caught a fault walking PsActiveProcessHead. Treat as hostile DKOM until proven otherwise.",
              "EXCEPTION in CvScanProcess");
        return;
    }

    if (walked < 8) {
        CvAdd(R, CvSevHigh, "process", "T2.b",
              "Implausibly short process list",
              "A healthy Windows 11 box has far more than a handful of EPROCESS entries.",
              "walked < 8");
    } else {
        CHAR ev[CV_EVIDENCE_LEN];
        RtlStringCbPrintfA(ev, sizeof(ev), "ActiveProcessLinks walked %lu processes", walked);
        CvAdd(R, CvSevClean, "process", "T2.b",
              "Process list walk completed",
              "Circular list from PsInitialSystemProcess is well-formed. Cross-check CID in user-mode.",
              ev);
    }
}

static void CvScanToken(CV_SCAN_RESULT *R)
{
    PEPROCESS proc = PsGetCurrentProcess();
    HANDLE pid;

    __try {
        pid = PsGetProcessId(proc);
        if (pid == (HANDLE)(ULONG_PTR)4) {
            CvAdd(R, CvSevInfo, "token", "T2.d",
                  "IRP originated from SYSTEM",
                  "Caller is PID 4. Token theft checks for other processes happen in the usermode companion via NtQueryInformationProcess.",
                  "PID 4");
        } else {
            CHAR ev[CV_EVIDENCE_LEN];
            RtlStringCbPrintfA(ev, sizeof(ev), "Caller PID %llu", (unsigned long long)(ULONG_PTR)pid);
            CvAdd(R, CvSevInfo, "token", "T2.d",
                  "IRP originated from non-SYSTEM process",
                  "Elevate cvscan/CrossView.exe. Kernel still walks PID 4 independently.",
                  ev);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        CvAdd(R, CvSevMedium, "token", "T2.d", "Token probe faulted", "SEH during token module.", NULL);
    }
}

static BOOLEAN CvNameIsLol(PUNICODE_STRING Name)
{
    const WCHAR **it;
    if (!Name || !Name->Buffer) {
        return FALSE;
    }
    for (it = kLolDrivers; *it; ++it) {
        UNICODE_STRING n;
        UNICODE_STRING tail;
        RtlInitUnicodeString(&n, *it);
        if (Name->Length < n.Length) {
            continue;
        }
        tail = *Name;
        tail.Buffer = (PWCH)((PUCHAR)Name->Buffer + Name->Length - n.Length);
        tail.Length = n.Length;
        tail.MaximumLength = n.Length;
        if (RtlEqualUnicodeString(&tail, &n, TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}

static void CvScanDrivers(CV_SCAN_RESULT *R, BOOLEAN WantByovd)
{
    ULONG i;
    ULONG n = 0;
    ULONG lol = 0;
    CV_SYS_MODULE_INFO *info = NULL;
    ULONG size = 0;
    NTSTATUS st;

    st = ZwQuerySystemInformation(CV_SystemModuleInformation, NULL, 0, &size);
    if (size == 0) {
        CvAdd(R, CvSevMedium, "driver", "T2.a",
              "SystemModuleInformation size query failed",
              "Cannot snapshot PsLoadedModulesList via ZwQuerySystemInformation.",
              NULL);
        return;
    }
    size += 0x1000;
    info = (CV_SYS_MODULE_INFO *)ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'vCxC');
    if (!info) {
        return;
    }
    st = ZwQuerySystemInformation(CV_SystemModuleInformation, info, size, &size);
    if (!NT_SUCCESS(st)) {
        ExFreePool(info);
        CvAdd(R, CvSevMedium, "driver", "T2.a",
              "Module snapshot failed",
              "ZwQuerySystemInformation(SystemModuleInformation) returned an error.",
              NULL);
        return;
    }

    n = info->NumberOfModules;
    for (i = 0; i < n; i++) {
        ANSI_STRING as;
        UNICODE_STRING us;
        RtlInitAnsiString(&as, (PCSZ)info->Modules[i].FullPathName);
        if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&us, &as, TRUE))) {
            if (CvNameIsLol(&us)) {
                CHAR ev[CV_EVIDENCE_LEN];
                lol++;
                RtlStringCbPrintfA(ev, sizeof(ev), "%s", info->Modules[i].FullPathName);
                if (WantByovd) {
                    CvAdd(R, CvSevCritical, "byovd", "T16.a",
                          "Known-vulnerable driver loaded",
                          "A LOLDrivers-class signed .sys is currently mapped. This is a BYOVD primitive, not proof of exploitation.",
                          ev);
                }
            }
            RtlFreeUnicodeString(&us);
        }
    }

    {
        CHAR ev[CV_EVIDENCE_LEN];
        RtlStringCbPrintfA(ev, sizeof(ev), "PsLoadedModules snapshot: %lu images, %lu LOLDrivers hits", n, lol);
        CvAdd(R, CvSevClean, "driver", "T2.a",
              "Loaded-module snapshot taken",
              "Compare this count to the \\Driver object directory and to PiDDB from a full memory image.",
              ev);
    }
    if (WantByovd && lol == 0) {
        CvAdd(R, CvSevInfo, "byovd", "T14.d",
              "No LOLDrivers currently mapped",
              "FudModule 3.1 does not need a third-party vulnerable .sys when afd.sys is unpatched. Check MmUnloadedDrivers offline.",
              "loaded LOLDrivers = 0");
    }
    ExFreePool(info);
}

static void CvScanIdtMsr(CV_SCAN_RESULT *R)
{
    UCHAR idt[10];
    ULONG_PTR base;
    ULONG64 lstar;
    CHAR ev[CV_EVIDENCE_LEN];

    __try {
        __sidt(idt);
        base = *(ULONG_PTR *)(idt + 2);
        lstar = __readmsr(0xC0000082);

        RtlStringCbPrintfA(ev, sizeof(ev), "IDT=%p  LSTAR=%p", (void *)base, (void *)(ULONG_PTR)lstar);
        if (lstar < 0xFFFF800000000000ULL) {
            CvAdd(R, CvSevCritical, "idt", "T1.b",
                  "IA32_LSTAR is not a canonical kernel address",
                  "Syscall MSR does not point into kernel space. Possible syscall hook or hypervisor intercept.",
                  ev);
        } else {
            CvAdd(R, CvSevClean, "idt", "T1.b",
                  "LSTAR is a kernel canonical address",
                  "Full confirmation that LSTAR == nt!KiSystemCall64 requires a symbol. Range check passed on this CPU.",
                  ev);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        CvAdd(R, CvSevMedium, "idt", "T1.b", "SIDT/RDMSR faulted", "Unexpected exception reading IDT or LSTAR.", NULL);
    }
}

static void CvScanDispatch(CV_SCAN_RESULT *R)
{
    UNICODE_STRING name;
    PFILE_OBJECT fileObj = NULL;
    PDEVICE_OBJECT dev = NULL;
    NTSTATUS st;
    ULONG hooked = 0;
    ULONG slot;

    RtlInitUnicodeString(&name, L"\\Device\\Null");
    st = IoGetDeviceObjectPointer(&name, FILE_READ_DATA, &fileObj, &dev);
    if (!NT_SUCCESS(st) || !dev || !dev->DriverObject) {
        CvAdd(R, CvSevInfo, "dispatch", "T4.f",
              "Null device not opened",
              "Could not reference \\Device\\Null for a MajorFunction range check.",
              NULL);
        return;
    }

    __try {
        PDRIVER_OBJECT drv = dev->DriverObject;
        PUCHAR start = (PUCHAR)drv->DriverStart;
        SIZE_T size = drv->DriverSize;
        for (slot = 0; slot <= IRP_MJ_MAXIMUM_FUNCTION; slot++) {
            PUCHAR fn = (PUCHAR)drv->MajorFunction[slot];
            if (!fn) {
                continue;
            }
            if (start && size && (fn < start || fn >= start + size)) {
                hooked++;
            }
        }
        {
            CHAR ev[CV_EVIDENCE_LEN];
            RtlStringCbPrintfA(ev, sizeof(ev), "null.sys out-of-image MajorFunction slots=%lu (IopInvalidDeviceRequest is OK)", hooked);
            if (hooked > 8) {
                CvAdd(R, CvSevHigh, "dispatch", "T4.f",
                      "Null driver dispatch heavily redirected",
                      "Most IRP slots point outside null.sys. Possible dispatch hijack (T2.n / T4.f).",
                      ev);
            } else {
                CvAdd(R, CvSevClean, "dispatch", "T4.f",
                      "Null driver dispatch looks stock",
                      "A few out-of-image slots are expected (IopInvalidDeviceRequest). Count is within bounds.",
                      ev);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        CvAdd(R, CvSevMedium, "dispatch", "T4.f", "Dispatch walk faulted", "SEH during null.sys MajorFunction scan.", NULL);
    }

    if (fileObj) {
        ObDereferenceObject(fileObj);
    }
}

/*
 * T11.a — process / thread / image notify callbacks (FudModule teardown class).
 *
 * Resolve Psp*NotifyRoutine arrays by decoding RIP-relative LEAs from the
 * exported setters (or their first near-call callee). Same version-safe style
 * as offsets.c — no PDB, no SSDT, read-only. Validated on Win11 26200
 * (ntoskrnl 10.0.26100.9444): 64 EX_FAST_REF slots, Function at block+0x08.
 *
 * Cross-view: if WdFilter.sys is mapped but no notify Function lands in its
 * image, treat as FudModule-class callback teardown.
 */
#define CV_NOTIFY_SLOTS     64
#define CV_FAST_REF_MASK    (~(ULONG_PTR)0xF)
#define CV_CB_FN_OFF        0x08

typedef struct _CV_MOD_RANGE {
    PVOID Base;
    ULONG Size;
    CHAR  Name[64];
} CV_MOD_RANGE;

static PVOID CvFollowNearCall(const UCHAR *p, ULONG MaxScan)
{
    ULONG i;
    if (!p || !MmIsAddressValid((PVOID)p)) {
        return NULL;
    }
    for (i = 0; i + 5 <= MaxScan; i++) {
        if (!MmIsAddressValid((PVOID)(p + i + 4))) {
            break;
        }
        if (p[i] == 0xE8) {
            LONG rel = *(LONG *)(p + i + 1);
            return (PVOID)(p + i + 5 + rel);
        }
        if (i + 4 <= MaxScan &&
            p[i] == 0xF3 && p[i + 1] == 0x0F && p[i + 2] == 0x1E && p[i + 3] == 0xFA) {
            i += 3;
        }
    }
    return NULL;
}

static PVOID CvFindLeaRipTarget(const UCHAR *p, ULONG MaxScan)
{
    ULONG i;
    if (!p || !MmIsAddressValid((PVOID)p)) {
        return NULL;
    }
    for (i = 0; i + 7 <= MaxScan; i++) {
        UCHAR modrm;
        LONG imm;
        if (!MmIsAddressValid((PVOID)(p + i + 6))) {
            break;
        }
        if ((p[i] == 0x48 || p[i] == 0x4C) && p[i + 1] == 0x8D) {
            modrm = p[i + 2];
            if ((modrm & 0xC7) == 0x05) {
                imm = *(LONG *)(p + i + 3);
                return (PVOID)(p + i + 7 + imm);
            }
        }
    }
    return NULL;
}

static PVOID CvGetExportA(const WCHAR *Name)
{
    UNICODE_STRING u;
    RtlInitUnicodeString(&u, Name);
    return MmGetSystemRoutineAddress(&u);
}

static PVOID CvResolveNotifyArray(const WCHAR *ExportName)
{
    const UCHAR *exp;
    PVOID arr;
    PVOID callee;

    exp = (const UCHAR *)CvGetExportA(ExportName);
    if (!exp) {
        return NULL;
    }
    arr = CvFindLeaRipTarget(exp, 0x100);
    if (arr && MmIsAddressValid(arr)) {
        return arr;
    }
    callee = CvFollowNearCall(exp, 0x40);
    if (!callee || !MmIsAddressValid(callee)) {
        return NULL;
    }
    arr = CvFindLeaRipTarget((const UCHAR *)callee, 0x100);
    if (arr && MmIsAddressValid(arr)) {
        return arr;
    }
    return NULL;
}

static ULONG CvCollectNotifyFns(PVOID Array, PVOID *Out, ULONG MaxOut)
{
    ULONG i;
    ULONG n = 0;

    if (!Array || !Out || !MaxOut) {
        return 0;
    }
    __try {
        for (i = 0; i < CV_NOTIFY_SLOTS; i++) {
            ULONG_PTR slot;
            PVOID block;
            PVOID fn;

            if (!MmIsAddressValid((PUCHAR)Array + i * sizeof(PVOID))) {
                break;
            }
            slot = *(ULONG_PTR *)((PUCHAR)Array + i * sizeof(PVOID));
            block = (PVOID)(slot & CV_FAST_REF_MASK);
            if (!block) {
                continue;
            }
            if (!MmIsAddressValid((PUCHAR)block + CV_CB_FN_OFF + sizeof(PVOID) - 1)) {
                continue;
            }
            fn = *(PVOID *)((PUCHAR)block + CV_CB_FN_OFF);
            if (!fn || (ULONG_PTR)fn < 0xFFFF800000000000ULL) {
                continue;
            }
            if (n < MaxOut) {
                Out[n++] = fn;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return n;
    }
    return n;
}

static BOOLEAN CvNameTailMatchA(const CHAR *Path, const CHAR *Tail)
{
    SIZE_T lp;
    SIZE_T lt;
    SIZE_T i;
    if (!Path || !Tail) {
        return FALSE;
    }
    lp = 0;
    while (Path[lp]) {
        lp++;
    }
    lt = 0;
    while (Tail[lt]) {
        lt++;
    }
    if (lt == 0 || lp < lt) {
        return FALSE;
    }
    for (i = 0; i < lt; i++) {
        CHAR a = Path[lp - lt + i];
        CHAR b = Tail[i];
        if (a >= 'A' && a <= 'Z') {
            a = (CHAR)(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = (CHAR)(b - 'A' + 'a');
        }
        if (a != b) {
            return FALSE;
        }
    }
    return TRUE;
}

static ULONG CvSnapshotSecurityMods(CV_MOD_RANGE *Out, ULONG MaxOut, BOOLEAN *WdFilterPresent)
{
    CV_SYS_MODULE_INFO *info = NULL;
    ULONG size = 0;
    ULONG n = 0;
    ULONG i;
    NTSTATUS st;
    static const CHAR *kTails[] = {
        "wdfilter.sys",
        "wdnisdrv.sys",
        "sysmon.sys",
        "sysmondrv.sys",
        NULL
    };

    if (WdFilterPresent) {
        *WdFilterPresent = FALSE;
    }
    st = ZwQuerySystemInformation(CV_SystemModuleInformation, NULL, 0, &size);
    if (size == 0) {
        return 0;
    }
    size += 0x1000;
    info = (CV_SYS_MODULE_INFO *)ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'bCxC');
    if (!info) {
        return 0;
    }
    st = ZwQuerySystemInformation(CV_SystemModuleInformation, info, size, &size);
    if (!NT_SUCCESS(st)) {
        ExFreePool(info);
        return 0;
    }
    for (i = 0; i < info->NumberOfModules && n < MaxOut; i++) {
        const CHAR *path = (const CHAR *)info->Modules[i].FullPathName;
        const CHAR **t;
        for (t = kTails; *t; ++t) {
            if (CvNameTailMatchA(path, *t)) {
                Out[n].Base = info->Modules[i].ImageBase;
                Out[n].Size = info->Modules[i].ImageSize;
                RtlStringCbCopyA(Out[n].Name, sizeof(Out[n].Name), *t);
                if (WdFilterPresent && CvNameTailMatchA(path, "wdfilter.sys")) {
                    *WdFilterPresent = TRUE;
                }
                n++;
                break;
            }
        }
    }
    ExFreePool(info);
    return n;
}

static BOOLEAN CvFnInRanges(PVOID Fn, const CV_MOD_RANGE *Mods, ULONG ModCount, CHAR *HitName, SIZE_T HitLen)
{
    ULONG i;
    for (i = 0; i < ModCount; i++) {
        PUCHAR b = (PUCHAR)Mods[i].Base;
        if (!b || !Mods[i].Size) {
            continue;
        }
        if ((PUCHAR)Fn >= b && (PUCHAR)Fn < b + Mods[i].Size) {
            if (HitName && HitLen) {
                RtlStringCbCopyA(HitName, HitLen, Mods[i].Name);
            }
            return TRUE;
        }
    }
    return FALSE;
}

static void CvScanCallbacks(CV_SCAN_RESULT *R)
{
    PVOID procArr = NULL;
    PVOID thrArr = NULL;
    PVOID imgArr = NULL;
    PVOID fns[CV_NOTIFY_SLOTS * 3];
    ULONG nProc = 0;
    ULONG nThr = 0;
    ULONG nImg = 0;
    ULONG nAll = 0;
    ULONG i;
    ULONG intoWd = 0;
    BOOLEAN wdPresent = FALSE;
    CV_MOD_RANGE mods[16];
    ULONG modCount;
    CHAR ev[CV_EVIDENCE_LEN];

    RtlZeroMemory(fns, sizeof(fns));
    RtlZeroMemory(mods, sizeof(mods));

    modCount = CvSnapshotSecurityMods(mods, 16, &wdPresent);

    __try {
        procArr = CvResolveNotifyArray(L"PsSetCreateProcessNotifyRoutine");
        if (!procArr) {
            procArr = CvResolveNotifyArray(L"PsSetCreateProcessNotifyRoutineEx");
        }
        thrArr = CvResolveNotifyArray(L"PsSetCreateThreadNotifyRoutine");
        imgArr = CvResolveNotifyArray(L"PsSetLoadImageNotifyRoutineEx");
        if (!imgArr) {
            imgArr = CvResolveNotifyArray(L"PsSetLoadImageNotifyRoutine");
        }

        if (procArr) {
            nProc = CvCollectNotifyFns(procArr, fns + nAll, CV_NOTIFY_SLOTS);
            nAll += nProc;
        }
        if (thrArr) {
            nThr = CvCollectNotifyFns(thrArr, fns + nAll, CV_NOTIFY_SLOTS);
            nAll += nThr;
        }
        if (imgArr) {
            nImg = CvCollectNotifyFns(imgArr, fns + nAll, CV_NOTIFY_SLOTS);
            nAll += nImg;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        CvAdd(R, CvSevMedium, "callback", "T11.a",
              "Exception resolving notify callback arrays",
              "SEH during export-LEA decode or slot walk. Refusing to guess on this build.",
              "EXCEPTION in CvScanCallbacks");
        return;
    }

    if (!procArr && !thrArr && !imgArr) {
        CvAdd(R, CvSevMedium, "callback", "T11.a",
              "Notify callback arrays not resolved",
              "Export-LEA decode failed for process/thread/image setters. No PDB fallback in this build.",
              "PsSet*NotifyRoutine LEA miss");
        return;
    }

    for (i = 0; i < nAll; i++) {
        CHAR hit[64];
        RtlZeroMemory(hit, sizeof(hit));
        if (CvFnInRanges(fns[i], mods, modCount, hit, sizeof(hit))) {
            if (CvNameTailMatchA(hit, "wdfilter.sys")) {
                intoWd++;
            }
        }
    }

    RtlStringCbPrintfA(ev, sizeof(ev),
                       "proc=%lu thr=%lu img=%lu  WdFilter=%s inWd=%lu secMods=%lu",
                       nProc, nThr, nImg,
                       wdPresent ? "mapped" : "absent",
                       intoWd, modCount);

    if (wdPresent && intoWd == 0) {
        CvAdd(R, CvSevHigh, "callback", "T11.a",
              "WdFilter mapped but absent from notify callbacks",
              "WdFilter.sys is in PsLoadedModules yet no process/thread/image notify Function points into it. Classic FudModule-class callback teardown (T11.a).",
              ev);
    } else if (nAll == 0) {
        CvAdd(R, CvSevHigh, "callback", "T11.a",
              "All notify callback arrays are empty",
              "Resolved Psp*NotifyRoutine arrays but every EX_FAST_REF slot is vacant. Healthy Win11 hosts register CI/WdFilter/third-party notifiers.",
              ev);
    } else {
        CvAdd(R, CvSevClean, "callback", "T11.a",
              "Notify callback arrays populated",
              "Export-LEA resolved process/thread/image arrays on this build. Cross-check vendor slots against mapped EDR modules.",
              ev);
        if (wdPresent && intoWd > 0) {
            CHAR ev2[CV_EVIDENCE_LEN];
            RtlStringCbPrintfA(ev2, sizeof(ev2), "WdFilter owns %lu notify Function(s)", intoWd);
            CvAdd(R, CvSevInfo, "callback", "T11.a",
                  "WdFilter notify callbacks present",
                  "At least one Psp*NotifyRoutine slot points into WdFilter.sys. Teardown not indicated on this pass.",
                  ev2);
        }
    }
}

/*
 * T15.b — FudModule 94-GUID ETW kill-list probe.
 * EnableMask lives in EtwpHostSiloState (undocumented). The real probe is in
 * cvscan (cli/etw-guids.h + StartTrace/EnableTraceEx2). Detection-only.
 */
static void CvScanEtw(CV_SCAN_RESULT *R)
{
    (void)R;
}

/*
 * T12.e — minifilter cross-view via Filter Manager (fltmc-style).
 *
 * WDM software driver: call FltEnumerateFilterInformation without registering
 * as a minifilter. Read-only. Win11 26200-safe (PASSIVE_LEVEL / APC_LEVEL max).
 *
 * FudModule-class signal: WdFilter.sys mapped in PsLoadedModules but absent
 * from FltMgr (or AV altitude 328010 missing) means the minifilter was torn
 * down while the image remained.
 */
#define CV_FLT_INFO_CLASS_AGG_STD   2u
#define CV_FLTFL_ASI_IS_MINIFILTER  0x00000001u
#define CV_FLT_ENUM_MAX             256u
#define CV_FLT_INFO_CB              768u
#define CV_WD_FILTER_ALTITUDE       "328010"

typedef struct _CV_FILTER_AGGREGATE_STANDARD_INFORMATION {
    ULONG NextEntryOffset;
    ULONG Flags;
    union {
        struct {
            ULONG Flags;
            ULONG FrameID;
            ULONG NumberOfInstances;
            USHORT FilterNameLength;
            USHORT FilterNameBufferOffset;
            USHORT FilterAltitudeLength;
            USHORT FilterAltitudeBufferOffset;
        } MiniFilter;
        struct {
            ULONG Flags;
            USHORT FilterNameLength;
            USHORT FilterNameBufferOffset;
            USHORT FilterAltitudeLength;
            USHORT FilterAltitudeBufferOffset;
        } LegacyFilter;
    } Type;
} CV_FILTER_AGGREGATE_STANDARD_INFORMATION;

NTSTATUS NTAPI FltEnumerateFilterInformation(
    ULONG Index,
    ULONG InformationClass,
    PVOID Buffer,
    ULONG BufferSize,
    PULONG BytesReturned
);

static BOOLEAN CvWideEqualsAsciiI(const WCHAR *W, USHORT ByteLen, const CHAR *A)
{
    USHORT n;
    USHORT i;
    if (!W || !A) {
        return FALSE;
    }
    n = (USHORT)(ByteLen / sizeof(WCHAR));
    for (i = 0; ; i++) {
        CHAR ac = A[i];
        WCHAR wc;
        CHAR wcl;
        if (ac == 0) {
            return (BOOLEAN)(i == n);
        }
        if (i >= n) {
            return FALSE;
        }
        wc = W[i];
        if (wc > 0x7f) {
            return FALSE;
        }
        wcl = (CHAR)wc;
        if (wcl >= 'A' && wcl <= 'Z') {
            wcl = (CHAR)(wcl - 'A' + 'a');
        }
        if (ac >= 'A' && ac <= 'Z') {
            ac = (CHAR)(ac - 'A' + 'a');
        }
        if (wcl != ac) {
            return FALSE;
        }
    }
}

static BOOLEAN CvWideContainsAsciiI(const WCHAR *W, USHORT ByteLen, const CHAR *A)
{
    USHORT n;
    USHORT al;
    USHORT i;
    USHORT j;
    if (!W || !A || !A[0]) {
        return FALSE;
    }
    n = (USHORT)(ByteLen / sizeof(WCHAR));
    al = 0;
    while (A[al]) {
        al++;
    }
    if (al == 0 || n < al) {
        return FALSE;
    }
    for (i = 0; i + al <= n; i++) {
        for (j = 0; j < al; j++) {
            WCHAR wc = W[i + j];
            CHAR ac = A[j];
            CHAR wcl;
            if (wc > 0x7f) {
                break;
            }
            wcl = (CHAR)wc;
            if (wcl >= 'A' && wcl <= 'Z') {
                wcl = (CHAR)(wcl - 'A' + 'a');
            }
            if (ac >= 'A' && ac <= 'Z') {
                ac = (CHAR)(ac - 'A' + 'a');
            }
            if (wcl != ac) {
                break;
            }
        }
        if (j == al) {
            return TRUE;
        }
    }
    return FALSE;
}

static void CvCopyWideToAnsi(
    const WCHAR *W,
    USHORT ByteLen,
    CHAR *Out,
    SIZE_T OutLen)
{
    USHORT n;
    USHORT i;
    if (!Out || OutLen == 0) {
        return;
    }
    Out[0] = 0;
    if (!W) {
        return;
    }
    n = (USHORT)(ByteLen / sizeof(WCHAR));
    if ((SIZE_T)n >= OutLen) {
        n = (USHORT)(OutLen - 1);
    }
    for (i = 0; i < n; i++) {
        WCHAR wc = W[i];
        Out[i] = (wc <= 0x7f) ? (CHAR)wc : '?';
    }
    Out[n] = 0;
}

static BOOLEAN CvIsWdFilterImageMapped(void)
{
    CV_MOD_RANGE mods[4];
    BOOLEAN wd = FALSE;
    RtlZeroMemory(mods, sizeof(mods));
    (void)CvSnapshotSecurityMods(mods, 4, &wd);
    return wd;
}

static void CvScanFilter(CV_SCAN_RESULT *R)
{
    ULONG idx;
    ULONG mini = 0;
    ULONG legacy = 0;
    ULONG total = 0;
    ULONG wdRegistered = 0;
    ULONG alt328010 = 0;
    BOOLEAN wdMapped;
    BOOLEAN enumOk = FALSE;
    BOOLEAN firstFail = FALSE;
    NTSTATUS firstSt = STATUS_SUCCESS;
    CHAR sample[96];
    CHAR ev[CV_EVIDENCE_LEN];
    UCHAR buf[CV_FLT_INFO_CB];

    sample[0] = 0;
    wdMapped = CvIsWdFilterImageMapped();

    __try {
        for (idx = 0; idx < CV_FLT_ENUM_MAX; idx++) {
            CV_FILTER_AGGREGATE_STANDARD_INFORMATION *info;
            ULONG got = 0;
            NTSTATUS st;
            const WCHAR *nameW;
            const WCHAR *altW;
            USHORT nameLen;
            USHORT altLen;
            CHAR nameA[64];
            CHAR altA[32];

            RtlZeroMemory(buf, sizeof(buf));
            st = FltEnumerateFilterInformation(
                idx,
                CV_FLT_INFO_CLASS_AGG_STD,
                buf,
                sizeof(buf),
                &got);

            if (st == STATUS_NO_MORE_ENTRIES) {
                enumOk = TRUE;
                break;
            }
            if (st == STATUS_BUFFER_TOO_SMALL && got > sizeof(buf)) {
                /* Skip oversized rare entries rather than fail the whole pass. */
                continue;
            }
            if (!NT_SUCCESS(st)) {
                if (!firstFail) {
                    firstFail = TRUE;
                    firstSt = st;
                }
                break;
            }

            enumOk = TRUE;
            total++;
            info = (CV_FILTER_AGGREGATE_STANDARD_INFORMATION *)buf;

            if (info->Flags & CV_FLTFL_ASI_IS_MINIFILTER) {
                mini++;
                nameLen = info->Type.MiniFilter.FilterNameLength;
                altLen = info->Type.MiniFilter.FilterAltitudeLength;
                nameW = (const WCHAR *)(buf + info->Type.MiniFilter.FilterNameBufferOffset);
                altW = (const WCHAR *)(buf + info->Type.MiniFilter.FilterAltitudeBufferOffset);
            } else {
                legacy++;
                nameLen = info->Type.LegacyFilter.FilterNameLength;
                altLen = info->Type.LegacyFilter.FilterAltitudeLength;
                nameW = (const WCHAR *)(buf + info->Type.LegacyFilter.FilterNameBufferOffset);
                altW = (const WCHAR *)(buf + info->Type.LegacyFilter.FilterAltitudeBufferOffset);
            }

            if ((PUCHAR)nameW < buf ||
                (PUCHAR)nameW + nameLen > buf + sizeof(buf) ||
                nameLen == 0) {
                continue;
            }
            if (!altW || altLen == 0 ||
                (PUCHAR)altW < buf ||
                (PUCHAR)altW + altLen > buf + sizeof(buf)) {
                altLen = 0;
                altW = NULL;
            }

            CvCopyWideToAnsi(nameW, nameLen, nameA, sizeof(nameA));
            altA[0] = 0;
            if (altW && altLen) {
                CvCopyWideToAnsi(altW, altLen, altA, sizeof(altA));
            }

            if (CvWideContainsAsciiI(nameW, nameLen, "WdFilter") ||
                CvNameTailMatchA(nameA, "WdFilter")) {
                wdRegistered++;
            }
            if (altA[0] && CvWideEqualsAsciiI(altW, altLen, CV_WD_FILTER_ALTITUDE)) {
                alt328010++;
            }

            if (sample[0] == 0 && nameA[0]) {
                if (altA[0]) {
                    RtlStringCbPrintfA(sample, sizeof(sample), "%s@%s", nameA, altA);
                } else {
                    RtlStringCbPrintfA(sample, sizeof(sample), "%s", nameA);
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        CvAdd(R, CvSevMedium, "filter", "T12.e",
              "FltMgr enumeration raised",
              "SEH caught during FltEnumerateFilterInformation. Filter Manager state may be unstable.",
              "FltEnumerateFilterInformation");
        return;
    }

    if (!enumOk && firstFail) {
        RtlStringCbPrintfA(ev, sizeof(ev), "status=0x%08X wdMapped=%u", (ULONG)firstSt, wdMapped ? 1u : 0u);
        CvAdd(R, CvSevMedium, "filter", "T12.e",
              "FltMgr filter enumeration failed",
              "FltEnumerateFilterInformation returned an error before any entry. Compare with fltmc filters from an elevated prompt.",
              ev);
        return;
    }

    RtlStringCbPrintfA(ev, sizeof(ev),
                       "filters=%lu mini=%lu leg=%lu wdReg=%lu alt328010=%lu wdMap=%u %s",
                       total, mini, legacy, wdRegistered, alt328010,
                       wdMapped ? 1u : 0u,
                       sample[0] ? sample : "-");

    if (wdMapped && wdRegistered == 0) {
        CvAdd(R, CvSevHigh, "filter", "T12.e",
              "WdFilter mapped but not registered with FltMgr",
              "WdFilter.sys is in PsLoadedModules yet FltEnumerateFilterInformation lists no WdFilter minifilter. Classic FudModule-class minifilter teardown (T12.e).",
              ev);
        return;
    }

    if (wdMapped && alt328010 == 0) {
        CvAdd(R, CvSevHigh, "filter", "T12.e",
              "WdFilter AV altitude 328010 missing",
              "WdFilter.sys is mapped but no minifilter advertises altitude 328010 (Defender AV FSFilter band). Possible altitude strip / teardown residue.",
              ev);
        return;
    }

    if (total == 0) {
        CvAdd(R, CvSevHigh, "filter", "T12.e",
              "No Filter Manager filters registered",
              "FltEnumerateFilterInformation returned zero entries. Healthy Win11 hosts register multiple inbox minifilters (WdFilter, FileCrypt, bindflt, ...).",
              ev);
        return;
    }

    CvAdd(R, CvSevClean, "filter", "T12.e",
          "Minifilter enumeration from FltMgr completed",
          "FltEnumerateFilterInformation walked registered filters (fltmc filters equivalent). Cross-check WdFilter registration and altitude 328010 against PsLoadedModules.",
          ev);

    if (wdMapped && wdRegistered > 0 && alt328010 > 0) {
        CHAR ev2[CV_EVIDENCE_LEN];
        RtlStringCbPrintfA(ev2, sizeof(ev2), "WdFilter registered; altitude 328010 present");
        CvAdd(R, CvSevInfo, "filter", "T12.e",
              "WdFilter minifilter present in FltMgr",
              "Mapped WdFilter.sys matches a FltMgr registration with Defender AV altitude 328010. Teardown not indicated on this pass.",
              ev2);
    }
}

static void CvScanBugcheck(CV_SCAN_RESULT *R)
{
    CvAdd(R, CvSevInfo, "bugcheck", "T12.i",
          "BugCheckReasonCallback list not walked in this build",
          "KeRegisterBugCheckReasonCallback entries are undocumented. Check for a dump-path callback whose ComponentRoutine is not in any LDR entry â€” FudModule 3.1's forensic-cleanup step.",
          "crashdmp.sys still loaded is not sufficient");
}

static void CvScanIntegrity(CV_SCAN_RESULT *R)
{
    RTL_OSVERSIONINFOW vi;
    CHAR ev[CV_EVIDENCE_LEN];

    RtlZeroMemory(&vi, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    RtlGetVersion(&vi);
    RtlStringCbPrintfA(ev, sizeof(ev), "NtBuildNumber=%lu", vi.dwBuildNumber);

    if (vi.dwBuildNumber > 0 && vi.dwBuildNumber < 26100) {
        CvAdd(R, CvSevMedium, "integrity", "T14.d",
              "Build is older than Windows 11 24H2",
              "CVE-2026-68820 targeting in the wild was 26100/26200, but AFD 0-days have a history. Verify afd.sys against the latest servicing stack from user-mode.",
              ev);
    } else {
        CvAdd(R, CvSevInfo, "integrity", "T14.d",
              "Recorded NT build for the AFD patch check",
              "User-mode must compare afd.sys FileVersion to 10.0.26100.9168 / 10.0.26200.9168 (KB5121003). A patched-but-unrebooted host is still exploitable.",
              ev);
    }
}

static void CvScanNetwork(CV_SCAN_RESULT *R)
{
    CvAdd(R, CvSevInfo, "network", "T12.b",
          "WFP callout table not enumerated here",
          "A later drop can call FwpmCalloutEnum0 from usermode (BFE). Kernel classifyFn pointers outside the owning module are T19.a / FudModule's Kaspersky WFP stage.",
          "netsh wfp show filters");
}

static void CvScanObject(CV_SCAN_RESULT *R)
{
    UNICODE_STRING name;
    PFILE_OBJECT fileObj = NULL;
    PDEVICE_OBJECT dev = NULL;

    RtlInitUnicodeString(&name, L"\\Driver\\Null");
    RtlInitUnicodeString(&name, L"\\Device\\Null");
    if (NT_SUCCESS(IoGetDeviceObjectPointer(&name, FILE_READ_DATA, &fileObj, &dev))) {
        CvAdd(R, CvSevClean, "object", "T2.e",
              "\\Device\\Null is named and reachable",
              "ObMakeTemporaryObject on a hijacked Null would make this open fail. It succeeded.",
              "IoGetDeviceObjectPointer \\Device\\Null");
        ObDereferenceObject(fileObj);
    } else {
        CvAdd(R, CvSevMedium, "object", "T12.a",
              "\\Device\\Null missing",
              "Could not open a stock Microsoft device. Possible object-directory DKOM.",
              NULL);
    }
}

static void CvScanHook(CV_SCAN_RESULT *R)
{
    UNICODE_STRING name;
    PFILE_OBJECT fileObj = NULL;
    PDEVICE_OBJECT dev = NULL;

    RtlInitUnicodeString(&name, L"\\Device\\Nsi");
    if (!NT_SUCCESS(IoGetDeviceObjectPointer(&name, FILE_READ_DATA, &fileObj, &dev)) || !dev || !dev->DriverObject) {
        CvAdd(R, CvSevInfo, "hook", "T3.c",
              "NSI device not opened",
              "Could not reference nsiproxy for a prologue check.",
              NULL);
        return;
    }
    __try {
        PDRIVER_OBJECT drv = dev->DriverObject;
        PUCHAR start = (PUCHAR)drv->DriverStart;
        PUCHAR fn = (PUCHAR)drv->MajorFunction[IRP_MJ_DEVICE_CONTROL];
        if (start && fn && (fn < start || fn >= start + drv->DriverSize)) {
            CvAdd(R, CvSevHigh, "hook", "T4.e",
                  "nsiproxy DeviceControl outside its image",
                  "Classic port-hiding hook. Cross-check sockets via TCB vs GetExtendedTcpTable.",
                  "IRP_MJ_DEVICE_CONTROL out of range");
        } else {
            CvAdd(R, CvSevClean, "hook", "T4.e",
                  "nsiproxy DeviceControl inside its image",
                  "No dispatch-level NSI hook on this path. Inline .text splices still need a disk vs memory hash from user-mode.",
                  NULL);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        CvAdd(R, CvSevMedium, "hook", "T4.e", "NSI walk faulted", NULL, NULL);
    }
    ObDereferenceObject(fileObj);
}

static void CvScanSsdt(CV_SCAN_RESULT *R)
{
    CvAdd(R, CvSevInfo, "ssdt", "T1.a",
          "SSDT not dumped (PatchGuard-sensitive)",
          "Reading KeServiceDescriptorTable is possible but version-fragile. If SSDT hooks survive on x64, PatchGuard is already dead â€” look at T12.m / T17 first. FudModule 3.1 does not hook SSDT.",
          "data-only kits skip this");
}

NTSTATUS CvRunScan(ULONG Modules, CV_SCAN_RESULT *Result, const CV_OFFSETS *Off)
{
    LARGE_INTEGER t0, t1, freq;

    RtlZeroMemory(Result, sizeof(*Result));
    Result->BuildNumber = Off->Build;
    Result->ModulesRun = Modules;
    KeQueryPerformanceCounter(&t0);

    if (Modules & CV_MOD_INTEGRITY) CvScanIntegrity(Result);
    if (Modules & CV_MOD_PROCESS)   CvScanProcess(Result, Off);
    if (Modules & CV_MOD_TOKEN)     CvScanToken(Result);
    if (Modules & CV_MOD_DRIVER)    CvScanDrivers(Result, FALSE);
    if (Modules & CV_MOD_BYOVD)     CvScanDrivers(Result, TRUE);
    if (Modules & CV_MOD_CALLBACK)  CvScanCallbacks(Result);
    if (Modules & CV_MOD_FILTER)    CvScanFilter(Result);
    if (Modules & CV_MOD_ETW)       CvScanEtw(Result);
    if (Modules & CV_MOD_HOOK)      CvScanHook(Result);
    if (Modules & CV_MOD_SSDT)      CvScanSsdt(Result);
    if (Modules & CV_MOD_IDT)       CvScanIdtMsr(Result);
    if (Modules & CV_MOD_DISPATCH)  CvScanDispatch(Result);
    if (Modules & CV_MOD_NETWORK)   CvScanNetwork(Result);
    if (Modules & CV_MOD_OBJECT)    CvScanObject(Result);
    if (Modules & CV_MOD_BUGCHECK)  CvScanBugcheck(Result);

    freq = KeQueryPerformanceCounter(&t1);
    if (freq.QuadPart) {
        Result->ElapsedMs = (ULONG)(((t1.QuadPart - t0.QuadPart) * 1000) / freq.QuadPart);
    }
    return STATUS_SUCCESS;
}

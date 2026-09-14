#include "scan.h"
#include <ntstrsafe.h>
#include <intrin.h>

/*
 * CROSSVIEW kernel scans — detection only.
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

static void CvScanCallbacks(CV_SCAN_RESULT *R)
{
    CvAdd(R, CvSevInfo, "callback", "T11.a",
          "Callback arrays require a symbol-backed pass",
          "This build of the driver does not pattern-scan PspCreateProcessNotifyRoutine (too build-fragile without PDB). Pair with the usermode ETW heartbeat and with loaded-module presence of WdFilter/EDR. Empty vendor slots while those .sys files are mapped is FudModule-class.",
          "use --fudmodule with ETW + usermode");
}

static void CvScanEtw(CV_SCAN_RESULT *R)
{
    CvAdd(R, CvSevInfo, "etw", "T15.b",
          "Kernel ETW enablement sampled from user-mode",
          "Provider EnableMask lives in EtwpHostSiloState (undocumented, silo-relative). The CLI probes the published 94-GUID FudModule kill-list from user-mode with StartTrace/EnableTrace. A silent Threat-Intelligence session plus a live host is T15.b.",
          "94-GUID list in etw-guids / cvscan --fudmodule");
}

static void CvScanFilter(CV_SCAN_RESULT *R)
{
    CvAdd(R, CvSevInfo, "filter", "T12.e",
          "Minifilter enumeration from FltMgr",
          "Link against fltmgr.lib and call FltEnumerateFilters in a later drop. For now, compare fltmc filters in usermode against altitude keys under HKLM\\SYSTEM\\CurrentControlSet\\Services. Mapped WdFilter + missing 328010 altitude is T12.e.",
          "fltmc filters");
}

static void CvScanBugcheck(CV_SCAN_RESULT *R)
{
    CvAdd(R, CvSevInfo, "bugcheck", "T12.i",
          "BugCheckReasonCallback list not walked in this build",
          "KeRegisterBugCheckReasonCallback entries are undocumented. Check for a dump-path callback whose ComponentRoutine is not in any LDR entry — FudModule 3.1's forensic-cleanup step.",
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
          "Reading KeServiceDescriptorTable is possible but version-fragile. If SSDT hooks survive on x64, PatchGuard is already dead — look at T12.m / T17 first. FudModule 3.1 does not hook SSDT.",
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

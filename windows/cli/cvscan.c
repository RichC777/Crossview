#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "version.lib")
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../shared/CrossViewShared.h"
#include <evntrace.h>
#include "etw-guids.h"
#include <fwpmu.h>
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")

static void PrintHelp(void)
{
    printf(
        "cvscan 1.0  Windows 11 x64  (CROSSVIEW)\n"
        "Detection-only. Requires SeLoadDriverPrivilege for Ring-0 modules.\n\n"
        "Usage:\n"
        "  cvscan.exe [options]\n\n"
        "Options:\n"
        "  --install          Create and start the CrossView service\n"
        "  --uninstall        Stop and delete the service\n"
        "  --quick            Process, token, callbacks, ETW, BYOVD, integrity\n"
        "  --full             Every module including SSDT, IDT, hooks, stacks\n"
        "  --fudmodule        Hunt FudModule 3.1 TTPs (default if no profile)\n"
        "  --json             Machine-readable findings on stdout\n"
        "  --quiet            Findings only, no banner\n"
        "  --no-driver        Skip kernel IOCTL (user-mode views only)\n"
        "  --out FILE         Write JSON report\n");
}

static const char *SevName(ULONG s)
{
    switch (s) {
    case CvSevCritical: return "CRITICAL";
    case CvSevHigh:     return "HIGH";
    case CvSevMedium:   return "MEDIUM";
    case CvSevLow:      return "LOW";
    case CvSevInfo:     return "INFO";
    default:            return "CLEAN";
    }
}

static int JsonEscape(FILE *f, const char *s)
{
    fputc('"', f);
    for (; s && *s; s++) {
        if (*s == '\\' || *s == '"') { fputc('\\', f); fputc(*s, f); }
        else if (*s == '\n') fputs("\\n", f);
        else fputc(*s, f);
    }
    fputc('"', f);
    return 0;
}

static BOOL InstallDriver(const char *sysPath)
{
    SC_HANDLE scm, svc;
    char full[MAX_PATH];
    DWORD n;

    n = GetFullPathNameA(sysPath, MAX_PATH, full, NULL);
    if (!n || n >= MAX_PATH) {
        fprintf(stderr, "invalid sys path\n");
        return FALSE;
    }
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        fprintf(stderr, "OpenSCManager failed %lu (admin?)\n", GetLastError());
        return FALSE;
    }
    svc = CreateServiceA(scm, "CrossView", "CROSSVIEW Kernel Integrity",
                         SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                         SERVICE_ERROR_NORMAL, full, NULL, NULL, NULL, NULL, NULL);
    if (!svc) {
        DWORD e = GetLastError();
        if (e == ERROR_SERVICE_EXISTS) {
            svc = OpenServiceA(scm, "CrossView", SERVICE_ALL_ACCESS);
        } else {
            fprintf(stderr, "CreateService failed %lu\n", e);
            CloseServiceHandle(scm);
            return FALSE;
        }
    }
    if (!StartServiceA(svc, 0, NULL)) {
        DWORD e = GetLastError();
        if (e != ERROR_SERVICE_ALREADY_RUNNING) {
            fprintf(stderr, "StartService failed %lu (test-signed? bcdedit /set testsigning on)\n", e);
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return FALSE;
        }
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    printf("driver loaded\n");
    return TRUE;
}

static BOOL UninstallDriver(void)
{
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE svc;
    SERVICE_STATUS ss;
    if (!scm) return FALSE;
    svc = OpenServiceA(scm, "CrossView", SERVICE_STOP | DELETE);
    if (!svc) { CloseServiceHandle(scm); return FALSE; }
    ControlService(svc, SERVICE_CONTROL_STOP, &ss);
    DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    printf("driver unloaded\n");
    return TRUE;
}

static HANDLE OpenDrv(void)
{
    return CreateFileA(CV_USER_DEVICE, GENERIC_READ | GENERIC_WRITE,
                       0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}


/*
 * T15.b — Probe the published FudModule v3.1 94-GUID ETW kill-list (detection-only).
 * Starts a private real-time session, EnableTraceEx2 each GUID, then disables and
 * stops the session. Does not permanently alter provider state or attack ETW.
 */
static int GuidEq(const GUID *a, const GUID *b)
{
    return IsEqualGUID(a, b);
}

static void UsermodeEtwProbe(CV_SCAN_RESULT *r)
{
    ULONG i;
    ULONG enableOk = 0, enableFail = 0, notFound = 0;
    ULONG tiStatus = (ULONG)-1, kpStatus = (ULONG)-1, saStatus = (ULONG)-1;
    ULONG startStatus, stopStatus;
    TRACEHANDLE hSession = (TRACEHANDLE)0;
    EVENT_TRACE_PROPERTIES *props = NULL;
    ULONG propsSize;
    wchar_t sessionName[] = L"CrossViewEtwT15b";
    CV_FINDING *f;
    const char *tiLabel, *sevTitle;
    ULONG sev;

    if (r->FindingCount >= CV_MAX_FINDINGS) return;

    propsSize = (ULONG)(sizeof(EVENT_TRACE_PROPERTIES) + sizeof(sessionName) + 32);
    props = (EVENT_TRACE_PROPERTIES *)calloc(1, propsSize);
    if (!props) return;

    props->Wnode.BufferSize = propsSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    props->LogFileNameOffset = 0;
    memcpy((char *)props + props->LoggerNameOffset, sessionName, sizeof(sessionName));

    startStatus = StartTraceW(&hSession, sessionName, props);
    if (startStatus == ERROR_ALREADY_EXISTS) {
        /* Orphaned probe session — stop then retry once. */
        ControlTraceW((TRACEHANDLE)0, sessionName, props, EVENT_TRACE_CONTROL_STOP);
        memset(props, 0, propsSize);
        props->Wnode.BufferSize = propsSize;
        props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props->Wnode.ClientContext = 1;
        props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        memcpy((char *)props + props->LoggerNameOffset, sessionName, sizeof(sessionName));
        startStatus = StartTraceW(&hSession, sessionName, props);
    }

    if (startStatus != ERROR_SUCCESS) {
        f = &r->Findings[r->FindingCount++];
        memset(f, 0, sizeof(*f));
        f->Severity = CvSevInfo;
        strncpy(f->Module, "etw", CV_MODULE_LEN - 1);
        strncpy(f->Technique, "T15.b", 15);
        strncpy(f->Title, "ETW kill-list probe could not start session", CV_TITLE_LEN - 1);
        _snprintf(f->Detail, CV_DETAIL_LEN - 1,
                  "StartTraceW(CrossViewEtwT15b) returned %lu. Need SeSystemProfilePrivilege / admin for a private real-time session.",
                  startStatus);
        _snprintf(f->Evidence, CV_EVIDENCE_LEN - 1, "StartTrace=%lu kill=%u", startStatus, CV_ETW_KILL_COUNT);
        free(props);
        return;
    }

    for (i = 0; i < CV_ETW_KILL_COUNT; i++) {
        ULONG st = EnableTraceEx2(hSession, &kCvEtwKillList[i],
                                  EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                  TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);
        if (GuidEq(&kCvEtwKillList[i], &kCvEtwThreatIntel)) tiStatus = st;
        if (GuidEq(&kCvEtwKillList[i], &kCvEtwKernelProcess)) kpStatus = st;
        if (GuidEq(&kCvEtwKillList[i], &kCvEtwSecAuditing)) saStatus = st;

        if (st == ERROR_SUCCESS) {
            enableOk++;
            EnableTraceEx2(hSession, &kCvEtwKillList[i],
                           EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                           0, 0, 0, 0, NULL);
        } else if (st == ERROR_WMI_GUID_NOT_FOUND) {
            notFound++;
        } else {
            enableFail++;
        }
    }

    stopStatus = ControlTraceW(hSession, sessionName, props, EVENT_TRACE_CONTROL_STOP);
    free(props);

    /* Classify results. TI EnableTrace often returns ERROR_ACCESS_DENIED (5) for
     * non-PPL consumers on clean hosts — that alone is NOT FudModule. */
    if (kpStatus == ERROR_SUCCESS &&
        tiStatus != ERROR_SUCCESS && tiStatus != (ULONG)-1 &&
        tiStatus != ERROR_ACCESS_DENIED &&
        tiStatus != ERROR_WMI_GUID_NOT_FOUND) {
        sev = CvSevHigh;
        sevTitle = "Threat-Intelligence provider enable failed on live host";
    } else if (kpStatus == ERROR_SUCCESS && tiStatus == ERROR_WMI_GUID_NOT_FOUND) {
        sev = CvSevHigh;
        sevTitle = "Threat-Intelligence provider missing on live host";
    } else if (enableFail > 8 && enableOk < 40) {
        sev = CvSevMedium;
        sevTitle = "FudModule kill-list shows widespread EnableTrace gaps";
    } else if (enableOk > 0) {
        sev = CvSevClean;
        sevTitle = "FudModule 94-GUID ETW kill-list probe completed";
    } else {
        sev = CvSevInfo;
        sevTitle = "FudModule 94-GUID ETW kill-list: no providers enableable";
    }

    if (tiStatus == ERROR_SUCCESS) tiLabel = "ti=ok";
    else if (tiStatus == ERROR_WMI_GUID_NOT_FOUND) tiLabel = "ti=absent";
    else if (tiStatus == ERROR_ACCESS_DENIED) tiLabel = "ti=denied";
    else if (tiStatus == (ULONG)-1) tiLabel = "ti=?";
    else tiLabel = "ti=FAIL";

    f = &r->Findings[r->FindingCount++];
    memset(f, 0, sizeof(*f));
    f->Severity = sev;
    strncpy(f->Module, "etw", CV_MODULE_LEN - 1);
    strncpy(f->Technique, "T15.b", 15);
    strncpy(f->Title, sevTitle, CV_TITLE_LEN - 1);
    _snprintf(f->Detail, CV_DETAIL_LEN - 1,
              "Probed %u GenDigital/Avast FudModule kill-list GUIDs via EnableTraceEx2 on a private session. "
              "enable_ok=%lu fail=%lu not_found=%lu. TI=%lu KernelProcess=%lu SecAuditing=%lu stop=%lu. Detection-only.",
              CV_ETW_KILL_COUNT, enableOk, enableFail, notFound,
              tiStatus, kpStatus, saStatus, stopStatus);
    _snprintf(f->Evidence, CV_EVIDENCE_LEN - 1,
              "kill94 ok=%lu fail=%lu nf=%lu %s kp=%lu sa=%lu",
              enableOk, enableFail, notFound, tiLabel, kpStatus, saStatus);

    if (tiStatus == ERROR_ACCESS_DENIED && r->FindingCount < CV_MAX_FINDINGS) {
        f = &r->Findings[r->FindingCount++];
        memset(f, 0, sizeof(*f));
        f->Severity = CvSevInfo;
        strncpy(f->Module, "etw", CV_MODULE_LEN - 1);
        strncpy(f->Technique, "T15.b", 15);
        strncpy(f->Title, "Threat-Intelligence EnableTrace Access Denied", CV_TITLE_LEN - 1);
        strncpy(f->Detail,
                "Microsoft-Windows-Threat-Intelligence returned ERROR_ACCESS_DENIED. "
                "Common for non-PPL consumers; not alone a FudModule 0x80 hit. Cross-check with kernel EnableMask if elevated telemetry is required.",
                CV_DETAIL_LEN - 1);
        _snprintf(f->Evidence, CV_EVIDENCE_LEN - 1, "TI={f4e1897c...} st=%lu (denied)", tiStatus);
    }

    if (sev == CvSevHigh && r->FindingCount < CV_MAX_FINDINGS) {
        f = &r->Findings[r->FindingCount++];
        memset(f, 0, sizeof(*f));
        f->Severity = CvSevHigh;
        strncpy(f->Module, "etw", CV_MODULE_LEN - 1);
        strncpy(f->Technique, "T15.b", 15);
        strncpy(f->Title, "Silent Threat-Intelligence provider (FudModule T15.b)", CV_TITLE_LEN - 1);
        _snprintf(f->Detail, CV_DETAIL_LEN - 1,
                  "Microsoft-Windows-Threat-Intelligence EnableTraceEx2 returned %lu while Kernel-Process returned %lu. "
                  "Possible FudModule 0x80 GUID-entry disablement signal.",
                  tiStatus, kpStatus);
        _snprintf(f->Evidence, CV_EVIDENCE_LEN - 1, "TI={f4e1897c...} st=%lu", tiStatus);
    }
}

/*
 * T12.b — WFP callout/filter/provider enumeration via BFE (detection-only).
 * Opens a dynamic Fwpm session, enumerates providers/callouts/filters, then
 * closes. Never adds/removes filters or callouts (no host isolation).
 * Kernel classifyFn cross-module checks remain T19.a.
 */
static void UsermodeWfpProbe(CV_SCAN_RESULT *r)
{
    HANDLE engine = NULL;
    DWORD st;
    FWPM_SESSION0 session;
    HANDLE enumH = NULL;
    FWPM_PROVIDER0 **providers = NULL;
    FWPM_CALLOUT0 **callouts = NULL;
    FWPM_FILTER0 **filters = NULL;
    UINT32 nProv = 0, nCall = 0, nFilt = 0;
    UINT32 i;
    UINT32 defProv = 0, mpsProv = 0, wdProv = 0;
    UINT32 defCall = 0, mpsCall = 0, wdCall = 0;
    CV_FINDING *f;
    ULONG sev;
    const char *sevTitle;
    char sample[96];

    if (r->FindingCount >= CV_MAX_FINDINGS) return;

    memset(&session, 0, sizeof(session));
    /* DYNAMIC: any accidental adds would evaporate on close; we never add. */
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.displayData.name = L"CrossViewWfpT12b";
    session.displayData.description = L"CROSSVIEW T12.b detection-only WFP enum";

    st = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine);
    if (st != ERROR_SUCCESS) {
        f = &r->Findings[r->FindingCount++];
        memset(f, 0, sizeof(*f));
        f->Severity = CvSevInfo;
        strncpy(f->Module, "network", CV_MODULE_LEN - 1);
        strncpy(f->Technique, "T12.b", 15);
        strncpy(f->Title, "WFP/BFE engine open failed", CV_TITLE_LEN - 1);
        _snprintf(f->Detail, CV_DETAIL_LEN - 1,
                  "FwpmEngineOpen0 returned 0x%08lX. Need admin / BFE running for "
                  "callout/filter/provider enumeration. Detection-only; no filters added.",
                  (unsigned long)st);
        _snprintf(f->Evidence, CV_EVIDENCE_LEN - 1, "FwpmEngineOpen0=0x%08lX", (unsigned long)st);
        return;
    }

    /* Providers */
    st = FwpmProviderCreateEnumHandle0(engine, NULL, &enumH);
    if (st == ERROR_SUCCESS) {
        st = FwpmProviderEnum0(engine, enumH, 4096, &providers, &nProv);
        if (st != ERROR_SUCCESS) { providers = NULL; nProv = 0; }
        FwpmProviderDestroyEnumHandle0(engine, enumH);
        enumH = NULL;
    }

    for (i = 0; i < nProv; i++) {
        const wchar_t *nm = NULL;
        if (!providers[i]) continue;
        if (providers[i]->displayData.name) nm = providers[i]->displayData.name;
        if (!nm) continue;
        /* Case-insensitive substring checks on common inbox / Defender names */
        if (wcsstr(nm, L"Defender") || wcsstr(nm, L"WdNis") || wcsstr(nm, L"Windows Defender"))
            wdProv++;
        if (wcsstr(nm, L"MPS") || wcsstr(nm, L"Windows Firewall") || wcsstr(nm, L"Base Filtering"))
            mpsProv++;
        if (wcsstr(nm, L"Microsoft") || wcsstr(nm, L"TCPIP") || wcsstr(nm, L"WFP"))
            defProv++;
    }

    /* Callouts */
    st = FwpmCalloutCreateEnumHandle0(engine, NULL, &enumH);
    if (st == ERROR_SUCCESS) {
        st = FwpmCalloutEnum0(engine, enumH, 8192, &callouts, &nCall);
        if (st != ERROR_SUCCESS) { callouts = NULL; nCall = 0; }
        FwpmCalloutDestroyEnumHandle0(engine, enumH);
        enumH = NULL;
    }

    sample[0] = '\0';
    for (i = 0; i < nCall; i++) {
        const wchar_t *nm = NULL;
        if (!callouts[i]) continue;
        if (callouts[i]->displayData.name) nm = callouts[i]->displayData.name;
        if (!nm) continue;
        if (wcsstr(nm, L"Defender") || wcsstr(nm, L"WdNis") || wcsstr(nm, L"NIS"))
            wdCall++;
        if (wcsstr(nm, L"MPS") || wcsstr(nm, L"Firewall") || wcsstr(nm, L"Ale"))
            mpsCall++;
        if (wcsstr(nm, L"Microsoft") || wcsstr(nm, L"TCP") || wcsstr(nm, L"IPSec") || wcsstr(nm, L"WFP"))
            defCall++;
        if (sample[0] == '\0' && nm[0]) {
            /* Capture one sample name (narrow, truncated) for evidence */
            int j;
            for (j = 0; j < (int)sizeof(sample) - 1 && nm[j]; j++) {
                wchar_t c = nm[j];
                sample[j] = (c < 128) ? (char)c : '?';
            }
            sample[j] = '\0';
        }
    }

    /* Filters — count only (can be large); no add/delete */
    st = FwpmFilterCreateEnumHandle0(engine, NULL, &enumH);
    if (st == ERROR_SUCCESS) {
        UINT32 batch = 0;
        UINT32 total = 0;
        for (;;) {
            FWPM_FILTER0 **batchEntries = NULL;
            st = FwpmFilterEnum0(engine, enumH, 512, &batchEntries, &batch);
            if (st != ERROR_SUCCESS || batch == 0) {
                if (batchEntries) FwpmFreeMemory0((void **)&batchEntries);
                break;
            }
            total += batch;
            FwpmFreeMemory0((void **)&batchEntries);
            if (batch < 512) break;
            /* Cap walk to avoid pathological stalls; still report cap */
            if (total >= 20000) break;
        }
        nFilt = total;
        FwpmFilterDestroyEnumHandle0(engine, enumH);
        enumH = NULL;
    }

    if (providers) FwpmFreeMemory0((void **)&providers);
    if (callouts) FwpmFreeMemory0((void **)&callouts);
    /* filters already freed per-batch */
    FwpmEngineClose0(engine);

    if (nCall == 0 && nProv == 0) {
        sev = CvSevMedium;
        sevTitle = "WFP enumeration returned empty BFE tables";
    } else if (nCall == 0) {
        sev = CvSevMedium;
        sevTitle = "WFP callout table empty while providers exist";
    } else {
        sev = CvSevClean;
        sevTitle = "WFP callout/filter/provider enumeration completed";
    }

    f = &r->Findings[r->FindingCount++];
    memset(f, 0, sizeof(*f));
    f->Severity = sev;
    strncpy(f->Module, "network", CV_MODULE_LEN - 1);
    strncpy(f->Technique, "T12.b", 15);
    strncpy(f->Title, sevTitle, CV_TITLE_LEN - 1);
    _snprintf(f->Detail, CV_DETAIL_LEN - 1,
              "BFE enum (Fwpm*Enum0, dynamic session CrossViewWfpT12b): "
              "providers=%lu callouts=%lu filters=%lu. "
              "name-hits provider(def/mps/wd)=%lu/%lu/%lu callout(def/mps/wd)=%lu/%lu/%lu. "
              "Detection-only; no filters/callouts added or removed.",
              (unsigned long)nProv, (unsigned long)nCall, (unsigned long)nFilt,
              (unsigned long)defProv, (unsigned long)mpsProv, (unsigned long)wdProv,
              (unsigned long)defCall, (unsigned long)mpsCall, (unsigned long)wdCall);
    _snprintf(f->Evidence, CV_EVIDENCE_LEN - 1,
              "prov=%lu call=%lu filt=%lu wdC=%lu sample=%s",
              (unsigned long)nProv, (unsigned long)nCall, (unsigned long)nFilt,
              (unsigned long)wdCall, sample[0] ? sample : "-");

    /* Optional INFO: Defender/NIS WFP surface visible */
    if (wdCall > 0 && r->FindingCount < CV_MAX_FINDINGS) {
        f = &r->Findings[r->FindingCount++];
        memset(f, 0, sizeof(*f));
        f->Severity = CvSevInfo;
        strncpy(f->Module, "network", CV_MODULE_LEN - 1);
        strncpy(f->Technique, "T12.b", 15);
        strncpy(f->Title, "Defender/NIS-related WFP callouts present", CV_TITLE_LEN - 1);
        _snprintf(f->Detail, CV_DETAIL_LEN - 1,
                  "At least %lu callout display name(s) matched Defender/WdNis/NIS. "
                  "Teardown not indicated on this pass. Kernel classifyFn outside owning module is T19.a.",
                  (unsigned long)wdCall);
        _snprintf(f->Evidence, CV_EVIDENCE_LEN - 1, "wdCall=%lu wdProv=%lu",
                  (unsigned long)wdCall, (unsigned long)wdProv);
    }
}

static void UsermodeIntegrity(CV_SCAN_RESULT *r)
{
    DWORD hv = 0, sz;
    UINT n;
    void *buf;
    VS_FIXEDFILEINFO *fi = NULL;
    CV_FINDING *f;
    const char *path = "C:\\Windows\\System32\\drivers\\afd.sys";

    if (r->FindingCount >= CV_MAX_FINDINGS) return;
    sz = GetFileVersionInfoSizeA(path, &hv);
    if (!sz) return;
    buf = malloc(sz);
    if (!buf) return;
    if (GetFileVersionInfoA(path, 0, sz, buf) &&
        VerQueryValueA(buf, "\\", (LPVOID *)&fi, &n) && fi) {
        DWORD verLS = fi->dwFileVersionLS;
        DWORD build = HIWORD(verLS);
        DWORD qfe = LOWORD(verLS);
        f = &r->Findings[r->FindingCount++];
        memset(f, 0, sizeof(*f));
        strncpy(f->Module, "integrity", CV_MODULE_LEN - 1);
        strncpy(f->Technique, "T14.d", 15);
        if (build < 9168) {
            f->Severity = CvSevCritical;
            strncpy(f->Title, "afd.sys older than KB5121003", CV_TITLE_LEN - 1);
            _snprintf(f->Detail, CV_DETAIL_LEN - 1,
                      "FileVersion QFE %lu < 9168. CVE-2026-68820 may still be live. Reboot after patch.", qfe);
        } else {
            f->Severity = CvSevClean;
            strncpy(f->Title, "afd.sys meets KB5121003 file version", CV_TITLE_LEN - 1);
            strncpy(f->Detail, "Still confirm the machine rebooted after the August 2026 update.", CV_DETAIL_LEN - 1);
        }
        _snprintf(f->Evidence, CV_EVIDENCE_LEN - 1, "afd.sys %lu.%lu", build, qfe);
    }
    free(buf);
}

int main(int argc, char **argv)
{
    int i;
    int doInstall = 0, doUninstall = 0, json = 0, quiet = 0, noDriver = 0;
    ULONG profile = CV_PROFILE_FUDMODULE;
    const char *outPath = NULL;
    const char *sysPath = "crossview.sys";
    HANDLE h;
    DWORD br;
    CV_SCAN_REQUEST req;
    CV_SCAN_RESULT result;
    CV_VERSION_INFO ver;
    int exitCode = 0;
    FILE *out = stdout;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) { PrintHelp(); return 0; }
        else if (!strcmp(argv[i], "--install")) doInstall = 1;
        else if (!strcmp(argv[i], "--uninstall")) doUninstall = 1;
        else if (!strcmp(argv[i], "--quick")) profile = CV_PROFILE_QUICK;
        else if (!strcmp(argv[i], "--full")) profile = CV_PROFILE_FULL;
        else if (!strcmp(argv[i], "--fudmodule")) profile = CV_PROFILE_FUDMODULE;
        else if (!strcmp(argv[i], "--json")) json = 1;
        else if (!strcmp(argv[i], "--quiet")) quiet = 1;
        else if (!strcmp(argv[i], "--no-driver")) noDriver = 1;
        else if (!strcmp(argv[i], "--out") && i + 1 < argc) outPath = argv[++i];
        else if (!strcmp(argv[i], "--sys") && i + 1 < argc) sysPath = argv[++i];
    }

    if (doInstall) return InstallDriver(sysPath) ? 0 : 2;
    if (doUninstall) return UninstallDriver() ? 0 : 2;

    memset(&result, 0, sizeof(result));
    memset(&ver, 0, sizeof(ver));

    if (!noDriver) {
        h = OpenDrv();
        if (h == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "cannot open \\\\.\\CrossView (%lu). Run --install as admin after test-signing.\n",
                    GetLastError());
            return 2;
        }
        DeviceIoControl(h, IOCTL_CV_GET_VERSION, NULL, 0, &ver, sizeof(ver), &br, NULL);
        req.Modules = profile;
        if (!DeviceIoControl(h, IOCTL_CV_RUN_SCAN, &req, sizeof(req), &req, sizeof(req), &br, NULL)) {
            fprintf(stderr, "IOCTL_CV_RUN_SCAN failed %lu\n", GetLastError());
            CloseHandle(h);
            return 2;
        }
        if (!DeviceIoControl(h, IOCTL_CV_GET_FINDINGS, NULL, 0, &result, sizeof(result), &br, NULL)) {
            fprintf(stderr, "IOCTL_CV_GET_FINDINGS failed %lu\n", GetLastError());
            CloseHandle(h);
            return 2;
        }
        CloseHandle(h);
    }

    UsermodeIntegrity(&result);
    if (profile & CV_MOD_ETW)
        UsermodeEtwProbe(&result);
    if (profile & CV_MOD_NETWORK)
        UsermodeWfpProbe(&result);

    if (outPath) {
        out = fopen(outPath, "w");
        if (!out) { fprintf(stderr, "cannot write %s\n", outPath); return 2; }
    }

    if (json || outPath) {
        ULONG k;
        fprintf(out, "{\n  \"version\": \"1.0\",\n  \"build\": %lu,\n  \"driverReady\": %u,\n  \"findings\": [\n",
                ver.NtBuildNumber, ver.DriverReady);
        for (k = 0; k < result.FindingCount; k++) {
            CV_FINDING *f = &result.Findings[k];
            fprintf(out, "    {\"severity\":");
            JsonEscape(out, SevName(f->Severity));
            fprintf(out, ",\"module\":"); JsonEscape(out, f->Module);
            fprintf(out, ",\"technique\":"); JsonEscape(out, f->Technique);
            fprintf(out, ",\"title\":"); JsonEscape(out, f->Title);
            fprintf(out, ",\"detail\":"); JsonEscape(out, f->Detail);
            fprintf(out, ",\"evidence\":"); JsonEscape(out, f->Evidence);
            fprintf(out, "}%s\n", (k + 1 < result.FindingCount) ? "," : "");
            if (f->Severity == CvSevCritical || f->Severity == CvSevHigh) exitCode = 1;
        }
        fprintf(out, "  ]\n}\n");
    } else {
        ULONG k;
        if (!quiet) {
            printf("CROSSVIEW 1.0  build %lu  driver=%s  offsets=%s\n\n",
                   ver.NtBuildNumber,
                   noDriver ? "skipped" : (ver.DriverReady ? "loaded" : "missing"),
                   ver.OffsetsResolved ? "ok" : "unresolved");
        }
        for (k = 0; k < result.FindingCount; k++) {
            CV_FINDING *f = &result.Findings[k];
            printf("[%-10s] %-8s  %-6s  %s\n", f->Module, SevName(f->Severity), f->Technique, f->Title);
            if (f->Evidence[0]) printf("             %s\n", f->Evidence);
            if (f->Severity == CvSevCritical || f->Severity == CvSevHigh) exitCode = 1;
        }
        if (!quiet) {
            printf("\n%lu findings  %lums\n", result.FindingCount, result.ElapsedMs);
        }
    }

    if (out && out != stdout) fclose(out);
    return exitCode;
}

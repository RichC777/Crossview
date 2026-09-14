#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "version.lib")
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../shared/CrossViewShared.h"

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

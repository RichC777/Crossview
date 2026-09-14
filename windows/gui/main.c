#define UNICODE
#define _UNICODE
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <commctrl.h>
#include <dwmapi.h>
#include <stdio.h>
#include "../shared/CrossViewShared.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "dwmapi.lib")

#define ID_SCAN   1001
#define ID_QUICK  1002
#define ID_FULL   1003
#define ID_FUD    1004
#define ID_LIST   1005
#define ID_STATUS 1006

static HWND g_List;
static HWND g_Status;
static ULONG g_Profile = CV_PROFILE_FUDMODULE;
static HBRUSH g_Bg;
static COLORREF COL_BG = RGB(12, 13, 15);
static COLORREF COL_FG = RGB(232, 230, 227);

static const wchar_t *SevW(ULONG s)
{
    switch (s) {
    case CvSevCritical: return L"CRITICAL";
    case CvSevHigh:     return L"HIGH";
    case CvSevMedium:   return L"MEDIUM";
    case CvSevLow:      return L"LOW";
    case CvSevInfo:     return L"INFO";
    default:            return L"CLEAN";
    }
}

static void Utf8ToWide(const char *s, wchar_t *d, int n)
{
    MultiByteToWideChar(CP_UTF8, 0, s ? s : "", -1, d, n);
    d[n - 1] = 0;
}

static void AddCol(HWND lv, int i, const wchar_t *name, int cx)
{
    LVCOLUMNW c;
    memset(&c, 0, sizeof(c));
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    c.pszText = (LPWSTR)name;
    c.cx = cx;
    c.iSubItem = i;
    ListView_InsertColumn(lv, i, &c);
}

static void RunScan(void)
{
    HANDLE h;
    DWORD br;
    CV_SCAN_REQUEST req;
    CV_SCAN_RESULT result;
    CV_VERSION_INFO ver;
    ULONG i;
    wchar_t status[256];
    wchar_t w[512];
    LVITEMW item;

    ListView_DeleteAllItems(g_List);
    h = CreateFileW(L"\\\\.\\CrossView", GENERIC_READ | GENERIC_WRITE, 0, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        SetWindowTextW(g_Status, L"Driver not loaded. Run cvscan.exe --install as admin after test-signing.");
        return;
    }
    memset(&ver, 0, sizeof(ver));
    memset(&result, 0, sizeof(result));
    DeviceIoControl(h, IOCTL_CV_GET_VERSION, NULL, 0, &ver, sizeof(ver), &br, NULL);
    req.Modules = g_Profile;
    if (!DeviceIoControl(h, IOCTL_CV_RUN_SCAN, &req, sizeof(req), &req, sizeof(req), &br, NULL) ||
        !DeviceIoControl(h, IOCTL_CV_GET_FINDINGS, NULL, 0, &result, sizeof(result), &br, NULL)) {
        SetWindowTextW(g_Status, L"IOCTL failed.");
        CloseHandle(h);
        return;
    }
    CloseHandle(h);

    for (i = 0; i < result.FindingCount; i++) {
        memset(&item, 0, sizeof(item));
        item.mask = LVIF_TEXT;
        item.iItem = (int)i;
        item.pszText = (LPWSTR)SevW(result.Findings[i].Severity);
        ListView_InsertItem(g_List, &item);
        Utf8ToWide(result.Findings[i].Module, w, 64);
        ListView_SetItemText(g_List, (int)i, 1, w);
        Utf8ToWide(result.Findings[i].Technique, w, 32);
        ListView_SetItemText(g_List, (int)i, 2, w);
        Utf8ToWide(result.Findings[i].Title, w, 240);
        ListView_SetItemText(g_List, (int)i, 3, w);
        Utf8ToWide(result.Findings[i].Evidence, w, 240);
        ListView_SetItemText(g_List, (int)i, 4, w);
    }
    _snwprintf(status, 255, L"CROSSVIEW  build %u  findings %u  %ums  offsets %s",
               ver.NtBuildNumber, result.FindingCount, result.ElapsedMs,
               ver.OffsetsResolved ? L"ok" : L"unresolved");
    SetWindowTextW(g_Status, status);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        HWND b;
        HFONT font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        b = CreateWindowW(L"BUTTON", L"Scan", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                          16, 16, 120, 36, hwnd, (HMENU)ID_SCAN, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Quick", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP,
                      152, 20, 80, 28, hwnd, (HMENU)ID_QUICK, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Full", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
                      236, 20, 70, 28, hwnd, (HMENU)ID_FULL, NULL, NULL);
        CreateWindowW(L"BUTTON", L"FudModule", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
                      310, 20, 110, 28, hwnd, (HMENU)ID_FUD, NULL, NULL);
        CheckRadioButton(hwnd, ID_QUICK, ID_FUD, ID_FUD);
        g_List = CreateWindowW(WC_LISTVIEWW, L"",
                               WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL,
                               16, 64, 900, 480, hwnd, (HMENU)ID_LIST, NULL, NULL);
        ListView_SetExtendedListViewStyle(g_List, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
        AddCol(g_List, 0, L"Severity", 90);
        AddCol(g_List, 1, L"Module", 90);
        AddCol(g_List, 2, L"ID", 70);
        AddCol(g_List, 3, L"Finding", 420);
        AddCol(g_List, 4, L"Evidence", 280);
        g_Status = CreateWindowW(L"STATIC", L"Driver idle. Scan is detection-only.",
                                 WS_CHILD | WS_VISIBLE, 16, 552, 900, 24, hwnd, (HMENU)ID_STATUS, NULL, NULL);
        SendMessageW(b, WM_SETFONT, (WPARAM)font, TRUE);
        SendMessageW(g_Status, WM_SETFONT, (WPARAM)font, TRUE);
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_SCAN: RunScan(); break;
        case ID_QUICK: g_Profile = CV_PROFILE_QUICK; break;
        case ID_FULL: g_Profile = CV_PROFILE_FULL; break;
        case ID_FUD: g_Profile = CV_PROFILE_FUDMODULE; break;
        }
        return 0;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN: {
        HDC dc = (HDC)wParam;
        SetTextColor(dc, COL_FG);
        SetBkColor(dc, COL_BG);
        return (LRESULT)g_Bg;
    }
    case WM_ERASEBKGND: {
        RECT r;
        GetClientRect(hwnd, &r);
        FillRect((HDC)wParam, &r, g_Bg);
        return 1;
    }
    case WM_SIZE: {
        RECT r;
        GetClientRect(hwnd, &r);
        if (g_List) MoveWindow(g_List, 16, 64, r.right - 32, r.bottom - 64 - 48, TRUE);
        if (g_Status) MoveWindow(g_Status, 16, r.bottom - 36, r.right - 32, 24, TRUE);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

HRESULT DwmSetWindowAttribute(HWND hwnd, DWORD dwAttribute, LPCVOID pvAttribute, DWORD cbAttribute);

HRESULT DwmSetWindowAttribute(HWND hwnd, DWORD dwAttribute, LPCVOID pvAttribute, DWORD cbAttribute);

int WINAPI wWinMain(HINSTANCE hi, HINSTANCE prev, PWSTR cmd, int show)
{
    WNDCLASSW wc;
    HWND hwnd;
    MSG msg;
    INITCOMMONCONTROLSEX icc;
    BOOL dark = TRUE;

    (void)prev; (void)cmd;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    g_Bg = CreateSolidBrush(COL_BG);
    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hi;
    wc.hbrBackground = g_Bg;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.lpszClassName = L"CrossViewWnd";
    RegisterClassW(&wc);

    hwnd = CreateWindowExW(0, L"CrossViewWnd", L"CROSSVIEW  —  kernel integrity scanner",
                           WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                           CW_USEDEFAULT, CW_USEDEFAULT, 980, 640,
                           NULL, NULL, hi, NULL);
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
    ShowWindow(hwnd, show);

    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    DeleteObject(g_Bg);
    return (int)msg.wParam;
}

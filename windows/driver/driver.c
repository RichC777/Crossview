#include <ntddk.h>
#include "offsets.h"
#include "scan.h"

/*
 * CROSSVIEW — detection-only WDM software driver for Windows 11 x64.
 * Test-sign this. Do not ship production-signed.
 *
 * Lock is a FAST_MUTEX because scans call paged APIs (ZwQuery*).
 */

static PDEVICE_OBJECT g_Device = NULL;
static CV_OFFSETS g_Offsets;
static CV_SCAN_RESULT g_LastScan;
static FAST_MUTEX g_Lock;

DRIVER_UNLOAD CvUnload;
DRIVER_DISPATCH CvCreateClose;
DRIVER_DISPATCH CvDeviceControl;
DRIVER_INITIALIZE DriverEntry;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, CvUnload)
#endif

NTSTATUS CvCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS CvDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION sl = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;
    ULONG code = sl->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = sl->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = sl->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (code) {
    case IOCTL_CV_GET_VERSION: {
        CV_VERSION_INFO vi;
        if (outLen < sizeof(vi) || !buf) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlZeroMemory(&vi, sizeof(vi));
        vi.Version = CV_VERSION;
        vi.NtBuildNumber = g_Offsets.Build;
        vi.Features = CV_PROFILE_FULL;
        vi.DriverReady = 1;
        vi.OffsetsResolved = g_Offsets.Valid ? 1 : 0;
        RtlCopyMemory(buf, &vi, sizeof(vi));
        info = sizeof(vi);
        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_CV_RUN_SCAN: {
        CV_SCAN_REQUEST req;
        ULONG mods;
        if (inLen < sizeof(CV_SCAN_REQUEST) || !buf) {
            req.Modules = CV_PROFILE_FUDMODULE;
        } else {
            RtlCopyMemory(&req, buf, sizeof(req));
        }
        mods = req.Modules ? req.Modules : CV_PROFILE_FUDMODULE;
        ExAcquireFastMutex(&g_Lock);
        status = CvRunScan(mods, &g_LastScan, &g_Offsets);
        ExReleaseFastMutex(&g_Lock);
        if (NT_SUCCESS(status) && outLen >= sizeof(ULONG) && buf) {
            *(ULONG *)buf = g_LastScan.FindingCount;
            info = sizeof(ULONG);
        }
        break;
    }
    case IOCTL_CV_GET_FINDINGS: {
        ULONG copy;
        if (!buf || outLen < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        ExAcquireFastMutex(&g_Lock);
        copy = sizeof(CV_SCAN_RESULT);
        if (copy > outLen) {
            copy = outLen;
        }
        RtlCopyMemory(buf, &g_LastScan, copy);
        ExReleaseFastMutex(&g_Lock);
        info = copy;
        status = STATUS_SUCCESS;
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID CvUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING link;
    PAGED_CODE();
    RtlInitUnicodeString(&link, CV_SYMLINK_NAME);
    IoDeleteSymbolicLink(&link);
    if (g_Device) {
        IoDeleteDevice(g_Device);
        g_Device = NULL;
    }
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING devName;
    UNICODE_STRING linkName;
    NTSTATUS st;

    UNREFERENCED_PARAMETER(RegistryPath);

    ExInitializeFastMutex(&g_Lock);
    RtlZeroMemory(&g_LastScan, sizeof(g_LastScan));
    CvResolveOffsets(&g_Offsets);

    RtlInitUnicodeString(&devName, CV_DEVICE_NAME);
    st = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_Device);
    if (!NT_SUCCESS(st)) {
        return st;
    }

    RtlInitUnicodeString(&linkName, CV_SYMLINK_NAME);
    st = IoCreateSymbolicLink(&linkName, &devName);
    if (!NT_SUCCESS(st)) {
        IoDeleteDevice(g_Device);
        g_Device = NULL;
        return st;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CvCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CvCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CvDeviceControl;
    DriverObject->DriverUnload = CvUnload;

    g_Device->Flags |= DO_BUFFERED_IO;
    g_Device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

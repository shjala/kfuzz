/*
 * Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
 * All rights reserved.
 */

#include "kflog.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, KflogDeviceCreate)
#pragma alloc_text(PAGE, KflogDeviceClose)
#pragma alloc_text(PAGE, KflogDeviceCleanUp)
#pragma alloc_text(PAGE, KflogUnload)
#endif

KSPIN_LOCK           _g_MemoryTrackingHashTableLock;
KSPIN_LOCK           _g_BblTrackingHashTableLock;
PAGED_LOOKASIDE_LIST _g_KernelPatchListPool;
PLOOKASIDE_LIST_EX   _g_BblTrackingEntriesPool;
LIST_ENTRY           _g_KernelPatchRecordList;
KT_CAPTURE           _g_KtCaptures;
FOCUS_BBL_LIST       _g_FocusBblList             = { NULL, 0 };
PCHAR                _g_EdgeTransitionMap        = NULL;
PHASH_TABLE          _g_MemTrackingHashTable     = NULL;
PHASH_TABLE          _g_BblTrackingHashTable     = NULL;
ULONG                _g_NewEdgesCounter          = 0;
HANDLE               _g_UsermodeTracerPid        = (HANDLE)-1;
ULONG                _g_TraceStatus              = TRACE_NONE;
ULONG                _g_TraceIRQL                = DISPATCH_LEVEL;
PMDL                 _g_EdgeTransitionMapMdl     = NULL;

NTSTATUS
InitMemoryPools(
    VOID
    ) 
{
    NTSTATUS Status;

    InitializeListHead(&_g_KernelPatchRecordList);
    ExInitializePagedLookasideList(&_g_KernelPatchListPool,
        NULL,
        NULL,
        0,
        sizeof(PATCH_RECORD_LIST),
        KFLOG_POOL_KPATCH_TAG,
        0);

    _g_BblTrackingEntriesPool = (PLOOKASIDE_LIST_EX)ExAllocatePoolWithTag(NonPagedPool,
        sizeof(LOOKASIDE_LIST_EX),
        KFLOG_POOL_BT_TAG);

    if (_g_BblTrackingEntriesPool == NULL) {

        DoTraceMessage("Failed to allocate NonPagedPool memory for bbl-tracking entries lookaside!\n");

        ExDeletePagedLookasideList(&_g_KernelPatchListPool);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = ExInitializeLookasideListEx(_g_BblTrackingEntriesPool,
        NULL,
        NULL,
        NonPagedPool,
        0,
        sizeof(BBL_TRACKING_ENTRY),
        KFLOG_POOL_BT_TAG,
        0);

    if (!NT_SUCCESS(Status)) {

        ExDeletePagedLookasideList(&_g_KernelPatchListPool);
        ExFreePoolWithTag(_g_BblTrackingEntriesPool, KFLOG_POOL_BT_TAG);

        return Status;
    }

    return STATUS_SUCCESS;
}


VOID
FreeRecordToBblTrackingPool(
    _In_ PVOID Context
    )
{
    ExFreeToLookasideListEx(_g_BblTrackingEntriesPool, Context);
}


VOID
FreeRecordsOfMemTracking(
    _In_ PVOID Context
    )
{
    ExFreePoolWithTag(Context, KFLOG_POOL_MT_TAG);
}


VOID
FreeMemoryPools(
    VOID
    )
{
    ApplyOnHashTableRecords(_g_BblTrackingHashTable, FreeRecordToBblTrackingPool);
    ExDeleteLookasideListEx(_g_BblTrackingEntriesPool);
    ExFreePoolWithTag(_g_BblTrackingEntriesPool, KFLOG_POOL_BT_TAG);

    ApplyOnHashTableRecords(_g_MemTrackingHashTable, FreeRecordsOfMemTracking);

    ExDeletePagedLookasideList(&_g_KernelPatchListPool);
}


NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject, 
    _In_ PUNICODE_STRING RegistryPath
    )
{
    UNICODE_STRING DeviceName, Win32Device;
    PDEVICE_OBJECT DeviceObject = NULL;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(RegistryPath);
    PAGED_CODE();

    RtlInitUnicodeString(&DeviceName, L"\\Device\\kflog");
    RtlInitUnicodeString(&Win32Device, L"\\DosDevices\\kflog");

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = KflogDeviceCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = KflogDeviceClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = KflogDeviceCleanUp;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KflogDeviceDispatch;
    DriverObject->DriverUnload                         = KflogUnload;

    Status = IoCreateDevice(DriverObject,
        0,
        &DeviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &DeviceObject);

    if (!NT_SUCCESS(Status))
        return Status;

    if (!DeviceObject)
        return STATUS_UNEXPECTED_IO_ERROR;

    DeviceObject->Flags |= DO_DIRECT_IO;
    DeviceObject->AlignmentRequirement = FILE_WORD_ALIGNMENT;
    Status = IoCreateSymbolicLink(&Win32Device, &DeviceName);
    if (!NT_SUCCESS(Status)) {

        IoDeleteDevice(DriverObject->DeviceObject);

        return Status;
    }

    Status = InitMemoryPools();
    if (!NT_SUCCESS(Status)) {

        
        IoDeleteSymbolicLink(&Win32Device);
        IoDeleteDevice(DriverObject->DeviceObject);

        return Status;
    }

    Status = InitTraceWorkerThreads();
    if (!NT_SUCCESS(Status)) {

        FreeMemoryPools();
        IoDeleteSymbolicLink(&Win32Device);
        IoDeleteDevice(DriverObject->DeviceObject);

        return Status;
    }

#if defined(__ALLOC_EMAP_SYS_MEM)
    PHYSICAL_ADDRESS LowAddress;
    PHYSICAL_ADDRESS HighAddress;

    LowAddress.QuadPart = 0;
    HighAddress.QuadPart = (ULONGLONG)-1;

    _g_EdgeTransitionMapMdl = MmAllocatePagesForMdl(LowAddress, HighAddress, LowAddress, EDGE_TRANS_MAP_SIZE);
    if (_g_EdgeTransitionMapMdl == NULL) {

        DoTraceMessage("Failed to allocate MDL for edge-transition map!\n");

        ExDeletePagedLookasideList(&_g_KernelPatchListPool);
        ExDeleteLookasideListEx(_g_MemTrackingEntriesPool);
        ExFreePoolWithTag(_g_MemTrackingEntriesPool, KFLOG_POOL_MT_TAG);
        
        IoDeleteSymbolicLink(&Win32Device);
        IoDeleteDevice(DriverObject->DeviceObject);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    _g_EdgeTransitionMap = (PCHAR)MmGetSystemAddressForMdlSafe(_g_EdgeTransitionMapMdl, HighPagePriority);
    if (_g_EdgeTransitionMap == NULL) {

        DoTraceMessage(FALSE, "Failed to map edge-transition map to kernel!\n");

        MmFreePagesFromMdl(_g_EdgeTransitionMapMdl);
        ExFreePool(_g_EdgeTransitionMapMdl);

        ExDeletePagedLookasideList(&_g_KernelPatchListPool);
        ExDeleteLookasideListEx(_g_MemTrackingEntriesPool);
        ExFreePoolWithTag(_g_MemTrackingEntriesPool, KFLOG_POOL_MT_TAG);

        IoDeleteSymbolicLink(&Win32Device);
        IoDeleteDevice(DriverObject->DeviceObject);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(_g_EdgeTransitionMap, EDGE_TRANS_MAP_SIZE);

    DoTraceMessage("Successfully allocated and mapped edge-transition map to kernel at 0x%p\n", 
        _g_EdgeTransitionMap);
#else
    _g_EdgeTransitionMap = (PCHAR)ExAllocatePoolWithTag(NonPagedPool,
        EDGE_TRANS_MAP_SIZE_64M,
        KFLOG_POOL_EDGE_MAP_TAG);

    if (_g_EdgeTransitionMap == NULL) {

        DoTraceMessage("Failed to allocate NonPagedPool memory for edge-transition map!\n");

        FreeMemoryPools();

        IoDeleteSymbolicLink(&Win32Device);
        IoDeleteDevice(DriverObject->DeviceObject);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DoTraceMessage("Successfully allocated edge-transition map at 0x%p\n", _g_EdgeTransitionMap);

    RtlZeroMemory(_g_EdgeTransitionMap, EDGE_TRANS_MAP_SIZE_64M);
    RtlZeroMemory(&_g_KtCaptures, sizeof(KT_CAPTURE));
#endif

    _g_MemTrackingHashTable = AllocateHashTable(HASH_TABALE_SIZE);
    if (_g_MemTrackingHashTable == NULL) {

        DoTraceMessage("Failed to allocate NonPagedPool memory for mem-tracking hash-table!\n");

#if defined(__ALLOC_EMAP_SYS_MEM)
        MmUnmapLockedPages(_g_EdgeTransitionMap, _g_EdgeTransitionMapMdl);

        MmFreePagesFromMdl(_g_EdgeTransitionMapMdl);
        ExFreePool(_g_EdgeTransitionMapMdl);
#else
        ExFreePoolWithTag(_g_EdgeTransitionMap, KFLOG_POOL_EDGE_MAP_TAG);
#endif

        FreeMemoryPools();

        IoDeleteSymbolicLink(&Win32Device);
        IoDeleteDevice(DriverObject->DeviceObject);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DoTraceMessage("Successfully allocated mem-tracking hash-table at 0x%p\n", _g_MemTrackingHashTable);


    _g_BblTrackingHashTable = AllocateHashTable(HASH_TABALE_SIZE);
    if (_g_BblTrackingHashTable == NULL) {

        DoTraceMessage("Failed to allocate NonPagedPool memory for bbl-tracking hash-table!\n");

#if defined(__ALLOC_EMAP_SYS_MEM)
        MmUnmapLockedPages(_g_EdgeTransitionMap, _g_EdgeTransitionMapMdl);

        MmFreePagesFromMdl(_g_EdgeTransitionMapMdl);
        ExFreePool(_g_EdgeTransitionMapMdl);
#else
        ExFreePoolWithTag(_g_EdgeTransitionMap, KFLOG_POOL_EDGE_MAP_TAG);
#endif

        FreeMemoryPools();
        FreeHashTable(_g_MemTrackingHashTable);

        IoDeleteSymbolicLink(&Win32Device);
        IoDeleteDevice(DriverObject->DeviceObject);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DoTraceMessage("Successfully allocated bbl-tracking hash-table at 0x%p\n", _g_BblTrackingHashTable);

    KeInitializeSpinLock(&_g_MemoryTrackingHashTableLock);
    KeInitializeSpinLock(&_g_BblTrackingHashTableLock);

    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}


VOID
KflogUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNICODE_STRING Win32Device;
    PAGED_CODE();

    RestoreKernelPatches();

    FreeMemoryPools();
    FreeHashTable(_g_MemTrackingHashTable);
    FreeHashTable(_g_BblTrackingHashTable);

    ReleaseAllFocusEvents();
    FreeTraceWorkerThreads();

#if defined(__ALLOC_EMAP_SYS_MEM)
    MmUnmapLockedPages(_g_EdgeTransitionMap, _g_EdgeTransitionMapMdl);

    MmFreePagesFromMdl(_g_EdgeTransitionMapMdl);
    ExFreePool(_g_EdgeTransitionMapMdl);
#else
    ExFreePoolWithTag(_g_EdgeTransitionMap, KFLOG_POOL_EDGE_MAP_TAG);
#endif

#ifdef __DEBUG_ECOV
    DumpCoverageInfoToFile();
#endif

    RtlInitUnicodeString(&Win32Device,L"\\DosDevices\\kflog");
    IoDeleteSymbolicLink(&Win32Device);
    IoDeleteDevice(DriverObject->DeviceObject);

    DoTraceMessage("KFLOG Unloaded successfully.\n");
}


NTSTATUS
KflogDeviceCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


NTSTATUS
KflogDeviceClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


NTSTATUS
KflogDeviceCleanUp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    _g_UsermodeTracerPid = 0;
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;
  
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


NTSTATUS
KflogDeviceDispatch(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
    )
{
    PIO_STACK_LOCATION pIoStackLocation;
    PBASICBLOCK_ADDR_INFO pBasicblock;
    PMEM_TRACKING_APIS_INFO MemTraackingAPIsInfo;
    PFOCUS_BBL_ENTRY pFocusEntry;
    ULONG IoCtlCode;
    ULONG InputBufferLen;
    ULONG OutputBufferLen;
    ULONG PatchCount;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    Irp->IoStatus.Information = 0;
    pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    IoCtlCode = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode; 
    OutputBufferLen = pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
    InputBufferLen = pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength; 

    
    switch (IoCtlCode) {

    case KFL_IOCTL_SET_FOCUS_BBL_EVENT:
        if (InputBufferLen < sizeof(FOCUS_BBL_ENTRY)) {

            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (_g_FocusBblList.Entries == NULL) {

            _g_FocusBblList.Entries = (PKERNEL_FOCUS_BBL_ENTRY)ExAllocatePoolWithTag(NonPagedPool,
                sizeof(KERNEL_FOCUS_BBL_ENTRY) * MAX_FOCUS_BBL,
                KFLOG_POOL_BT_TAG);

            if (_g_FocusBblList.Entries == NULL) {

                DoTraceMessage("Failed to allocate NonPagedPool memory for bbl-tracking focus list!\n");

                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
            else {

                RtlZeroMemory(_g_FocusBblList.Entries, sizeof(KERNEL_FOCUS_BBL_ENTRY) * MAX_FOCUS_BBL);
            }
        }

        pFocusEntry = (PFOCUS_BBL_ENTRY)Irp->AssociatedIrp.SystemBuffer;
        Status = RegisterFocusBlockEvent(pFocusEntry);

        break;

    case KFL_IOCTL_BBL_INSERT_PROBE:
        if (InputBufferLen < sizeof(BASICBLOCK_ADDR_INFO)) {

            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        pBasicblock = (PBASICBLOCK_ADDR_INFO)Irp->AssociatedIrp.SystemBuffer;
        if (IsAddressPatched((PVOID)pBasicblock->Address) == TRUE) {

            DoTraceMessage("Basic-block is already patched!\n");

            Status = STATUS_SUCCESS;
        }
        else {

            Status = InsertEgdeTransitionProbeOnBasicBlock(pBasicblock->Address,
                pBasicblock->Length,
                pBasicblock->CopyLength,
                pBasicblock->IsFocusBlock);
        }

        DoTraceMessage("%s to insert probe on : %s!0x%p (Length:%d, CopyLength:%d)\n",
            NT_SUCCESS(Status) ? "Succeeded" : "Failed",
            pBasicblock->ImageName,
            pBasicblock->Address,
            pBasicblock->Length,
            pBasicblock->CopyLength);

        break;

    case KFL_IOCTL_BBL_LIST_INSERT_PROBE:
        if (InputBufferLen < sizeof(BASICBLOCK_ADDR_INFO) || OutputBufferLen < sizeof(ULONG)) {

            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        pBasicblock = (PBASICBLOCK_ADDR_INFO)Irp->AssociatedIrp.SystemBuffer;
        PatchCount = InsertEgdeTransitionProbeOnBasicBlockList(pBasicblock, InputBufferLen);

        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &PatchCount, sizeof(ULONG));
        Irp->IoStatus.Information = sizeof(ULONG);

        Status = STATUS_SUCCESS;
        break;


    case KFL_IOCTL_SET_CAPTURE_STATUS:
        if (InputBufferLen < sizeof(KT_CAPTURE)) {

            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        RtlCopyMemory(&_g_KtCaptures, Irp->AssociatedIrp.SystemBuffer, sizeof(KT_CAPTURE));
        Status = STATUS_SUCCESS;
        break;

    case KFL_IOCTL_GET_CAPTURE_STATUS:
        if (OutputBufferLen < sizeof(KT_CAPTURE)) {

            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer , &_g_KtCaptures, sizeof(KT_CAPTURE));
        Irp->IoStatus.Information = sizeof(KT_CAPTURE);

        Status = STATUS_SUCCESS;
        break;

    case KFL_IOCTL_SET_TRACER_PID:
        if (InputBufferLen < sizeof(ULONG)) {

            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        RtlCopyMemory(&_g_UsermodeTracerPid, Irp->AssociatedIrp.SystemBuffer, sizeof(ULONG));

        DoTraceMessage("Succeeded to set user-mode tracer PID to %d\n", _g_UsermodeTracerPid);

        Status = STATUS_SUCCESS;
        break;

    case KFL_IOCTL_SET_TRACE_STATUS:
        if (InputBufferLen < sizeof(ULONG)) {

            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        RtlCopyMemory(&_g_TraceStatus, Irp->AssociatedIrp.SystemBuffer, sizeof(ULONG));

        DoTraceMessage("Succeeded to set trace status %d\n", _g_TraceIRQL);

        Status = STATUS_SUCCESS;
        break;


    case KFL_IOCTL_SET_TRACE_IRQL:
        if (InputBufferLen < sizeof(ULONG)) {

            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        RtlCopyMemory(&_g_TraceIRQL, Irp->AssociatedIrp.SystemBuffer, sizeof(ULONG));

        DoTraceMessage("Succeeded to set trace IRQL %d\n", _g_TraceIRQL);

        Status = STATUS_SUCCESS;
        break;

    case KFL_IOCTL_RESET_EDGE_TRANS_MAP:
        RtlZeroMemory(_g_EdgeTransitionMap, EDGE_TRANS_MAP_SIZE_64M);

        DoTraceMessage("Succeeded to zeroed-out edge-transition map contents.\n");

        Status = STATUS_SUCCESS;
        break;

    case KFL_IOCTL_ENABLE_MEMORY_TRACKING:
        if (InputBufferLen < sizeof(MEM_TRACKING_APIS_INFO)) {

            Status = STATUS_INVALID_PARAMETER;
            break;
        }

        MemTraackingAPIsInfo = (PMEM_TRACKING_APIS_INFO)Irp->AssociatedIrp.SystemBuffer;
        EnableMemoryTracking(MemTraackingAPIsInfo, InputBufferLen/sizeof(MEM_TRACKING_APIS_INFO));

        Status = STATUS_SUCCESS;
        break;

    case KFL_IOCTL_GET_BBL_COV_CAPTURES:
        if (OutputBufferLen < sizeof(ULONG)) {

            Status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        Status = CopyBlockCoverageInfo(Irp->AssociatedIrp.SystemBuffer, &OutputBufferLen);
        if (NT_SUCCESS(Status)) {

            Irp->IoStatus.Information = OutputBufferLen;
        }
        else if (Status == STATUS_INVALID_BUFFER_SIZE) {

            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &OutputBufferLen, sizeof(ULONG));
            Irp->IoStatus.Information = sizeof(ULONG);

            Status = STATUS_SUCCESS;
        }

        break;

    default:

        DoTraceMessage("Error, dispatch routine eeceived an invalid IO request...\n");
        break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}
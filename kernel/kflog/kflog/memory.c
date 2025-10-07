/*
 * Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
 * All rights reserved.
 */

#include "kflog.h"

extern KT_CAPTURE         _g_KtCaptures;
extern PHASH_TABLE        _g_MemTrackingHashTable;
extern KSPIN_LOCK         _g_MemoryTrackingHashTableLock;

/*
Verifier Pool Thunk (_VfPoolThunks) and more:
    Alloc:
        ExAllocateCacheAwareRundownProtection           -> ExAllocatePoolWithTag
        ExAllocatePool                                  -> ExpAllocatePoolWithTagFromNode (Internal, non-export)
        ExAllocatePoolWithTag                           -> ExpAllocatePoolWithTagFromNode (Internal, non-export)
        ExAllocatePoolWithTagPriority                   -> ExpAllocatePoolWithTagFromNode (Internal, non-export)
        ExAllocatePoolWithQuota                         -> ExAllocatePoolWithQuotaTag
        ExAllocatePoolWithQuotaTag                      -> ExAllocatePoolWithTag
        IoAllocateMdl                                   -> ExAllocatePoolWithTag
        IoAllocateErrorLogEntry                         -> ExAllocatePoolWithTag
        RtlDuplicateUnicodeString                       -> ExAllocatePoolWithTag
        RtlCreateUnicodeString                          -> ExAllocatePoolWithTag
        RtlCreateUnicodeString                          -> ExAllocatePoolWithTag
        RtlDuplicateUnicodeString                       -> ExAllocatePoolWithTag
        RtlAnsiStringToUnicodeString                    -> ExAllocatePoolWithTag
        RtlUnicodeStringToAnsiString                    -> ExAllocatePoolWithTag
        RtlUpcaseUnicodeStringToAnsiString              -> ExAllocatePoolWithTag
        RtlOemStringToUnicodeString                     -> ExAllocatePoolWithTag
        RtlUnicodeStringToOemString                     -> ExAllocatePoolWithTag
        RtlUpcaseUnicodeStringToOemString               -> ExAllocatePoolWithTag
        RtlOemStringToCountedUnicodeString              -> ExAllocatePoolWithTag
        RtlUnicodeStringToCountedOemString              -> ExAllocatePoolWithTag
        RtlUpcaseUnicodeStringToCountedOemString        -> ExAllocatePoolWithTag
        RtlUpcaseUnicodeString                          -> ExAllocatePoolWithTag
        RtlDowncaseUnicodeString                        -> ExAllocatePoolWithTag
        ExInitializePagedLookasideList                  -> ExAllocatePoolWithTag (called by ExAllocateFromPagedLookasideList)
        ZwAllocateVirtualMemory                         -> NtAllocateVirtualMemory
        IoAllocateMdl                                   -> ExAllocatePoolWithTag

    Free:
        ExFreePool                                      -> ExFreePoolWithTag
        ExFreePoolWithTag                               -> _ExFreeHeapPool (Internal, non-export)
        IoFreeMdl                                       -> ExFreePoolWithTag

    Patch:
        NtAllocateVirtualMemory
        ZwAllocateVirtualMemory

        ExAllocatePool
        ExAllocatePoolWithTag
        ExAllocatePoolWithTagPriority

        ExFreePoolWithTag

        NtFreeVirtualMemory
        ZwFreeVirtualMemory

Note : In case, check out RtlEnoughStackSpaceForStackCapture, 
ViPoolLogStackTrace, MmReplaceImportEntry and KsepPatchImportTableEntry.
*/

NTSTATUS
RecordAndReportMemoryAllocation(
    _In_ PVOID Address,
    _In_ ULONG Size
    ) 
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PMEM_TRACKING_ENRTY MemEntry;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        return STATUS_INVALID_LEVEL;

    KeAcquireInStackQueuedSpinLock(&_g_MemoryTrackingHashTableLock, &LockHandle);

    MemEntry = (PMEM_TRACKING_ENRTY)ExAllocatePoolWithTag(NonPagedPool, 
        sizeof(MEM_TRACKING_ENRTY),
        KFLOG_POOL_MT_TAG);

    if (MemEntry != NULL) {

        MemEntry->Address = Address;
        MemEntry->Size = Size;

        Status = AddRecordToHashTable(_g_MemTrackingHashTable,
            MemEntry, (ULONG)MemEntry->Address);

        if (NT_SUCCESS(Status)){

            if (_g_KtCaptures.Counters.Memory.Record)
                _g_KtCaptures.Counters.Memory.AllocCounter += MemEntry->Size;
        }
        else {

            ExFreePoolWithTag(MemEntry, KFLOG_POOL_MT_TAG);
        }
    }

    KeReleaseInStackQueuedSpinLock(&LockHandle);

    return Status;
}


NTSTATUS
RecordAndReportMemoryDeallocation(
    _In_ PVOID Address
    )
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PMEM_TRACKING_ENRTY MemEntry;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        return STATUS_INVALID_LEVEL;

    KeAcquireInStackQueuedSpinLock(&_g_MemoryTrackingHashTableLock, &LockHandle);

    MemEntry = (PMEM_TRACKING_ENRTY)GetRecordFromHashTable(_g_MemTrackingHashTable, 
        (ULONG)Address);

    if (MemEntry != NULL) {

        if (_g_KtCaptures.Counters.Memory.Record)
            _g_KtCaptures.Counters.Memory.FreeCounter += MemEntry->Size;

        Status = RemoveRecordFromHashTable(_g_MemTrackingHashTable, (ULONG)Address);
        ExFreePoolWithTag(MemEntry, KFLOG_POOL_MT_TAG);
    }

    KeReleaseInStackQueuedSpinLock(&LockHandle);

    return Status;
}


NTSTATUS
NTAPI
InstrumentOnNtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
    )
{
    NTSTATUS Status = NtAllocateVirtualMemory(ProcessHandle,
        BaseAddress,
        ZeroBits,
        RegionSize,
        AllocationType,
        Protect);
    
    if (NT_SUCCESS(Status))
        RecordAndReportMemoryAllocation(*BaseAddress, *RegionSize);

    return Status;
}


PVOID
NTAPI
InstrumentOnExAllocatePool(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes
    ) 
{
    PVOID Return = ExAllocatePool(PoolType, 
        NumberOfBytes);

    if (Return)
        RecordAndReportMemoryAllocation(Return, NumberOfBytes);

    return Return;
}


PVOID
NTAPI
InstrumentOnExAllocatePoolWithTag(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
    )
{
    PVOID Return = ExAllocatePoolWithTag(PoolType, 
        NumberOfBytes, 
        Tag);

    if (Return)
        RecordAndReportMemoryAllocation(Return, NumberOfBytes);

    return Return;
}


PVOID
NTAPI
InstrumentOnExAllocatePoolWithTagPriority(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag,
    _In_ EX_POOL_PRIORITY Priority
    )
{
    PVOID Return = ExAllocatePoolWithTagPriority(PoolType, 
        NumberOfBytes, 
        Tag, 
        Priority);

    if (Return)
        RecordAndReportMemoryAllocation(Return, NumberOfBytes);

    return Return;
}


VOID
InstrumentOnExFreePoolWithTag(
    _Pre_notnull_ PVOID P,
    _In_ ULONG Tag
    )
{
    RecordAndReportMemoryDeallocation(P);

    ExFreePoolWithTag(P, Tag);
}


NTSTATUS
NTAPI
InstrumentOnNtFreeVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
    )
{
    RecordAndReportMemoryDeallocation(*BaseAddress);

    NTSTATUS Status = NtFreeVirtualMemory(ProcessHandle,
        BaseAddress,
        RegionSize,
        FreeType);

    return Status;
}


PVOID 
GetImportAddress(
    _In_ PMEM_TRACKING_APIS_INFO APIsInfo,
    _In_ ULONG Length,
    _In_ PCSTR Target
    )
{
    for (ULONG i = 0; i < Length; i++) {

        if (strcmp(APIsInfo[i].Name, Target) == 0)
            return APIsInfo[i].IATAddress;
    }

    return NULL;
}


VOID
EnableMemoryTracking(
    _In_ PMEM_TRACKING_APIS_INFO APIsInfo,
    _In_ ULONG Length
    )
{
    PVOID Address = 0;
    PVOID Replacement;
    ULONG OriginalAddress;
    NTSTATUS Status;
    
    MEM_TRACKING_API_HOOKS TARGET_APIS[] = { 
        {"NtAllocateVirtualMemory",         (PVOID)InstrumentOnNtAllocateVirtualMemory},
        {"ZwAllocateVirtualMemory",         (PVOID)InstrumentOnNtAllocateVirtualMemory},
        {"ExAllocatePool",                  (PVOID)InstrumentOnExAllocatePool},
        {"ExAllocatePoolWithTag",           (PVOID)InstrumentOnExAllocatePoolWithTag},
        {"ExAllocatePoolWithTagPriority",   (PVOID)InstrumentOnExAllocatePoolWithTagPriority},
        {"ExFreePoolWithTag",               (PVOID)InstrumentOnExFreePoolWithTag},
        {"NtFreeVirtualMemory",             (PVOID)InstrumentOnNtFreeVirtualMemory},
        {"ZwFreeVirtualMemory",             (PVOID)InstrumentOnNtFreeVirtualMemory}
    };

    for (ULONG i = 0; i < _countof(TARGET_APIS); i++) {

        Address = GetImportAddress(APIsInfo, Length, TARGET_APIS[i].Name);
        if (Address != NULL) {
            /* TODO : get patch record, check address*/
            if (IsAddressPatched(Address) == TRUE) {
                DoTraceMessage("Target API  %s (0x%p) is already patched!\n",
                    TARGET_APIS[i].Name, Address);

                continue;
            }
            
            Replacement = TARGET_APIS[i].Replacement;
            Status = RewriteKernelAddress(Address,
                &Replacement,
                sizeof(PVOID),
                (PVOID)&OriginalAddress);

            if (!NT_SUCCESS(Status)) {

                DoTraceMessage("Failed to insert memory-tracking probe at %s (0x%p)\n",
                    TARGET_APIS[i].Name, Address);
            }
            else {

                DoTraceMessage("Target API  %s (0x%p) is successfully patched!\n",
                    TARGET_APIS[i].Name, Address);

                AddPatchRecordToList(Address, sizeof(PVOID), NULL, &OriginalAddress);
            }
        }
    }
    
}

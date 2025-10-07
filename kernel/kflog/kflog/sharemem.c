/*
 * Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
 * All rights reserved.
 */

#include "kflog.h"

extern SHARED_MEMORY _g_KernelUserSharedCounters;


NTSTATUS
InitialiseSharedMemory(
    _In_ PSHARED_MEMORY SharedMem, 
    _In_ ULONG Length
    )
{
    PHYSICAL_ADDRESS LowAddress;
    PHYSICAL_ADDRESS HighAddress;

    LowAddress.QuadPart  = 0;
    HighAddress.QuadPart = (ULONGLONG)-1;

    SharedMem->SharedMdl = MmAllocatePagesForMdl(LowAddress, HighAddress, LowAddress, Length);
    if (SharedMem->SharedMdl == NULL) {

        DoTraceMessage("Failed to allocare MDL for shared-memory!\n");

        return STATUS_INSUFFICIENT_RESOURCES;
    }
        
    SharedMem->KernelAddress = MmGetSystemAddressForMdlSafe(SharedMem->SharedMdl, NormalPagePriority);
    if (SharedMem->KernelAddress == NULL) {
    
        MmFreePagesFromMdl(SharedMem->SharedMdl);
        ExFreePool(SharedMem->SharedMdl);

        DoTraceMessage("Failed to get system-address of shared-memory!\n");
    
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DoTraceMessage("Successfully mapped shared-memory into kernel at 0x%p\n", 
        SharedMem->KernelAddress);

    return STATUS_SUCCESS;
}


NTSTATUS
MapSharedMemoryToUsermode(
    _In_ PSHARED_MEMORY SharedMem
    )
{
    if (SharedMem->SharedMdl != NULL) {

        try {

            SharedMem->UserAddress = MmMapLockedPagesSpecifyCache(SharedMem->SharedMdl, 
                UserMode,
                MmCached, 
                NULL, 
                FALSE, 
                HighPagePriority);

            if (SharedMem->UserAddress == NULL)
                return STATUS_INSUFFICIENT_RESOURCES;

        } except (EXCEPTION_EXECUTE_HANDLER) {

            DoTraceMessage("Failed to map shared-memory into user-mode PID (%d), Exception : 0x%.8x\n",
                SharedMem->UserProcessId, GetExceptionCode());

            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SharedMem->UserProcessId = (ULONG)PsGetCurrentProcessId();

        DoTraceMessage("Successfully mapped shared-memory into user-mode PID (%d) at 0x%p\n", 
            SharedMem->UserProcessId, SharedMem->UserAddress);

        return STATUS_SUCCESS;
    }

    return STATUS_INVALID_PARAMETER;
}


VOID
UnmapSharedMemoryFromUsermode(
    _In_ PSHARED_MEMORY SharedMem
    )
{
    if (SharedMem->SharedMdl != NULL && SharedMem->UserAddress != NULL)
        MmUnmapLockedPages(SharedMem->UserAddress , SharedMem->SharedMdl);
    
    DoTraceMessage("Successfully unmapped shared-memory from PID (%d) at 0x%p\n",
        SharedMem->UserProcessId, SharedMem->UserAddress);

    SharedMem->UserAddress = NULL;
    SharedMem->UserProcessId = 0;
}


VOID
DestroySharedMemory(
    _In_ PSHARED_MEMORY SharedMem
    )
{
    MmUnmapLockedPages(SharedMem->UserAddress, SharedMem->SharedMdl);
    MmFreePagesFromMdl(SharedMem->SharedMdl);

    ExFreePool(SharedMem->SharedMdl);

    DoTraceMessage("Successfully unmapped shared-memory from Kernel|User\n");
}

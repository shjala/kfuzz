/*
 * Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
 * All rights reserved.
 */

#include "kflog.h"

DWORD nCPUsLocked;
DWORD LockAcquired;


NTSTATUS
LockKernelPage(
    _In_ PVOID Address,
    _In_ ULONG Length,
    _In_ LOCK_OPERATION LockMode,
    _Outptr_ PPAGE_LOCK PageLock
    )
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    ASSERT(Length != 0);
    ASSERT(Address != NULL);

    PageLock->Mdl = IoAllocateMdl(
        (PVOID)Address,
        Length,
        FALSE,
        FALSE,
        NULL);

    if (PageLock->Mdl == NULL) {

        DoTraceMessage("Failed to allocated MDL for address 0x%p (%d)\n",
            Address, Length);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    try {

        MmProbeAndLockPages(PageLock->Mdl, KernelMode, LockMode);

    }
    except(EXCEPTION_EXECUTE_HANDLER) {

        Status = GetExceptionCode();
        IoFreeMdl(PageLock->Mdl);

        DoTraceMessage("Exception 0x%.8x while locking address at 0x%p\n", 
            Status, Address);

        return Status;
    }

    PageLock->Address = MmGetSystemAddressForMdlSafe(PageLock->Mdl, HighPagePriority);
    if (PageLock->Address == NULL) {

        DoTraceMessage("Failed to get MDL system-address for address 0x%p\n",
            Address);

        MmUnlockPages(PageLock->Mdl);
        IoFreeMdl(PageLock->Mdl);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}


VOID
UnlockKernelPage(
    _In_ PPAGE_LOCK PageLock
    )
{
    ASSERT(PageLock != NULL);

    MmUnlockPages(PageLock->Mdl);
    IoFreeMdl(PageLock->Mdl);
}


NTSTATUS
RewriteKernelAddress(
    _In_ PVOID Destination,
    _In_ PVOID Replacement,
    _In_ ULONG Length,
    _Inout_ _Maybenull_ PUCHAR OrginalBytes
    ) 
{
    COPY_CONTEXT CopyContext;
    PAGE_LOCK PageLock;
    KIRQL OldIrql;
    ULONG NumberOfProcessors;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    Status = LockKernelPage(Destination,
        Length,
        IoReadAccess,
        &PageLock);

    if (NT_SUCCESS(Status)) {

        /* Unnecessary */
        Status = MmProtectMdlSystemAddress(PageLock.Mdl, PAGE_READWRITE);
        if (!NT_SUCCESS(Status)) {

            DoTraceMessage("Failed to make lock kernel pages writable at address 0x%p (%d)\n",
                Destination, Length);

            UnlockKernelPage(&PageLock);

            return Status;
        }

        if (OrginalBytes != NULL)
            RtlCopyMemory(OrginalBytes, PageLock.Address, Length);

        CopyContext.ProcessorNumber = KeGetCurrentProcessorNumber();
        CopyContext.Destination = PageLock.Address;
        CopyContext.Replacement = Replacement;
        CopyContext.Length = Length;
        CopyContext.Done = FALSE;
        
        NumberOfProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
        if (NumberOfProcessors > 1) {

            CopyContext.ProcessorsBarrier = NumberOfProcessors - 1;
            CopyContext.ProcessorsToResume = NumberOfProcessors - 1;
            KeIpiGenericCall(PerformSingleProccessorCopy, (ULONG_PTR)&CopyContext);
        }
        else {

            OldIrql = KeGetCurrentIrql();
            if (OldIrql < IPI_LEVEL - 1) {
                KfRaiseIrql(IPI_LEVEL - 1);
            }

            CopyContext.ProcessorsBarrier = 0;
            CopyContext.ProcessorsToResume = 0;
            PerformSingleProccessorCopy((ULONG_PTR)&CopyContext);
            KfLowerIrql(OldIrql);
        }

        UnlockKernelPage(&PageLock);
    }
    else {

        DoTraceMessage("Failed to lock kernel pages at address 0x%p (%d)\n",
            Destination, Length);
    }

    return Status;
}


ULONG_PTR
PerformSingleProccessorCopy(
    _In_ ULONG_PTR Context
    )
{
    PCOPY_CONTEXT CopyContext;
    CopyContext = (PCOPY_CONTEXT)Context;

    if (CopyContext->ProcessorNumber != KeGetCurrentProcessorNumber()) {

        /* All processors but one wait here until the routine is complete */
        InterlockedDecrement(&CopyContext->ProcessorsBarrier);
        while (CopyContext->Done == FALSE) {
            KeYieldProcessor();
        }

        InterlockedDecrement(&CopyContext->ProcessorsToResume);
        return 0;
    }

    while (CopyContext->ProcessorsBarrier != 0) {
        KeYieldProcessor();
    }

    RtlCopyMemory(CopyContext->Destination, CopyContext->Replacement, CopyContext->Length);
    CopyContext->Done = TRUE;

    while (CopyContext->ProcessorsToResume != 0) {
        KeYieldProcessor();
    }

    return 0;
}
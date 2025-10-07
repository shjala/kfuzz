/*
 * Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
 * All rights reserved.
 */

#include "kflog.h"

extern LIST_ENTRY           _g_KernelPatchRecordList;
extern PAGED_LOOKASIDE_LIST _g_KernelPatchListPool;


NTSTATUS
AddPatchRecordToList(
    _In_ PVOID Address,
    _In_ ULONG Lenght,
    _In_opt_ _Maybenull_ PVOID ProbeAddress,
    _In_ PVOID OrginalBytes
    )
{
    PPATCH_RECORD_LIST PatchRecordEntry = NULL;

    if (Lenght > MAX_INST_LEN)
        return STATUS_INVALID_PARAMETER;

    PatchRecordEntry = (PPATCH_RECORD_LIST)ExAllocateFromPagedLookasideList(&_g_KernelPatchListPool);
    if (PatchRecordEntry == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    PatchRecordEntry->PatchRecord.Address      = Address;
    PatchRecordEntry->PatchRecord.Length       = Lenght;
    PatchRecordEntry->PatchRecord.ProbeAddress = ProbeAddress;

    RtlCopyMemory(PatchRecordEntry->PatchRecord.OrginalBytes, OrginalBytes, Lenght);
    InsertTailList(&_g_KernelPatchRecordList, &PatchRecordEntry->List);

    return STATUS_SUCCESS;
}


LOGICAL
IsAddressPatched(
    PVOID Address
    )
{
    PPATCH_RECORD_LIST PatchRecordEntry = NULL;
    PLIST_ENTRY pEntry = _g_KernelPatchRecordList.Flink;

    while(pEntry != &_g_KernelPatchRecordList)
    {
        PatchRecordEntry = CONTAINING_RECORD(pEntry, PATCH_RECORD_LIST, List);
        if (PatchRecordEntry != NULL) {

            if (PatchRecordEntry->PatchRecord.Address == Address)
                return TRUE;
        }

        pEntry = pEntry->Flink;
    }

    return FALSE;
}


VOID
RestoreKernelPatches(
    VOID
    )
{
    PPATCH_RECORD_LIST PatchRecordEntry = NULL;
    PLIST_ENTRY pList = NULL;
    PVOID pOrginalBytes = NULL;
    ULONG Count = 0;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    while (!IsListEmpty(&_g_KernelPatchRecordList)) {

        pList = RemoveHeadList(&_g_KernelPatchRecordList);
        PatchRecordEntry = CONTAINING_RECORD(pList, PATCH_RECORD_LIST, List);

        if (PatchRecordEntry != NULL) {

            pOrginalBytes = ExAllocatePoolWithTag(NonPagedPool,
                PatchRecordEntry->PatchRecord.Length,
                KFLOG_POOL_KPATCH_TAG);

            if (pOrginalBytes != NULL) {

                RtlCopyMemory(pOrginalBytes,
                    PatchRecordEntry->PatchRecord.OrginalBytes,
                    PatchRecordEntry->PatchRecord.Length);

                Status = RewriteKernelAddress(PatchRecordEntry->PatchRecord.Address,
                    pOrginalBytes,
                    PatchRecordEntry->PatchRecord.Length,
                    NULL);

                if (!NT_SUCCESS(Status))
                    DoTraceMessage("%s to remove probe from : 0x%p (Length:%.2d)\n",
                        "Failed",
                        PatchRecordEntry->PatchRecord.Address,
                        PatchRecordEntry->PatchRecord.Length);

                ExFreePoolWithTag(pOrginalBytes, KFLOG_POOL_KPATCH_TAG);
            }

            if (!NT_SUCCESS(Status) || pOrginalBytes == NULL) {

                DoTraceMessage("Failed to remove probe at address 0x%p (***FATAL EMBACE FOR B.S.O.D ***)\n",
                    PatchRecordEntry->PatchRecord.Address);

                ExFreeToPagedLookasideList(&_g_KernelPatchListPool, PatchRecordEntry);
                continue;
            }

            Count++;

            if (PatchRecordEntry->PatchRecord.ProbeAddress)
                ExFreePoolWithTag(PatchRecordEntry->PatchRecord.ProbeAddress, KFLOG_POOL_KPATCH_TAG);

            ExFreeToPagedLookasideList(&_g_KernelPatchListPool, PatchRecordEntry);
        }
    }

    DoTraceMessage("Successfully removed KFL's probe callback (%d).\n", Count);
}
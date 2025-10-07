/*
 * Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
 * All rights reserved.
 */

#include "kflog.h"

extern KT_CAPTURE          _g_KtCaptures;
extern FOCUS_BBL_LIST      _g_FocusBblList;
extern KSPIN_LOCK          _g_BblTrackingHashTableLock;
extern PHASH_TABLE         _g_BblTrackingHashTable;
extern PLOOKASIDE_LIST_EX  _g_BblTrackingEntriesPool;


VOID
UpdateSimpleCounters(
    _In_ ULONG BlockAddress,
    _In_ LOGICAL IsNewBlock,
    _In_ ULONG Hash
    )
{
    if (_g_KtCaptures.Counters.Bbls.Record)
        InterlockedIncrement((VOLATILE LONG*)&_g_KtCaptures.Counters.Bbls.Counter);

    if (_g_KtCaptures.Counters.NewEdges.Record && IsNewBlock)
        InterlockedIncrement((VOLATILE LONG*)&_g_KtCaptures.Counters.NewEdges.Counter);
}


NTSTATUS
RecordBlockCoverageInfo(
    _In_ ULONG Address
    )
{
    KLOCK_QUEUE_HANDLE LockHandle;
    PBBL_TRACKING_ENTRY BblEntry;
    NTSTATUS Status = STATUS_SUCCESS;

    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        return STATUS_INVALID_LEVEL;

    if (_g_KtCaptures.Extended.CodeCov.Record) {

        BblEntry = (PBBL_TRACKING_ENTRY)GetRecordFromHashTable(_g_BblTrackingHashTable,
            Address);

        if (BblEntry != NULL) {

            _mm_prefetch((CONST PCHAR)&BblEntry->HitCount, _MM_HINT_T0);
            BblEntry->HitCount++;
        }
        else {

            BblEntry = (PBBL_TRACKING_ENTRY)ExAllocateFromLookasideListEx(
                _g_BblTrackingEntriesPool);

            if (BblEntry != NULL) {

                BblEntry->Address = (PVOID)Address;
                BblEntry->HitCount = 1;

                KeAcquireInStackQueuedSpinLock(&_g_BblTrackingHashTableLock, &LockHandle);

                Status = AddRecordToHashTable(_g_BblTrackingHashTable,
                    BblEntry, Address);

                KeReleaseInStackQueuedSpinLock(&LockHandle);

                if (!NT_SUCCESS(Status))
                    ExFreeToLookasideListEx(_g_BblTrackingEntriesPool, BblEntry);
            }
        }
    }

    return Status;
}


NTSTATUS
CopyBlockCoverageInfo(
    _In_ PVOID Buffer,
    _In_ PULONG pSize
    )
{
    NTSTATUS Status;
    ULONG RecordCount;
    ULONG ContentSize;
    
    RecordCount = CountHashTableRecords(_g_BblTrackingHashTable);
    ContentSize = RecordCount * sizeof(BBL_TRACKING_ENTRY);
    if (Buffer == NULL || ContentSize > *pSize) {

        *pSize = ContentSize;
        return STATUS_INVALID_BUFFER_SIZE;
    }
        
    Status = CopyHashTableContent(_g_BblTrackingHashTable,
        sizeof(BBL_TRACKING_ENTRY),
        Buffer,
        *pSize);

    return Status;
}


NTSTATUS
RegisterFocusBlockEvent(
    PFOCUS_BBL_ENTRY UserEntry
    ) 
{
    PKERNEL_FOCUS_BBL_ENTRY KernelEntry;
    PKEVENT Event;
    NTSTATUS Status;

    for (ULONG i = 0; i < MAX_FOCUS_BBL; i++) {

        KernelEntry = &_g_FocusBblList.Entries[i];
        if (KernelEntry->Address == NULL || KernelEntry->Address == UserEntry->Address) {

            if (KernelEntry->Address == UserEntry->Address) {

                ObDereferenceObject(KernelEntry->Event);
                KernelEntry->Address = NULL;
                KernelEntry->Event = NULL;
                _g_FocusBblList.Count--;
            }
            
            Status = ObReferenceObjectByHandle(UserEntry->Event,
                SYNCHRONIZE | EVENT_MODIFY_STATE,
                *ExEventObjectType,
                UserMode,
                &Event,
                NULL
            );

            if (!NT_SUCCESS(Status)) {

                DoTraceMessage("Failed to register an event for block at 0x%p!\n",
                    KernelEntry->Address);

                return Status;
            }

            KernelEntry->Address = UserEntry->Address;
            KernelEntry->Event = Event;

            DoTraceMessage("Successfully registered an event for block at 0x%p.\n", 
                KernelEntry->Address);

            _g_FocusBblList.Count++;
            return STATUS_SUCCESS;
        }
    }

    DoTraceMessage("All focus BBL entries are full!\n");
    return STATUS_INSUFFICIENT_RESOURCES;
}


VOLATILE
NTSTATUS
STDCALL
SingalFocusBlockEvent(
    PVOID Address
    )
{
    ULONG Occupied = 0;
    PKERNEL_FOCUS_BBL_ENTRY FocusEntry;

    /* If Wait is set to FALSE, the caller can be running at IRQL <= DISPATCH_LEVE */
    if (KeGetCurrentIrql() > DISPATCH_LEVEL)
        return STATUS_INVALID_LEVEL;

    for (ULONG i = 0; i < MAX_FOCUS_BBL; i++) {

        FocusEntry = &_g_FocusBblList.Entries[i];
        _mm_prefetch((CONST PCHAR)FocusEntry, _MM_HINT_T2);

        if (FocusEntry->Address != NULL) {
            if (FocusEntry->Address == Address) {

                KeSetEvent(FocusEntry->Event, 0, FALSE);
                return STATUS_SUCCESS;
            }
            else {

                Occupied++;
                if (Occupied == _g_FocusBblList.Count)
                    return STATUS_NOT_FOUND;
            }
        }
    }

    return STATUS_NOT_FOUND;
}


VOID
ReleaseAllFocusEvents(
    VOID
    )
{
    if (_g_FocusBblList.Entries == NULL)
        return;

    for (ULONG i = 0; i < MAX_FOCUS_BBL; i++)
        if (_g_FocusBblList.Entries[i].Event != NULL)
            ObDereferenceObject(_g_FocusBblList.Entries[i].Event);

    ExFreePoolWithTag(_g_FocusBblList.Entries, KFLOG_POOL_BT_TAG);
}


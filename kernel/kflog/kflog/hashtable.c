/*
 * Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
 * All rights reserved.
 */

#include "kflog.h"

ULONG  _g_CachedAddrSpaceSize = 0;
ULONG  _g_CachedImageNameId = 0;
ULONG  _g_CachedAddress = 0;

PHASH_TABLE
AllocateHashTable(
    _In_ ULONG Capacity
    )
{
    /* TODO : one improvement in this function would be using a hash-table
       like hopscotch (or robinhood) which is more cache friendly.
    */
    PHASH_TABLE pTable = NULL;
    ULONG TableSize = Capacity * sizeof(PVOID);

    pTable = (PHASH_TABLE)ExAllocatePoolWithTag(NonPagedPool,
        sizeof(HASH_TABLE),
        KFLOG_POOL_KHT_TAG);

    if (pTable == NULL) {

        DoTraceMessage("AllocateHashTable(): failed to allocate HASH_TABLE_HANDLE of size : %d\n", sizeof(HASH_TABLE));
        return NULL;
    }

    pTable->HashTable = (PVOID*)ExAllocatePoolWithTag(NonPagedPool,
        TableSize,
        KFLOG_POOL_KHT_TAG);

    if (pTable->HashTable == NULL) {

        DoTraceMessage("AllocateHashTable(): failed to allocate HashTable of size : %d\n", TableSize);
        return NULL;
    }

    pTable->Capacity = Capacity;
    RtlZeroMemory(pTable->HashTable, TableSize);

    return pTable;
}


NTSTATUS
AddRecordToHashTable(
    _In_ PHASH_TABLE hHashTable,
    _In_ PVOID Content,
    _In_ ULONG Key
    )
{
    ULONG Index;
    PHT_RECORD_LIST KeyRecord;
    PHT_RECORD_LIST CurrentRecord;

    KeyRecord = GetRecordListFromHashTable(hHashTable, Key);
    if (KeyRecord != NULL)
        return STATUS_SUCCESS;

    /* Simple (z mod n) is best hash function for our data-set */
    Index = (Key % hHashTable->Capacity);
    _mm_prefetch(hHashTable->HashTable[Index], _MM_HINT_T0);
    CurrentRecord = (PHT_RECORD_LIST)hHashTable->HashTable[Index];

    /* TODO : use ExAllocateFromNPagedLookasideList */
    KeyRecord = (PHT_RECORD_LIST)ExAllocatePoolWithTag(NonPagedPool,
        sizeof(HT_RECORD_LIST),
        KFLOG_POOL_KHT_TAG);

    if (KeyRecord == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    KeyRecord->Next = NULL;
    KeyRecord->Key = Key;
    KeyRecord->Record = Content;

    if (CurrentRecord == NULL) {

        hHashTable->HashTable[Index] = KeyRecord;
    }
    else {

        while (CurrentRecord->Next != NULL)
            CurrentRecord = CurrentRecord->Next;

        CurrentRecord->Next = KeyRecord;
    }

    return STATUS_SUCCESS;
}


NTSTATUS
RemoveRecordFromHashTable(
    _In_ PHASH_TABLE hHashTable,
    _In_ ULONG Key
    )
{
    ULONG Index;
    PHT_RECORD_LIST KeyRecord;
    PHT_RECORD_LIST Prev = NULL;

    Index = (Key % hHashTable->Capacity);
    KeyRecord = (PHT_RECORD_LIST)hHashTable->HashTable[Index];

    if (KeyRecord != NULL) {

        do {

            if (KeyRecord->Key == Key) {

                if (Prev == NULL) {

                    if (KeyRecord->Next != NULL)
                        hHashTable->HashTable[Index] = KeyRecord->Next;
                    else
                        hHashTable->HashTable[Index] = NULL;
                }
                else {

                    Prev->Next = KeyRecord->Next;
                }

                ExFreePoolWithTag(KeyRecord, KFLOG_POOL_KHT_TAG);

                return STATUS_SUCCESS;
            }

            Prev = KeyRecord;
            KeyRecord = KeyRecord->Next;

        } while (KeyRecord != NULL);
    }

    return STATUS_NOT_FOUND;
}


PVOID
GetRecordFromHashTable(
    _In_ PHASH_TABLE hHashTable,
    _In_ ULONG Key
    )
{
    PHT_RECORD_LIST KeyRecord;

    KeyRecord = GetRecordListFromHashTable(hHashTable, Key);
    if (KeyRecord != NULL)
        return KeyRecord->Record;

    return NULL;
}


PHT_RECORD_LIST
GetRecordListFromHashTable(
    _In_ PHASH_TABLE hHashTable,
    _In_ ULONG Key
    )
{
    ULONG Index;
    PHT_RECORD_LIST KeyRecord;

    Index = (Key % hHashTable->Capacity);
    KeyRecord = (PHT_RECORD_LIST)hHashTable->HashTable[Index];

    if (KeyRecord != NULL) {

        do {

            if (KeyRecord->Key == Key)
                return KeyRecord;

            KeyRecord = KeyRecord->Next;

        } while (KeyRecord != NULL);
    }

    return NULL;
}


VOID
FreeHashTable(
    _In_ PHASH_TABLE HashTable
    )
{
    PHT_RECORD_LIST Current;
    PHT_RECORD_LIST Next;
    ULONG i = 0;

    if (HashTable != NULL) {

        for (i = 0; i < HashTable->Capacity; i++) {

            if (HashTable->HashTable[i] != NULL) {

                Current = (PHT_RECORD_LIST)HashTable->HashTable[i];

                do {

                    Next = Current->Next;
                    ExFreePoolWithTag(Current, KFLOG_POOL_KHT_TAG);
                    Current = Next;

                } while (Current != NULL);
            }
        }

        ExFreePoolWithTag(HashTable->HashTable, KFLOG_POOL_KHT_TAG);
        ExFreePoolWithTag(HashTable, KFLOG_POOL_KHT_TAG);
    }
}


VOID
ClearHashTable(
    _In_ PHASH_TABLE HashTable
    )
{
    PHT_RECORD_LIST Current;
    PHT_RECORD_LIST Next;
    ULONG TableSize = HashTable->Capacity * sizeof(PVOID);
    ULONG i = 0;

    if (HashTable != NULL) {

        for (i = 0; i < HashTable->Capacity; i++) {

            Current = (PHT_RECORD_LIST)HashTable->HashTable[i];

            if (Current != NULL) {

                do {

                    Next = Current->Next;
                    ExFreePoolWithTag(Current, KFLOG_POOL_KHT_TAG);
                    Current = Next;

                } while (Current != NULL);
            }
        }

        RtlZeroMemory(HashTable->HashTable, TableSize);
    }
}


ULONG
CountHashTableRecords(
    _In_ PHASH_TABLE HashTable
    )
{
    PHT_RECORD_LIST Current;
    ULONG Count = 0;

    for (ULONG i = 0; i < HashTable->Capacity; i++) {

        Current = (PHT_RECORD_LIST)HashTable->HashTable[i];

        if (Current != NULL) {

            do {

                Current = Current->Next;
                Count++;

            } while (Current != NULL);
        }
    }

    return Count;
}


VOID
ApplyOnHashTableRecords(
    _In_ PHASH_TABLE HashTable,
    _In_ PHASH_RECORD_ROUTINE Routine
    )
{
    PHT_RECORD_LIST Current;

    for (ULONG i = 0; i < HashTable->Capacity; i++) {

        Current = (PHT_RECORD_LIST)HashTable->HashTable[i];

        if (Current != NULL) {

            do {

                Routine(Current->Record);
                Current = Current->Next;

            } while (Current != NULL);
        }
    }
}


NTSTATUS
CopyHashTableContent(
    _In_ PHASH_TABLE HashTable,
    _In_ ULONG RecordSize,
    _In_ PVOID Buffer,
    _In_ ULONG Size
    )
{
    PHT_RECORD_LIST Current;
    ULONG CopyOffset = 0;

    if (Buffer == NULL || Size == 0)
        return STATUS_INVALID_PARAMETER;

    for (ULONG i = 0; i < HashTable->Capacity; i++) {

        Current = (PHT_RECORD_LIST)HashTable->HashTable[i];

        if (Current != NULL) {

            do {

                if ((CopyOffset + RecordSize) > Size)
                    return STATUS_INSUFFICIENT_RESOURCES;

                RtlCopyMemory((PUCHAR)Buffer + CopyOffset, Current->Record, RecordSize);

                CopyOffset += RecordSize;
                Current = Current->Next;

            } while (Current != NULL);
        }
    }

    return STATUS_SUCCESS;
}

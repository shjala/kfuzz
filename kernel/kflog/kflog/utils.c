/*
 * Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
 * All rights reserved.
 */

#include "kflog.h"

VOID
DoTraceMessage(
    _In_ PCCH Format,
    ...
    )
{
#ifndef NO_TRACE_MESSAGE
    va_list arglist;

    va_start(arglist, Format);
    vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, arglist);
    va_end(arglist);
#endif
}


#ifdef __DEBUG_ECOV
#define ECOV_DUMP_SIZE  655360

PDBG_DUMP_ECOV _g_DbgEcovDump = NULL;
ULONG          _g_DbgEcovDumpCount = 0;

VOID
AddCoverageInfoToDump(
    __in ULONG PrevAddr,
    __in ULONG PrevId,
    __in ULONG CurrAddr,
    __in ULONG CurrId,
    __in ULONG Hash
    ) 
{
    if (_g_DbgEcovDump == NULL) {
        _g_DbgEcovDump = (PDBG_DUMP_ECOV)ExAllocatePool(NonPagedPool, sizeof(DBG_DUMP_ECOV) * ECOV_DUMP_SIZE);
        if (_g_DbgEcovDump == NULL)
            return;

        RtlZeroMemory(_g_DbgEcovDump, sizeof(DBG_DUMP_ECOV) * ECOV_DUMP_SIZE);
    }

    if (_g_DbgEcovDumpCount + 1 >= ECOV_DUMP_SIZE) {
        DoTraceMessage("ECDUMP Is rolling back to index zero...\n");
        _g_DbgEcovDumpCount = 0;
    }

    _g_DbgEcovDump[_g_DbgEcovDumpCount].PrevBlockAddr = PrevAddr;
    _g_DbgEcovDump[_g_DbgEcovDumpCount].PrevBlockId = PrevId;
    _g_DbgEcovDump[_g_DbgEcovDumpCount].CurrBlockAddr = CurrAddr;
    _g_DbgEcovDump[_g_DbgEcovDumpCount].CurrBlockId = CurrId;
    _g_DbgEcovDump[_g_DbgEcovDumpCount].Hash = Hash;
    _g_DbgEcovDumpCount++;
}

NTSTATUS
DumpCoverageInfoToFile(
    VOID
    )
{
    IO_STATUS_BLOCK ioStatusBlock;
    OBJECT_ATTRIBUTES ObjectAttr;
    UNICODE_STRING FilePath;
    HANDLE LogFile;
    NTSTATUS Status;

    RtlInitUnicodeString(&FilePath, KFLOG_ECOV_DUMP_FILE_PATH);
    InitializeObjectAttributes(&ObjectAttr,
        &FilePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    Status = ZwCreateFile(&LogFile,
        GENERIC_WRITE | SYNCHRONIZE | FILE_APPEND_DATA,
        &ObjectAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_WRITE | FILE_SHARE_READ,
        FILE_OPEN_IF,
        FILE_WRITE_THROUGH | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    if (!NT_SUCCESS(Status))
        return Status;

    Status = ZwWriteFile(LogFile,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            _g_DbgEcovDump,
            sizeof(DBG_DUMP_ECOV) * ECOV_DUMP_SIZE,
            NULL,
            NULL);

    ZwClose(LogFile);
    ExFreePool(_g_DbgEcovDump);
    _g_DbgEcovDump = NULL;

    return Status;
}
#endif
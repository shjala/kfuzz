/*
 * Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
 * All rights reserved.
 */

#include "kflog.h"

ULONG _g_MemoryCounter = 0;

ULONG
GenBasicblockId(
    VOID
    )
{
    ULONG BasicBlockId;
    LARGE_INTEGER Seed;

    KeQueryTickCount(&Seed);
    BasicBlockId = RtlRandomEx(&Seed.LowPart);
    BasicBlockId = (BasicBlockId >> BIT_SIZE_24) ^ (BasicBlockId & MASK_24);

    ASSERT(BasicBlockId < EDGE_TRANS_MAP_SIZE_64M);
    return BasicBlockId;
}


NTSTATUS
InsertEgdeTransitionProbeOnBasicBlock(
    _In_ PVOID Address,
    _In_ ULONG Length,
    _In_ ULONG CopyLength,
    _In_ ULONG IsFocusBlock
    )
{
    UCHAR JUMP_FORWARD[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
    UCHAR OrginalBytes[MAX_INST_LEN];
    PVOID pJumpContent;
    PVOID pProbeContent;
    INT32 BranchOffset;
    ULONG Callback = (ULONG)CallOnEdgeTransition;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if (Address == NULL || Length == 0 || CopyLength == 0) {

        DoTraceMessage("Invalid parameters Address: 0x%p, Length: %d, CopyLength: %d\n",
            Address, Length, CopyLength);

        return STATUS_INVALID_PARAMETER;
    }

    if (Length < sizeof(JUMP_FORWARD) || CopyLength < sizeof(JUMP_FORWARD) || CopyLength > Length) {

        DoTraceMessage("Invalid length parameters Length: %d, CopyLength: %d\n",
            Length, CopyLength);

        return STATUS_INVALID_PARAMETER;
    }

    if (IsFocusBlock)
        Callback = (ULONG)CallOnEdgeTransitionEvent;

    pProbeContent = AllocTransitionProbe(Address,
        GenBasicblockId(),
        CopyLength,
        ((ULONG)Address + CopyLength),
        (ULONG)Callback);

    if (pProbeContent != NULL) {

        pJumpContent = ExAllocatePoolWithTag(NonPagedPool,
            sizeof(JUMP_FORWARD),
            KFLOG_POOL_KPATCH_TAG);

        if (pJumpContent == NULL) {

            DoTraceMessage("Failed to allocate memory for jump trampoline.\n");

            return STATUS_INSUFFICIENT_RESOURCES;
        }

        /* Fomrula : Offset = (INT32)Dst - ((INT32)Scr + 5) */
        BranchOffset = (INT32)pProbeContent - ((INT32)Address + 5);
        RtlCopyMemory(JUMP_FORWARD + 1, &BranchOffset, sizeof(BranchOffset));
        RtlCopyMemory(pJumpContent, JUMP_FORWARD, sizeof(JUMP_FORWARD));

        Status = RewriteKernelAddress(Address,
            pJumpContent,
            sizeof(JUMP_FORWARD),
            (PUCHAR)OrginalBytes);

        if (!NT_SUCCESS(Status)) {

            DoTraceMessage("Failed to insert probe at address 0x%p\n", 
                Address);

            ExFreePoolWithTag(pJumpContent, KFLOG_POOL_KPATCH_TAG);
            ExFreePoolWithTag(pProbeContent, KFLOG_POOL_KPATCH_TAG);
            return Status;
        }

        ExFreePoolWithTag(pJumpContent, KFLOG_POOL_KPATCH_TAG);

        AddPatchRecordToList(Address, sizeof(JUMP_FORWARD), pProbeContent, OrginalBytes);
        return STATUS_SUCCESS;
    }

    DoTraceMessage("Failed to allocate edge-transition probe for address 0x%p\n",
        Address);

    return STATUS_INSUFFICIENT_RESOURCES;
}


PVOID
AllocTransitionProbe(
    _In_ PVOID Address,
    _In_ ULONG Identifier,
    _In_ ULONG CopyLength,
    _In_ ULONG ReturnAddress,
    _In_ ULONG CallbackAddress
    )
{
    UCHAR SAVE_EFLAGS[]      = { 0x50, 0x9F, 0x0F, 0x90, 0xC0 };
    UCHAR RES_EFLAGS[]       = { 0x04, 0x7F, 0x9E, 0x58 };
    UCHAR PUSH_ADDRESS[]     = { 0x68, 0x00, 0x00, 0x00, 0x00 };
    UCHAR CALL_CALLBACK[]    = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
    UCHAR JUMP_ADDR[]        = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
    PUCHAR pProbeContent = NULL;
    ULONG ContentOffset = 0;
    ULONG ProbeSize;
    INT32 BranchOffset;
    
    ProbeSize = ROUND_UP(
        sizeof(SAVE_EFLAGS)     +
        sizeof(PUSH_ADDRESS)    +
        sizeof(PUSH_ADDRESS)    +
        sizeof(CALL_CALLBACK)   +
        sizeof(RES_EFLAGS)      +
        sizeof(JUMP_ADDR)       +  
        CopyLength, 
        4);

    pProbeContent = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool,
        ProbeSize, 
        KFLOG_POOL_KPATCH_TAG);

    if (pProbeContent == NULL) {

        DoTraceMessage("Failed to allocate memory for edge-transison probe (%d).\n",
            ProbeSize);

        return NULL;
    }

    /* Update the internal memory allocation size counter */
    _g_MemoryCounter += ProbeSize;

    /* NOP out the stub memory */
    RtlFillMemory(pProbeContent, ProbeSize, INST_NOP);

    /* 
    PUSH EAX
    LAHF
    SETO AL
    */
    RtlCopyMemory(pProbeContent, SAVE_EFLAGS, sizeof(SAVE_EFLAGS));
    ContentOffset += sizeof(SAVE_EFLAGS);

    /* PUSH BlockId */
    RtlCopyMemory((PUSH_ADDRESS + 1), &Identifier, sizeof(Identifier));
    RtlCopyMemory(pProbeContent + ContentOffset, PUSH_ADDRESS, sizeof(PUSH_ADDRESS)); 
    ContentOffset += sizeof(PUSH_ADDRESS);

    /* PUSH BlockAddress */
    RtlCopyMemory((PUSH_ADDRESS + 1), &Address, sizeof(Address));
    RtlCopyMemory(pProbeContent + ContentOffset, PUSH_ADDRESS, sizeof(PUSH_ADDRESS)); 
    ContentOffset += sizeof(PUSH_ADDRESS);

    /* CALL Callback */
    BranchOffset = (INT32)CallbackAddress - ((INT32)(pProbeContent + ContentOffset) + 5);
    RtlCopyMemory(CALL_CALLBACK + 1, &BranchOffset, sizeof(BranchOffset));
    RtlCopyMemory((pProbeContent + ContentOffset), CALL_CALLBACK, sizeof(CALL_CALLBACK));
    ContentOffset += sizeof(CALL_CALLBACK);

    /*
    ADD AL,7F
    SAHF
    POP EAX
    */
    RtlCopyMemory(pProbeContent + ContentOffset, RES_EFLAGS, sizeof(RES_EFLAGS)); 
    ContentOffset += sizeof(RES_EFLAGS);

    /* Copy saved instructions */
    RtlCopyMemory(pProbeContent + ContentOffset, Address, CopyLength); 
    ContentOffset += CopyLength;

    /* JMP ReturnAddress */
    BranchOffset = (INT32)ReturnAddress - ((INT32)(pProbeContent + ContentOffset) + 5);
    RtlCopyMemory(JUMP_ADDR + 1, &BranchOffset, sizeof(BranchOffset));
    RtlCopyMemory(pProbeContent + ContentOffset, JUMP_ADDR, sizeof(JUMP_ADDR));
    
    return pProbeContent;
}


ULONG
InsertEgdeTransitionProbeOnBasicBlockList(
    _In_ PBASICBLOCK_ADDR_INFO List,
    _In_ ULONG Size
    )
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    ULONG Count = 0, PatchCounter = 0;
    ULONG i = 0;

    /* Reset internal memory counter*/
    _g_MemoryCounter = 0;

    Count = Size / sizeof(BASICBLOCK_ADDR_INFO);
    for (i = 0; i < Count; i++) {

        if (i > 0)
            if (!NT_SUCCESS(Status))
                DoTraceMessage("%s to insert probe on : %s!0x%p (Length:%.3d, CopyLength:%.2d) [%d/%d]\n",
                    "Failed",
                    List[i-1].ImageName,
                    List[i-1].Address,
                    List[i-1].Length,
                    List[i-1].CopyLength,
                    i,
                    Count);
        
        if (IsAddressPatched((PVOID)List[i].Address) == TRUE) {

            PatchCounter++;
            Status = STATUS_SUCCESS;

            continue;
        }

        Status = InsertEgdeTransitionProbeOnBasicBlock(
            List[i].Address,
            List[i].Length,
            List[i].CopyLength,
            List[i].IsFocusBlock);

        if (NT_SUCCESS(Status))
            PatchCounter++;
    }

    DoTraceMessage("Successfully set KFL's probe callback on (%d/%d) basic-blocks.\n",
        PatchCounter, Count);

    DoTraceMessage("Allocated total %d Bytes of physical memory for probe insertion.\n",
        _g_MemoryCounter);

    return PatchCounter;
}
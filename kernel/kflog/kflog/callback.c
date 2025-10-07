/*
 * Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
 * All rights reserved.
 */

#include "kflog.h"

extern PCHAR          _g_EdgeTransitionMap;
extern HANDLE         _g_UsermodeTracerPid;
extern ULONG          _g_TraceStatus;
extern ULONG          _g_TraceIRQL;

WORKER_THREAD_CONTEXT _g_WorkersContext[MAX_THREAD_COUNT];
ULONG                 _g_TmpPrevLocation = 0;
ULONG                 _g_ActiveThreadsCount = 0;
#ifdef __DEBUG_ECOV   
ULONG                 _g_PrevLocAddr = 0;
ULONG                 _g_PrevBlockId = 0;
#endif


VOLATILE
ULONG
STDCALL
StatusFitForTracing(
    VOID
    )
{
#if defined(__PROBE_CALLBACK_CHECK_IRQL)
    if (KeGetCurrentIrql() > _g_TraceIRQL || KeGetCurrentIrql() > DISPATCH_LEVEL)
        return 0;
#endif

    switch (_g_TraceStatus) {
    case TRACE_NONE:
        return 0;

    case TRACE_ALL:
        return 1;

    case TRACE_KERNEL:
        if (PsGetCurrentProcessId() == NULL || PsGetCurrentProcessId() == KERNEL_PID)
            return 1;
        return 0;

    case TRACE_USER:
        if (PsGetCurrentProcessId() > KERNEL_PID)
            return 1;
        return 0;

    case TRACE_PID:
        if (PsGetCurrentProcessId() == _g_UsermodeTracerPid)
            return 1;
        return 0;
    }

    return 0;
}


VOID
WaitAndCleanUpTracedThread(
    _In_ PVOID Context
    ) 
{
    NTSTATUS Status;
    LARGE_INTEGER Timeout;
    VOLATILE PETHREAD TargetThreadObject;
    PWORKER_THREAD_CONTEXT WorkerContext;

    Timeout.QuadPart = -(5000000000/100); /* 5 Seconds */
    WorkerContext = (PWORKER_THREAD_CONTEXT)Context;

    while (TRUE) {

        KeWaitForSingleObject(&WorkerContext->WaitEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL);

        if (WorkerContext->Exit) {

            DoTraceMessage("Worker (0x%p) extiting...\n", WorkerContext->Thread);

            return;
        }

        InterlockedExchange((VOLATILE LONG*)&TargetThreadObject, (LONG)WorkerContext->TargetThreadObject);
        DoTraceMessage("Worker (0x%p) assigned to wait for thread (0x%p)...\n", 
            WorkerContext->Thread,
            TargetThreadObject);
        
        /* TODO : Find a way to gurantee the ETHREAD uniqueness! */
        while (TargetThreadObject) {

            Status = KeWaitForSingleObject(TargetThreadObject,
                Executive,
                KernelMode,
                FALSE,
                &Timeout);

            if (WorkerContext->Exit) {

                DoTraceMessage("Worker (0x%p) extiting...\n", WorkerContext->Thread);

                return;
            }

            if (Status == STATUS_SUCCESS)
                break;
        }
        
        for (ULONG i = 0; i < MAX_THREAD_COUNT; i++) {

            if (_g_WorkersContext[i].TargetThreadObject == TargetThreadObject) {

                InterlockedExchange((VOLATILE LONG*)&_g_WorkersContext[i].TargetThreadObject, (LONG)0);
                _g_ActiveThreadsCount--;
                break;
            }
        }

        KeResetEvent(&WorkerContext->WaitEvent);
        WorkerContext->Busy = FALSE;
        
        DoTraceMessage("Target (0x%p) Thread finished, removed from locations table, set worker (0x%p) free!\n",
            TargetThreadObject, WorkerContext->Thread);

        TargetThreadObject = NULL;
    }
}


NTSTATUS
InitTraceWorkerThreads(
    VOID
    )
{
    NTSTATUS Status;
    HANDLE Thread;
    RtlZeroMemory(_g_WorkersContext, sizeof(_g_WorkersContext));

    for (ULONG i = 0; i < MAX_THREAD_COUNT; i++) {

        KeInitializeEvent(&_g_WorkersContext[i].WaitEvent,
            NotificationEvent,
            FALSE);

        Status = PsCreateSystemThread(&Thread,
            0,
            NULL,
            NULL,
            NULL,
            WaitAndCleanUpTracedThread,
            &_g_WorkersContext[i]);

        if (!NT_SUCCESS(Status)) {

            DoTraceMessage("Faild to start the worker thread!\n");

            FreeTraceWorkerThreads();
            return Status;
        }

        _g_WorkersContext[i].Thread = Thread;
    }

    DoTraceMessage("Sucessfully initiated %d worker threads.\n", MAX_THREAD_COUNT);

    return STATUS_SUCCESS;
}


VOID
FreeTraceWorkerThreads(
    VOID
    )
{
    NTSTATUS Status;
    PVOID ThreadObject;

    for (ULONG i = 0; i < MAX_THREAD_COUNT; i++) {

        if (_g_WorkersContext[i].Thread == NULL)
            continue;

        _g_WorkersContext[i].Exit = TRUE;
        KeSetEvent(&_g_WorkersContext[i].WaitEvent, 0, FALSE);

        Status = ObReferenceObjectByHandle(_g_WorkersContext[i].Thread,
            SYNCHRONIZE,
            *PsThreadType,
            KernelMode,
            &ThreadObject,
            NULL);

        if (NT_SUCCESS(Status)) {

            KeWaitForSingleObject(ThreadObject,
                Executive,
                KernelMode,
                FALSE,
                NULL);

            ObDereferenceObject(ThreadObject);
        }

        ZwClose(_g_WorkersContext[i].Thread);
    }
}


PULONG
GetThreadPrevLocationAddress(
    VOID
    )
{
    ULONG Occupied = 0;
    PETHREAD CurrThreadObject = PsGetCurrentThread();
    if (CurrThreadObject == NULL)
        return &_g_TmpPrevLocation; /* This should never happen! */

    for (ULONG i = 0; i < MAX_THREAD_COUNT; i++) {
        if (CurrThreadObject == _g_WorkersContext[i].TargetThreadObject) {

            _mm_prefetch((CONST PCHAR) &_g_WorkersContext[i].PrevLocation, _MM_HINT_T0);
            return (&_g_WorkersContext[i].PrevLocation);
        }

        if (CurrThreadObject != NULL)
            Occupied++;

        if (Occupied >= _g_ActiveThreadsCount)
            break;
    }

    for (ULONG i = 0; i < MAX_THREAD_COUNT; i++) {

        if (InterlockedCompareExchange(&_g_WorkersContext[i].Busy, TRUE, FALSE) == FALSE) {

            _g_WorkersContext[i].TargetThreadObject = CurrThreadObject;
            _g_WorkersContext[i].PrevLocation = 0;
            _g_ActiveThreadsCount++;

            KeSetEvent(&_g_WorkersContext[i].WaitEvent, 0, FALSE);

            _mm_prefetch((CONST PCHAR) &_g_WorkersContext[i].PrevLocation, _MM_HINT_T0);
            return (&_g_WorkersContext[i].PrevLocation);
        }
    }

    DoTraceMessage("Exceeded maximum number of available worker threads!\n");
    return &_g_TmpPrevLocation; /* This should never happen! */
}


VOLATILE
VOID
STDCALL
InstrumentionBridgeOnEdgeTransition(
    _In_ ULONG BlockAddress,
    _In_ ULONG BlockId,
    _In_ ULONG IsNewBlock,
    _In_ ULONG Hash
    )
{
    UpdateSimpleCounters(BlockAddress, IsNewBlock, Hash);
    RecordBlockCoverageInfo(BlockAddress);

#ifdef __DEBUG_ECOV
    if (IsNewBlock)
        AddCoverageInfoToDump(_g_PrevLocAddr, 
            _g_PrevBlockId,
            BlockAddress, 
            BlockId,
            Hash);
#endif
    
    /* call further instrumentation function here... */
}


NAKED
VOID
STDCALL
CallOnEdgeTransition(
    _In_ ULONG BlockAddress,
    _In_ ULONG BlockId
    )
{
    /* TODO: optimize this if possible!

       Be aware that we can't use XMM registers to replace the stack pushes, 
       because thread scheduler wont save floating-point register and
       cost of calling KeSave/KeRestore is much more than a bunch of stack pushes.

       On x64 we can use SSE registers (XMM) without calling KeSave/KeRestore,
       but they are part of calling-convention so further analysis required 
       to deduce the free registers at each block :(

       Kernel stack is guaranteed to be resident in memory, but kernel might occasionally
       page out stack of inactive threads, this can't happen to us,
       so push instructions are safe.

       PsGetCurrentProcessId can cause #PF
    */
    __asm
    {
        push    ebp
        mov     ebp, esp
        /*  save GP regs ... */
        push    eax
        push    ebx
        push    ecx
        push    edx
        push    esi
        push    edi

        call    StatusFitForTracing
        test    eax, eax
        jz      __no_trace

#ifdef __DEBUG_ECOV
        mov     ecx, dword ptr[ebp + 0x08]
        mov     _g_PrevLocAddr, ecx
        mov     ecx, dword ptr[ebp + 0x0c]
        mov     _g_PrevBlockId, ecx
#endif

        /* CurrLocation = BlockId;
           _g_EdgeTransitionMap[CurrLocation ^ PrevLocation] = 1;
           PrevLocation = CurrLocation;
        */
        call    GetThreadPrevLocationAddress
        mov     edx, [eax]
        mov     ecx, dword ptr[ebp + 0x0c]         /* BlockId */
        xor     edx, ecx
        shr     ecx, 1
        mov     [eax], ecx

        mov     cl, 1
        xor     eax, eax
        mov     esi, _g_EdgeTransitionMap
        lock    cmpxchg byte ptr[esi + edx], cl
        btc     eax, 0

        push    edx                                 /* Hash            */
        push    eax                                 /* IsNewBlock      */
        push    dword ptr[ebp + 0x0c]               /* BlockId         */
        push    dword ptr[ebp + 0x08]               /* BlockAddress    */
        call    InstrumentionBridgeOnEdgeTransition

__no_trace:
        /* restore GP regs ... */ 
        pop     edi
        pop     esi
        pop     edx
        pop     ecx
        pop     ebx
        pop     eax

        pop     ebp
        retn    8
    }
}


NAKED
VOID
STDCALL
CallOnEdgeTransitionEvent(
    _In_ ULONG BlockAddress,
    _In_ ULONG BlockId
    )
{
    __asm
    {
        push    ebp
        mov     ebp, esp
        /*  save GP regs ... */
        push    eax
        push    ebx
        push    ecx
        push    edx
        push    esi
        push    edi

        mov     ecx, dword ptr[ebp + 0x08]
        push    ecx
        call    SingalFocusBlockEvent

        call    StatusFitForTracing
        test    eax, eax
        jz      __no_trace

#ifdef __DEBUG_ECOV
        mov     ecx, dword ptr[ebp + 0x08]
        mov     _g_PrevLocAddr, ecx
        mov     ecx, dword ptr[ebp + 0x0c]
        mov     _g_PrevBlockId, ecx
#endif

        /* CurrLocation = BlockId;
           _g_EdgeTransitionMap[CurrLocation ^ PrevLocation] = 1;
           PrevLocation = CurrLocation;
        */
        call    GetThreadPrevLocationAddress
        mov     edx, [eax]
        mov     ecx, dword ptr[ebp + 0x0c]         /* BlockId */
        xor     edx, ecx
        shr     ecx, 1
        mov     [eax], ecx

        mov     cl, 1
        xor     eax, eax
        mov     esi, _g_EdgeTransitionMap
        lock    cmpxchg byte ptr[esi + edx], cl
        btc     eax, 0

        push    edx                                 /* Hash            */
        push    eax                                 /* IsNewBlock      */
        push    dword ptr[ebp + 0x0c]               /* BlockId         */
        push    dword ptr[ebp + 0x08]               /* BlockAddress    */
        call    InstrumentionBridgeOnEdgeTransition

__no_trace:
        /* restore GP regs ... */ 
        pop     edi
        pop     esi
        pop     edx
        pop     ecx
        pop     ebx
        pop     eax

        pop     ebp
        retn    8
    }
}
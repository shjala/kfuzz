/*
 * Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
 * All rights reserved.
 */

#include <ntifs.h>
#include <ntddk.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <Ntstrsafe.h>
#include <ntimage.h>
#pragma warning( disable : 4100 )

//#define __DEBUG_ECOV
#define __PROBE_CALLBACK_CHECK_IRQL             1
#define KFLOG_LOG_FILE_PATH                     L"\\??\\C:\\kflog.txt"
#define KFLOG_ECOV_DUMP_FILE_PATH               L"\\??\\C:\\kflog_ecov.dmp"

#define _countof(array)                         (sizeof(array) / sizeof(array[0]))
#define RVATOVA(a, b)                           ((PUCHAR)a+(ULONG)b)
#define ROUND_UP(N, S)				            ((((N) + (S) - 1) / (S)) * (S))

#define DBG_BREAK()                             __asm int 3
#define NAKED                                   __declspec( naked )
#define STDCALL						            __stdcall
#define VOLATILE                                volatile

#define KFLOG_POOL_EDGE_MAP_TAG			        (ULONG)'PMfK'
#define KFLOG_POOL_KPATCH_TAG			        (ULONG)'APfK'
#define KFLOG_POOL_KHT_TAG			            (ULONG)'THfK'
#define KFLOG_POOL_MT_TAG			            (ULONG)'TMfK'
#define KFLOG_POOL_BT_TAG			            (ULONG)'TBfK'

#define INST_NOP                                0x90
#define MAX_INST_LEN				            64

#define MAX_THREAD_COUNT                        64
#define MAX_FOCUS_BBL                           1024
#define HASH_TABALE_SIZE                        (1024 * 128)

#define TRACE_NONE                              0
#define TRACE_ALL                               1
#define TRACE_PID                               2
#define TRACE_KERNEL                            3
#define TRACE_USER                              4
#define KERNEL_PID                              (HANDLE)0x4

#define DBG_REPORT_TRESHOLD                     2000
#define DBG_MSG_SIZE                            2048
#define MB                                      1000000

#define EDGE_TRANS_MAP_SIZE_64M		            (64 * 1024 * 1024)      /* 64M */
#define MASK_24                                 (((UINT32)1<<24)-1)
#define BIT_SIZE_24                             24

#define KeYieldProcessor                        _mm_pause

#define KFLOG_DEVICE				            0x8000
#define KFL_IOCTL_BBL_INSERT_PROBE		        CTL_CODE(KFLOG_DEVICE, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_SET_TRACER_PID		        CTL_CODE(KFLOG_DEVICE, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_BBL_LIST_INSERT_PROBE         CTL_CODE(KFLOG_DEVICE, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_RESET_EDGE_TRANS_MAP          CTL_CODE(KFLOG_DEVICE, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_ENABLE_MEMORY_TRACKING        CTL_CODE(KFLOG_DEVICE, 0x805, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_GET_BBL_COV_CAPTURES          CTL_CODE(KFLOG_DEVICE, 0x806, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_SET_TRACE_STATUS		        CTL_CODE(KFLOG_DEVICE, 0x807, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_SET_TRACE_IRQL		        CTL_CODE(KFLOG_DEVICE, 0x808, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_SET_CAPTURE_STATUS            CTL_CODE(KFLOG_DEVICE, 0x809, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_GET_CAPTURE_STATUS            CTL_CODE(KFLOG_DEVICE, 0x80A, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_SET_FOCUS_BBL_EVENT           CTL_CODE(KFLOG_DEVICE, 0x80B, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

typedef
VOID
HASH_RECORD_ROUTINE(
    _In_ PVOID Context
);
typedef HASH_RECORD_ROUTINE* PHASH_RECORD_ROUTINE;


typedef struct _DBG_DUMP_ECOV {
    ULONG PrevBlockAddr;
    ULONG PrevBlockId;
    ULONG CurrBlockAddr;
    ULONG CurrBlockId;
    ULONG Hash;
} DBG_DUMP_ECOV, *PDBG_DUMP_ECOV;


typedef struct _WORKER_THREAD_CONTEXT {
    VOLATILE LONG Busy;
    BOOLEAN Exit;
    HANDLE Thread;

    KEVENT WaitEvent;
    VOLATILE PETHREAD TargetThreadObject;
    ULONG PrevLocation;
} WORKER_THREAD_CONTEXT, *PWORKER_THREAD_CONTEXT;


typedef struct _FOCUS_BBL_ENTRY {
    PVOID Address;
    HANDLE Event;
} FOCUS_BBL_ENTRY, *PFOCUS_BBL_ENTRY;


typedef struct _KERNEL_FOCUS_BBL_ENTRY {
    PVOID Address;
    PKEVENT Event;
} KERNEL_FOCUS_BBL_ENTRY, *PKERNEL_FOCUS_BBL_ENTRY;


typedef struct _FOCUS_BBL_LIST {
    PKERNEL_FOCUS_BBL_ENTRY Entries;
    ULONG Count;
}FOCUS_BBL_LIST, *PFOCUS_BBL_LIST;


typedef struct _PAGE_LOCK { 
    PVOID Address;
    PMDL Mdl;
} PAGE_LOCK, *PPAGE_LOCK;


typedef struct _COPY_CONTEXT {
    PVOID Destination;
    PVOID Replacement;
    ULONG Length;

    ULONG ProcessorNumber;
    LONG VOLATILE ProcessorsBarrier;
    LONG VOLATILE ProcessorsToResume;
    LOGICAL VOLATILE Done;
} COPY_CONTEXT, *PCOPY_CONTEXT;


typedef struct _HASH_TABLE {
    PVOID* HashTable;
    ULONG Capacity;
} HASH_TABLE, *PHASH_TABLE;


typedef struct _HT_RECORD_LIST {
    struct _HT_RECORD_LIST* Next;
    ULONG Key;
    PVOID Record;
} HT_RECORD_LIST, *PHT_RECORD_LIST;


typedef struct _BBL_TRACKING_ENTRY {
    PVOID Address;
    ULONG64 HitCount;
} BBL_TRACKING_ENTRY, * PBBL_TRACKING_ENTRY;


typedef struct _MEM_TRACKING_ENRTY {
    PVOID Address;
    ULONG Size;
    ULONG Type;
} MEM_TRACKING_ENRTY, *PMEM_TRACKING_ENRTY;


typedef struct _MEM_TRACKING_API_HOOKS {
    CHAR Name[128];
    PVOID Replacement;
} MEM_TRACKING_API_HOOKS, *PMEM_TRACKING_API_HOOKS;


typedef struct _MEM_TRACKING_APIS_INFO {
    CHAR Name[128];
    PVOID IATAddress;
} MEM_TRACKING_APIS_INFO, *PMEM_TRACKING_APIS_INFO;


#pragma pack(push, 1)
typedef struct _BASICBLOCK_ADDR_INFO {
    CHAR ImageName[32];
    PVOID Address;
    ULONG Length;
    ULONG CopyLength;
    ULONG IsFocusBlock;
} BASICBLOCK_ADDR_INFO, *PBASICBLOCK_ADDR_INFO;
#pragma pack(pop)


typedef struct _PATCH_RECORD {
    UCHAR OrginalBytes[MAX_INST_LEN];
    ULONG Length;
    PVOID Address;
    PVOID ProbeAddress;
} PATCH_RECORD, *PPATCH_RECORD;


typedef struct _PATCH_RECORD_LIST {
    LIST_ENTRY List;
    PATCH_RECORD PatchRecord;
} PATCH_RECORD_LIST, *PPATCH_RECORD_LIST;


typedef struct _SHARED_MEMORY
{
    PVOID UserAddress;
    PVOID KernelAddress;
    ULONG UserProcessId;
    PMDL SharedMdl;
} SHARED_MEMORY, *PSHARED_MEMORY;


typedef struct _BASIC_BLOCK_COUNTER {
    ULONG Counter;
    ULONG64 Record;
} BASIC_BLOCK_COUNTER, *PBASIC_BLOCK_COUNTER;


typedef struct _EDGE_COUNTER {
    ULONG Counter;
    ULONG64 Record;
} EDGE_COUNTER, *PEDGE_COUNTER;


typedef struct _MEM_COUNTER {
    ULONG64 AllocCounter;
    ULONG64 FreeCounter;
    ULONG Record;
} MEM_COUNTER, *PMEM_COUNTER;


typedef struct _CC_CAPTURE {
    ULONG Record;
} CC_CAPTURE, *PCC_CAPTURE;


typedef struct _KT_CAPTURE
{
    struct {
        /* Edges and Bbls are basically same */
        EDGE_COUNTER NewEdges;
        BASIC_BLOCK_COUNTER Bbls;
        /* Memory */
        MEM_COUNTER Memory;
    } Counters;

    struct {
        /* Coverage */
        CC_CAPTURE CodeCov;
    } Extended;

} KT_CAPTURE, *PKT_CAPTURE;


VOID
KflogUnload(
    _In_ PDRIVER_OBJECT DriverObject
    );


NTSTATUS
KflogDeviceClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
    );


NTSTATUS
KflogDeviceCleanUp(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
    );


NTSTATUS
KflogDeviceCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
    );


NTSTATUS
KflogDeviceDispatch(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
    );


NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject, 
    _In_ PUNICODE_STRING RegistryPath
    );


VOID
DoTraceMessage(
    _In_ PCCH  Format,
    ...
    );


#ifdef __DEBUG_ECOV
VOID
AddCoverageInfoToDump(
    __in ULONG PrevAddr,
    __in ULONG PrevId,
    __in ULONG CurrAddr,
    __in ULONG CurrId,
    __in ULONG Hash
    ) ;


NTSTATUS
DumpCoverageInfoToFile(
    VOID
    );   
#endif

NTSTATUS
LockKernelPage(
    _In_ PVOID Address,
    _In_ ULONG Length,
    _In_ LOCK_OPERATION LockMode,
    _Outptr_ PPAGE_LOCK PageLock
    );


VOID
UnlockKernelPage(
    _In_ PPAGE_LOCK PageLock
    );


NTSTATUS
RewriteKernelAddress(
    _In_ PVOID Destination,
    _In_ PVOID Replacement,
    _In_ ULONG Length,
    _Inout_ _Maybenull_ PUCHAR OrginalBytes
    );


ULONG_PTR
PerformSingleProccessorCopy(
    _In_ ULONG_PTR Context
    );


NTSTATUS
InitialiseSharedMemory(
    _In_ PSHARED_MEMORY  SharedMap, 
    _In_ ULONG           MapSize
    );


NTSTATUS
MapSharedMemoryToUsermode(
    _In_ PSHARED_MEMORY SharedMap
    );


VOID
UnmapSharedMemoryFromUsermode(
    _In_ PSHARED_MEMORY SharedMap
    );


VOID
DestroySharedMemory(
    _In_ PSHARED_MEMORY SharedMap
    );


NTSTATUS
AddPatchRecordToList(
    _In_ PVOID Address,
    _In_ ULONG Lenght,
    _In_opt_ _Maybenull_ PVOID ProbeAddress,
    _In_ PVOID OrginalBytes
    );


LOGICAL
IsAddressPatched(
    PVOID Address
    );

VOID
RestoreKernelPatches(
    VOID
    );


ULONG
GenBasicblockId(
    VOID
    );


PVOID
GetImportTableAddress(
    _In_ PVOID BaseAddress,
    _In_ PCSTR pszImportName
    );


PVOID
AllocTransitionProbe(
    _In_ PVOID Address,
    _In_ ULONG Identifier,
    _In_ ULONG CopyLength,
    _In_ ULONG ReturnAddress,
    _In_ ULONG CallbackAddress
    );


NTSTATUS
InsertEgdeTransitionProbeOnBasicBlock(
    _In_ PVOID Address,
    _In_ ULONG Length,
    _In_ ULONG CopyLength,
    _In_ ULONG IsFocusBlock
    );


ULONG
InsertEgdeTransitionProbeOnBasicBlockList(
    _In_ PBASICBLOCK_ADDR_INFO BlocksCollection,
    _In_ ULONG  Size
    );


VOID
STDCALL
CallOnEdgeTransition(
    _In_ ULONG BlockAddress,
    _In_ ULONG BlockId
    );


VOID
STDCALL
CallOnEdgeTransitionEvent(
    _In_ ULONG BlockAddress,
    _In_ ULONG BlockId
    );


VOLATILE
ULONG
STDCALL
StatusFitForTracing(
    VOID
    );


VOID
EnableMemoryTracking(
    _In_ PMEM_TRACKING_APIS_INFO APIsInfo,
    _In_ ULONG Length
    );


PHASH_TABLE
AllocateHashTable(
    _In_ ULONG Capacity
    );


NTSTATUS
AddRecordToHashTable(
    _In_ PHASH_TABLE hHashTable,
    _In_ PVOID Content,
    _In_ ULONG Key
    );


NTSTATUS
RemoveRecordFromHashTable(
    _In_ PHASH_TABLE hHashTable,
    _In_ ULONG Key
    );


PVOID
GetRecordFromHashTable(
    _In_ PHASH_TABLE hHashTable,
    _In_ ULONG Key
    );


PHT_RECORD_LIST
GetRecordListFromHashTable(
    _In_ PHASH_TABLE hHashTable,
    _In_ ULONG Key
    );


VOID
FreeHashTable(
    _In_ PHASH_TABLE HashTable
    );


VOID
ClearHashTable(
    _In_ PHASH_TABLE HashTable
    );


ULONG
CountHashTableRecords(
    _In_ PHASH_TABLE HashTable
    );


VOID
ApplyOnHashTableRecords(
    _In_ PHASH_TABLE HashTable,
    _In_ PHASH_RECORD_ROUTINE Routine
    );


NTSTATUS
CopyHashTableContent(
    _In_ PHASH_TABLE HashTable,
    _In_ ULONG RecordSize,
    _In_ PVOID Buffer,
    _In_ ULONG Size
    );


VOID
UpdateSimpleCounters(
    _In_ ULONG BlockAddress,
    _In_ LOGICAL IsNewBlock,
    _In_ ULONG Hash
    );


NTSTATUS
RecordBlockCoverageInfo(
    _In_ ULONG Address
    );


NTSTATUS
CopyBlockCoverageInfo(
    _In_ PVOID Buffer,
    _In_ PULONG pSize
    );


NTSTATUS
RegisterFocusBlockEvent(
    PFOCUS_BBL_ENTRY Entry
    );


VOLATILE
NTSTATUS
STDCALL
SingalFocusBlockEvent(
    PVOID Address
    );


VOID
ReleaseAllFocusEvents(
    VOID
    );


NTSTATUS
InitTraceWorkerThreads(
    VOID
    );


VOID
FreeTraceWorkerThreads(
    VOID
    );
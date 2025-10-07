/*
 * Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
 * All rights reserved.
 */

#ifndef KTRACE_HEADER_FILE_H
#define KTRACE_HEADER_FILE_H
#include "..\common.hpp"
#include <unordered_map>
#include <stdexcept>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

#define KFLOG_DEVICE				      0x8000
#define KFL_IOCTL_BBL_INSERT_PROBE		  CTL_CODE(KFLOG_DEVICE, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_SET_TRACER_PID		  CTL_CODE(KFLOG_DEVICE, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_BBL_LIST_INSERT_PROBE   CTL_CODE(KFLOG_DEVICE, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_RESET_EDGE_TRANS_MAP    CTL_CODE(KFLOG_DEVICE, 0x804, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_ENABLE_MEMORY_TRACKING  CTL_CODE(KFLOG_DEVICE, 0x805, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_GET_BBL_COV_CAPTURES    CTL_CODE(KFLOG_DEVICE, 0x806, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_SET_TRACE_STATUS		  CTL_CODE(KFLOG_DEVICE, 0x807, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_SET_TRACE_IRQL		  CTL_CODE(KFLOG_DEVICE, 0x808, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_SET_CAPTURE_STATUS      CTL_CODE(KFLOG_DEVICE, 0x809, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_GET_CAPTURE_STATUS      CTL_CODE(KFLOG_DEVICE, 0x80A, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KFL_IOCTL_SET_FOCUS_BBL_EVENT     CTL_CODE(KFLOG_DEVICE, 0x80B, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)


#define STATUS_SUCCESS                    ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL               ((NTSTATUS)0xC0000001L)
#define STATUS_INFO_LENGTH_MISMATCH       ((NTSTATUS)0xC0000004L)
#define STATUS_INVALID_BUFFER_SIZE        ((NTSTATUS)0xC0000206L)

#define OFFSET_TO_KERNEL_ADDR(a,b)        ((ULONG)a + (ULONG)b)
#define RVATOVA(a, b)                     ((PUCHAR)a+(ULONG)b)

char* strstri(const char* s1, const char* s2)
{
    return StrStrIA(s1, s2);
}

unsigned long djb2_hash(unsigned char* str)
{
    unsigned long hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

namespace ktrace {

const ULONG MAX_IMAGE_NAME_LEN = 32;
const ULONG MAX_API_NAME_LEN = 128;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

typedef struct tagSYSTEM_MODULE_INFORMATION {
    ULONG Reserved[2];
    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT Unknown;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef NTSTATUS(WINAPI* NTQUERYSYSTEMINFORMATION)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

/* BasicBlock info */
#pragma pack(push, 1)
    typedef struct _BASICBLOCK_ADDR_INFO {
        CHAR ImageName[MAX_IMAGE_NAME_LEN];
        ULONG Address;
        ULONG Size;
        ULONG CopyLength;
        ULONG IsFocusBlock;
    } BASICBLOCK_ADDR_INFO, *PBASICBLOCK_ADDR_INFO;

    typedef struct _BASICBLOCK_ADDR {
        ULONG Address;
        ULONG Size;
        ULONG CopyLength;
    } BASICBLOCK_ADDR, *PBASICBLOCK_ADDR;
#pragma pack(pop)


typedef struct _TRACKED_MODULE_INFO {
    CHAR ImageName[MAX_IMAGE_NAME_LEN];
    ULONG ImageNameHash;
    ULONG Address;
    ULONG Size;
} TRACKED_MODULE_INFO, *PTRACKED_MODULE_INFO;;

typedef struct _FOCUS_BBL_ENTRY {
    PVOID Address;
    HANDLE Event;
} FOCUS_BBL_ENTRY, *PFOCUS_BBL_ENTRY;

typedef struct _ADDR_BLOCK_HEADER {
    ULONG AddressCount;
    PCHAR ImageName;
} ADDR_BLOCK_HEADER, *PADDR_BLOCK_HEADER;


typedef struct _BBL_TRACKING_ENTRY {
    PVOID Address;
    ULONG64 HitCount;
} BBL_TRACKING_ENTRY, *PBBL_TRACKING_ENTRY;

typedef struct _FILE_BBL_TRACKING_ENTRY {
    ULONG ImageNameHash;
    ULONG Address;
    ULONG64 HitCount;
} FILE_BBL_TRACKING_ENTRY, *PFILE_BBL_TRACKING_ENTRY;


typedef struct _BASIC_BLOCK_COUNTER {
    ULONG64 Counter;
    ULONG Record;
} BASIC_BLOCK_COUNTER, *PBASIC_BLOCK_COUNTER;

typedef struct _EDGE_COUNTER {
    ULONG64 Counter;
    ULONG Record;
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


typedef struct _MEM_TRACKING_APIS_INFO {
    CHAR Name[128];
    PVOID IATAddress;
} MEM_TRACKING_APIS_INFO, *PMEM_TRACKING_APIS_INFO;

MEM_TRACKING_APIS_INFO kMemAPIsInfo[] = {
    {"NtAllocateVirtualMemory",       NULL},
    {"ZwAllocateVirtualMemory",       NULL},
    {"ExAllocatePool",                NULL},
    {"ExAllocatePoolWithTag",         NULL},
    {"ExAllocatePoolWithTagPriority", NULL},
    {"ExFreePoolWithTag",             NULL},
    {"NtFreeVirtualMemory",           NULL},
    {"ZwFreeVirtualMemory",           NULL},
};


enum class CAPTURE { 
    ALL,
    EDGE,
    BBL,
    MEMORY,
    CODE_COV
};

enum class QUERY {
    EDGE,
    BBL,
    MEMORY_ALLOC,
    MEMORY_FREE
};

enum class TRACE {
    NONE,
    ALL,
    PID,
    KERNEL,
    USER
};


class Tracer {
public:

#ifdef __DEBUG_MOCK_KT
    Tracer(ULONG TracerPid = 0) {}
    BOOL TraceCodeCoverage(const std::string& BasicBlockFile) { return TRUE; }
    BOOL TraceMemoryAllocations(const std::string& ModuleName, const std::string& ModulePath) { return TRUE; }
    BOOL TracerPID(const ULONG TracerPid) { return TRUE; }
    BOOL TraceStatus(const TRACE Status) { return TRUE; }
    BOOL TraceLevel(const ULONG IrqlLevel) { return TRUE; }
    VOID StartRecording(CAPTURE Counter = CAPTURE::ALL) {}
    VOID StopRecording(CAPTURE Counter = CAPTURE::ALL) {}
    BOOL UpdateCounters(VOID) { return TRUE; }
    BOOL ResetCounters(VOID) { return TRUE; }
    ULONG64 QueryCounter(QUERY Counter, BOOL Reset = TRUE) { return rand() % 100 < 90? 0 : 1; }
    VOID ClearCounters(VOID) {}
    ULONG GetLoadedBasicBlocks(VOID) { return 0; }
    ULONG GetPatchedBasicBlocks(VOID) { return 0; }
    VOID ResetEdgeTransMap(VOID) {}
    VOID SaveCoverageCapture(const std::string FilePath) {}
    HANDLE RegisterFocusBlockEvent(ULONG Address, const std::string& ImageName) { return CreateEvent(NULL, TRUE, FALSE, NULL); }
#else

    Tracer(ULONG TracerPid = GetCurrentProcessId()) {
        /* get the the KFlog driver handle */
        hKrnTracerHandle = GetKflogDriverHandle();
        if (hKrnTracerHandle == INVALID_HANDLE_VALUE)
            throw std::runtime_error("Invalid KFLOG driver handle");

        LOG_DBG("KFLOG driver handle at 0x%p.\n", hKrnTracerHandle);

        if (SetUsermodeTracerPid(TracerPid) == FALSE)
            throw std::runtime_error("Failed to set tracer PID");

        LOG_DBG("Set tracer PID to %.8\n", TracerPid);

        ClearCounters();
    }

    BOOL TraceCodeCoverage(const std::string& BasicBlockFile) {
        /* Insert the instrumentation probe from basic-block informations file */
        return SetProbeOnBasicBlocksFromFile((CONST PCHAR)BasicBlockFile.c_str());
    }
    
    BOOL TraceMemoryAllocations(const std::string& ModuleName, const std::string& ModulePath) {
        ULONG Address;
        ULONG AddrSpaceSize;

        /* Get the driver image base at run-time */
        BOOL Result = GetTargetDriverImageBase((CONST PCHAR)ModuleName.c_str(),
            &Address, &AddrSpaceSize);

        if (!Result)
            return Result;

        for (ULONG i = 0; i < _countof(kMemAPIsInfo); i++) {

            ULONG Offset = GetImportTableOffset((CONST PCHAR)ModulePath.c_str(), kMemAPIsInfo[i].Name);
            if (Offset != 0)
                kMemAPIsInfo[i].IATAddress = (PVOID)(Address + Offset);
        }

        Result = EnableMemoryTracing((PMEM_TRACKING_APIS_INFO)&kMemAPIsInfo, sizeof(kMemAPIsInfo));
        return Result;
    }

    BOOL TracerPID(const ULONG TracerPid) {
        if (SetUsermodeTracerPid(TracerPid) == FALSE)
            return FALSE;

        LOG_DBG("Set tracer PID to %d.\n", TracerPid);

        return TRUE;
    }

    BOOL TraceStatus(const TRACE Status) {
        if (SetTraceStatus((ULONG)Status) == FALSE)
            return FALSE;

        LOG_DBG("Set tracer status to %d.\n", Status);
        return TRUE;
    }

    BOOL TraceLevel(const ULONG IrqlLevel) {
        if (SetTraceIRQL(IrqlLevel) == FALSE)
            return FALSE;

        LOG_DBG("Set tracer IRQL to %d.\n", IrqlLevel);
        return TRUE;
    }

    VOID StartRecording(CAPTURE Counter = CAPTURE::ALL) {
        if (Counter != CAPTURE::ALL) {
            return SetCounterRecordStatus(Counter, 1);
        }
        else {
            SetCounterRecordStatus(CAPTURE::EDGE, 1);
            SetCounterRecordStatus(CAPTURE::BBL, 1);
            SetCounterRecordStatus(CAPTURE::MEMORY, 1);
            SetCounterRecordStatus(CAPTURE::CODE_COV, 1);
        }

        SetCaptureStatus(&KtCapture);
    }

    VOID StopRecording(CAPTURE Counter = CAPTURE::ALL) {
        /* Get status and only set the flags to zero, preserving the counters */
        GetCaptureStatus(&KtCapture);

        if (Counter != CAPTURE::ALL) {
            return SetCounterRecordStatus(Counter, 0);
        }
        else {

            SetCounterRecordStatus(CAPTURE::EDGE, 0);
            SetCounterRecordStatus(CAPTURE::BBL, 0);
            SetCounterRecordStatus(CAPTURE::MEMORY, 0);
            SetCounterRecordStatus(CAPTURE::CODE_COV, 0);
        }

        SetCaptureStatus(&KtCapture);
    }

    BOOL UpdateCounters(VOID) {

        return GetCaptureStatus(&KtCapture);
    }

    BOOL ResetCounters(VOID) {

        KtCapture.Counters.NewEdges.Counter = 0;
        KtCapture.Counters.Bbls.Counter = 0;
        KtCapture.Counters.Memory.AllocCounter = 0;
        KtCapture.Counters.Memory.FreeCounter = 0;
        return SetCaptureStatus(&KtCapture);
    }

    ULONG64 QueryCounter(QUERY Counter, BOOL Reset = TRUE) {
        ULONG64 Count;
       
        switch (Counter) {
            case QUERY::EDGE:
                return KtCapture.Counters.NewEdges.Counter;
            case QUERY::BBL:
                return KtCapture.Counters.Bbls.Counter;
            case QUERY::MEMORY_ALLOC:
                return KtCapture.Counters.Memory.AllocCounter;
            case QUERY::MEMORY_FREE:
                return KtCapture.Counters.Memory.FreeCounter;
        }

        return -1;
    }

    VOID ClearCounters(VOID) {
        RtlSecureZeroMemory(&KtCapture, sizeof(KT_CAPTURE));
        SetCaptureStatus(&KtCapture);
    }

    ULONG GetLoadedBasicBlocks(VOID) {

        return FileBasicBlock;
    }

    ULONG GetPatchedBasicBlocks(VOID) {

        return PatchedBasicBlocks;
    }

    VOID ResetEdgeTransMap(VOID) {

        ZeroEdgeTransitionMap();
    }

    VOID SaveCoverageCapture(const std::string FilePath) {
        std::lock_guard<std::mutex> Guard(*CovSaveLock);
        CopyCodeCoverageCapture((CONST PCHAR)FilePath.c_str());
    }
    
    HANDLE RegisterFocusBlockEvent(ULONG Address, const std::string& ImageName) {
        HANDLE Event;

        Event = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (Event == NULL) {
            LOG_INFO("Failed to create event!\n");
            return NULL;
        }
            
        FOCUS_BBL_ENTRY Entry;
        Entry.Address = (PVOID)GetKernelAddress(Address, (PCHAR)ImageName.c_str());
        Entry.Event = Event;

        if (SetFocusBlockEntry(&Entry)) {
            FocusBlocks.push_back((ULONG)Entry.Address);

            LOG_INFO("Successfully registered an event for address 0x%p.\n", Entry.Address);
            return Event;
        }
        
        CloseHandle(Event);
        return NULL;
    }

#endif

private:
    CONST PCHAR kKflogDeviceName = (PCHAR)"\\\\.\\kflog";
    std::unordered_map<ULONG, TRACKED_MODULE_INFO> TrackedModules;
    std::vector<ULONG> FocusBlocks;
    std::mutex* CovSaveLock = new std::mutex();
    CONST ULONG kBblFileBlockSig = 0x42424C58;
    CONST ULONG kInvalidBblAddress = 0;
    ULONG FileBasicBlock, PatchedBasicBlocks = 0;
    HANDLE hKrnTracerHandle = INVALID_HANDLE_VALUE;
    KT_CAPTURE KtCapture;

    HANDLE GetKflogDriverHandle(VOID) {
        HANDLE hDevice;

        hDevice = CreateFile(kKflogDeviceName,
            GENERIC_WRITE | GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        return hDevice;
    }

    ULONG SetProbeOnBasicBlockList(CONST PVOID BasicBlocksList, ULONG Size) {
        BOOL Result;
        ULONG HookCount = 0;
        ULONG BytesReturned;

        Result = DeviceIoControl(hKrnTracerHandle,
            KFL_IOCTL_BBL_LIST_INSERT_PROBE,
            BasicBlocksList,
            Size,
            &HookCount,
            sizeof(ULONG),
            &BytesReturned,
            NULL);

        return HookCount;
    }

    BOOL SetFocusBlockEntry(PFOCUS_BBL_ENTRY Entry) {
        BOOL Result;
        ULONG BytesReturned;

        Result = DeviceIoControl(hKrnTracerHandle,
            KFL_IOCTL_SET_FOCUS_BBL_EVENT,
            Entry,
            sizeof(FOCUS_BBL_ENTRY),
            NULL,
            0,
            &BytesReturned,
            NULL);

        return Result;
    }

    BOOL SetUsermodeTracerPid(ULONG Pid) {
        BOOL Result;
        ULONG BytesReturned;
        ULONG TracerPid = Pid;

        Result = DeviceIoControl(hKrnTracerHandle,
            KFL_IOCTL_SET_TRACER_PID,
            &TracerPid,
            sizeof(ULONG),
            NULL,
            0,
            &BytesReturned,
            NULL);

        return Result;
    }

    BOOL SetTraceStatus(ULONG Status) {
        BOOL Result;
        ULONG BytesReturned;
        ULONG TraceStatus = Status;

        Result = DeviceIoControl(hKrnTracerHandle,
            KFL_IOCTL_SET_TRACE_STATUS,
            &TraceStatus,
            sizeof(ULONG),
            NULL,
            0,
            &BytesReturned,
            NULL);

        return Result;
    }

    BOOL SetTraceIRQL(ULONG IRQL) {
        BOOL Result;
        ULONG BytesReturned;
        ULONG TraceIRQL = IRQL;

        Result = DeviceIoControl(hKrnTracerHandle,
            KFL_IOCTL_SET_TRACE_IRQL,
            &TraceIRQL,
            sizeof(ULONG),
            NULL,
            0,
            &BytesReturned,
            NULL);

        return Result;
    }

    BOOL ZeroEdgeTransitionMap(VOID) {
        BOOL Result;

        Result = DeviceIoControl(hKrnTracerHandle,
            KFL_IOCTL_RESET_EDGE_TRANS_MAP,
            NULL,
            0,
            NULL,
            0,
            NULL,
            NULL);

        return Result;
    }

    BOOL SetCaptureStatus(CONST PKT_CAPTURE pKtCapture) {
        BOOL Result;
        ULONG BytesReturned;

        Result = DeviceIoControl(hKrnTracerHandle,
            KFL_IOCTL_SET_CAPTURE_STATUS,
            pKtCapture,
            sizeof(KT_CAPTURE),
            NULL,
            0,
            &BytesReturned,
            NULL);

        return Result;
    }

    BOOL GetCaptureStatus(PKT_CAPTURE pKtCapture) {
        BOOL Result;
        ULONG BytesReturned;

        Result = DeviceIoControl(hKrnTracerHandle,
            KFL_IOCTL_GET_CAPTURE_STATUS,
            NULL,
            0,
            pKtCapture,
            sizeof(KT_CAPTURE),
            &BytesReturned,
            NULL);

        return Result;
    }

    BOOL EnableMemoryTracing(CONST PMEM_TRACKING_APIS_INFO MemAPIs, ULONG Size) {
        BOOL Result;
        ULONG BytesReturned;

        Result = DeviceIoControl(hKrnTracerHandle,
            KFL_IOCTL_ENABLE_MEMORY_TRACKING,
            MemAPIs,
            Size,
            NULL,
            0,
            &BytesReturned,
            NULL);

        return Result;
    }

    ULONG GetKernelAddress(ULONG Offset, CONST PCHAR ImageName) {
        ULONG Address = 0, AddrSpaceSize = 0;

        /* Get the driver image base at run-time */
        BOOL Result = GetTargetDriverImageBase(ImageName, &Address,
            &AddrSpaceSize);

        if (!Result)
            return 0;

        return OFFSET_TO_KERNEL_ADDR(Address, Offset);
    }

    BOOL SetProbeOnBasicBlocksFromFile(CONST PCHAR szFilePath) {
        PBASICBLOCK_ADDR_INFO pBlockArray = NULL;
        CHAR szCurrentImageName[MAX_PATH] = { 0 };
        ULONG Address = 0, AddrSpaceSize = 0;

        if (szFilePath == NULL || strlen(szFilePath) <= 0) {
            LOG_ERR("Invalid basic-block file path");
            return FALSE;
        }

        FileBasicBlock = GetBasicBlocksOffsetFromFile(szFilePath, &pBlockArray);
        LOG_INFO("Found %d valid basic-block addresses in file.\n", FileBasicBlock);

        for (ULONG i = 0; i < FileBasicBlock; i++) {

            if (pBlockArray[i].Address != kInvalidBblAddress && pBlockArray[i].Size > 0) {

                if (strncmp(szCurrentImageName, pBlockArray[i].ImageName, MAX_IMAGE_NAME_LEN) != 0) {

                    /* Get the driver image base at run-time */
                    BOOL Result = GetTargetDriverImageBase(pBlockArray[i].ImageName, &Address,
                        &AddrSpaceSize);

                    if (!Result) {

                        LOG_ERR("Failed to get driver image info!\n");

                        HEAP_FREE(pBlockArray);
                        return FALSE;
                    }

                    strncpy_s(szCurrentImageName, pBlockArray[i].ImageName, MAX_IMAGE_NAME_LEN);
                    AddModuleToList(szCurrentImageName, Address, AddrSpaceSize);
                }

                ULONG ulAbsoluteBlockAddress = OFFSET_TO_KERNEL_ADDR(Address, pBlockArray[i].Address);
                pBlockArray[i].Address = ulAbsoluteBlockAddress;
                for (ULONG& Addr : FocusBlocks) {
                    if (Addr >= pBlockArray[i].Address && Addr < (pBlockArray[i].Address + pBlockArray[i].Size)) {
                        pBlockArray[i].IsFocusBlock = 1;

                        LOG_INFO("Place event handler for block at address 0x%p\n", Addr);
                    }
                }
            }
        }

        LOG_INFO(AC_YELLOW "Trying to set probes on %d basic-blocks, this might take a few moments,\n"
                "Use Dbgview to see some progress infromation...\n" AC_RESET, FileBasicBlock);

        PatchedBasicBlocks = SetProbeOnBasicBlockList(pBlockArray, 
            sizeof(BASICBLOCK_ADDR_INFO) * FileBasicBlock);

        LOG_INFO(AC_GREEN "Successfully" AC_RESET " patched " AC_YELLOW "(%d/%d)" AC_RESET " of enumerated basic-blocks.\n" ,
            PatchedBasicBlocks, FileBasicBlock);

        HEAP_FREE(pBlockArray);
        return TRUE;
    }

    ULONG GetBasicBlocksOffsetFromFile(CONST PCHAR szFilePath, PBASICBLOCK_ADDR_INFO* pAddressInfo) {
        ULONG BlocksRead = 0;
        HANDLE hFile = CreateFile(szFilePath,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (hFile == INVALID_HANDLE_VALUE)
            return 0;

        ULONG dwFileSize = GetFileSize(hFile, NULL);
        if (dwFileSize == 0) {

            CloseHandle(hFile);
            return 0;
        }

        ADDR_BLOCK_HEADER BlockHeader;
        PBASICBLOCK_ADDR pBasicBlockAddr;
        PBASICBLOCK_ADDR_INFO pReadAddrInfo = NULL;
        while (GetCurrentAddressBlockHeader(hFile, &BlockHeader)) {

            pBasicBlockAddr = (PBASICBLOCK_ADDR)HEAP_ALLOC(BlockHeader.AddressCount * sizeof(BASICBLOCK_ADDR));
            if (pBasicBlockAddr == NULL) {

                HEAP_FREE(BlockHeader.ImageName);
                CloseHandle(hFile);

                *pAddressInfo = pReadAddrInfo;
                return BlocksRead;
            }

            ULONG dwRead;
            BOOL Result = ReadFile(hFile, pBasicBlockAddr, BlockHeader.AddressCount * sizeof(BASICBLOCK_ADDR), &dwRead, NULL);
            if (!Result || dwRead != (BlockHeader.AddressCount * sizeof(BASICBLOCK_ADDR))) {

                HEAP_FREE(BlockHeader.ImageName);
                HEAP_FREE(pBasicBlockAddr);
                CloseHandle(hFile);

                *pAddressInfo = pReadAddrInfo;
                return BlocksRead;
            }

            if (pReadAddrInfo == NULL) {

                pReadAddrInfo = (PBASICBLOCK_ADDR_INFO)HEAP_ALLOC(BlockHeader.AddressCount * sizeof(BASICBLOCK_ADDR_INFO));
                if (pReadAddrInfo == NULL) {

                    HEAP_FREE(BlockHeader.ImageName);
                    HEAP_FREE(pBasicBlockAddr);
                    CloseHandle(hFile);
                    return 0;
                }
            }
            else {

                pReadAddrInfo = (PBASICBLOCK_ADDR_INFO)HeapReAlloc(GetProcessHeap(), 0, pReadAddrInfo,
                    (BlocksRead + BlockHeader.AddressCount) * sizeof(BASICBLOCK_ADDR_INFO));

                if (pReadAddrInfo == NULL) {

                    HEAP_FREE(BlockHeader.ImageName);
                    HEAP_FREE(pBasicBlockAddr);
                    CloseHandle(hFile);
                    return 0;
                }
            }

            for (ULONG i = 0; i < BlockHeader.AddressCount; i++) {

                pReadAddrInfo[i + BlocksRead].Address = pBasicBlockAddr[i].Address;
                pReadAddrInfo[i + BlocksRead].Size = pBasicBlockAddr[i].Size;
                pReadAddrInfo[i + BlocksRead].CopyLength = pBasicBlockAddr[i].CopyLength;
                strncpy_s(pReadAddrInfo[i + BlocksRead].ImageName, BlockHeader.ImageName, 32);
            }

            BlocksRead += BlockHeader.AddressCount;

            HEAP_FREE(BlockHeader.ImageName);
            HEAP_FREE(pBasicBlockAddr);
        }

        CloseHandle(hFile);
        *pAddressInfo = pReadAddrInfo;
        return BlocksRead;
    }

    BOOL GetCurrentAddressBlockHeader(CONST HANDLE hFile, PADDR_BLOCK_HEADER pHeader) {
        ULONG Read = 0;
        BOOL Result = FALSE;

        ULONG ulSignature;
        Result = ReadFile(hFile, &ulSignature, sizeof(ULONG), &Read, NULL);
        if (!Result || Read != sizeof(ULONG))
            return FALSE;

        if (ulSignature != kBblFileBlockSig)
            return FALSE;

        ULONG ulImageNameSize;
        Result = ReadFile(hFile, &ulImageNameSize, sizeof(ULONG), &Read, NULL);
        if (!Result || Read != sizeof(ULONG))
            return FALSE;

        if (ulImageNameSize > MAX_IMAGE_NAME_LEN)
            return FALSE;

        pHeader->ImageName = (PCHAR)HEAP_ALLOC(ulImageNameSize + 1);
        if (pHeader->ImageName == NULL)
            return FALSE;

        Result = ReadFile(hFile, pHeader->ImageName, ulImageNameSize, &Read, NULL);
        if (!Result || Read != ulImageNameSize) {

            HEAP_FREE(pHeader->ImageName);
            return FALSE;
        }

        Result = ReadFile(hFile, &pHeader->AddressCount, sizeof(ULONG), &Read, NULL);
        if (!Result || Read != sizeof(ULONG)) {

            HEAP_FREE(pHeader->ImageName);
            return FALSE;
        }

        if (pHeader->AddressCount == 0) {

            HEAP_FREE(pHeader->ImageName);
            return FALSE;
        }

        return TRUE;
    }

    BOOL GetTargetDriverImageBase(PCHAR DriverName, PULONG Address, PULONG AddrSpaceSize) {

        NTQUERYSYSTEMINFORMATION ZwQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(
            GetModuleHandle("NTDLL"), "ZwQuerySystemInformation");

        if (ZwQuerySystemInformation != NULL) {

            if (AddrSpaceSize == NULL || Address == NULL)
                return FALSE;

            ULONG dwNeedSize = 0;
            NTSTATUS Status;
            Status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &dwNeedSize);
            if (Status == STATUS_INFO_LENGTH_MISMATCH) {

                PBYTE Buffer = (PBYTE)HEAP_ALLOC(dwNeedSize);
                Status = ZwQuerySystemInformation(SystemModuleInformation, Buffer, dwNeedSize, &dwNeedSize);

                if (Status == STATUS_SUCCESS) {

                    ULONG Count = Buffer != NULL ? *((PULONG)Buffer) : 0;
                    PSYSTEM_MODULE_INFORMATION pmi = (PSYSTEM_MODULE_INFORMATION)(Buffer + sizeof(ULONG));

                    for (ULONG i = 0; i < Count; i++) {

                        PCHAR ImageName = strrchr(pmi->ImageName, '\\');
                        ImageName == NULL ? ImageName = pmi->ImageName : ImageName += sizeof('\\');

                        if (strstri(ImageName, DriverName)) {

                            *AddrSpaceSize = pmi->Size;
                            *Address = (ULONG)pmi->Base;

                            LOG_DBG("%s Base at 0x%p, Address Space Size %d\n", DriverName, pmi->Base, pmi->Size);
                            return TRUE;
                        }

                        pmi++;
                    }
                }

                HEAP_FREE(Buffer);
            }
        }

        return FALSE;
    }

    VOID SetCounterRecordStatus(CAPTURE Counter, ULONG Recording) {
        switch (Counter) {
            case CAPTURE::EDGE:
                KtCapture.Counters.NewEdges.Record = Recording;
                break;
            case CAPTURE::BBL:
                KtCapture.Counters.Bbls.Record = Recording;
                break;
            case CAPTURE::MEMORY:
                KtCapture.Counters.Memory.Record = Recording;
                break;
            case CAPTURE::CODE_COV:
                KtCapture.Extended.CodeCov.Record = Recording;
                break;
        }
    }

    ULONG GetImportTableOffset(CONST PCHAR szFilePath, CONST PCHAR szImportName) {
        PVOID FileMapping;
        PIMAGE_DOS_HEADER pDosHeader;
        PIMAGE_NT_HEADERS pNtHeader;
        PIMAGE_IMPORT_DESCRIPTOR pImageImportDesc;
        ULONG Offset = NULL;

        HANDLE hFile = CreateFileA(szFilePath,
            GENERIC_READ, 
            FILE_SHARE_READ, 
            NULL, 
            OPEN_EXISTING, 
            0, 
            NULL);

        if (hFile == INVALID_HANDLE_VALUE)
            return NULL;

        HANDLE hMappedFile = CreateFileMappingA(hFile, 
            NULL, 
            PAGE_READONLY | SEC_IMAGE, 
            0, 
            0, 
            NULL);

        if (hMappedFile == NULL)
            goto _MAPPING_CREATE_ERR;

        FileMapping = MapViewOfFile(hMappedFile, 
            FILE_MAP_READ, 
            0, 
            0, 
            0);

        if (FileMapping == NULL)
            goto _MAPPING_VIEW_ERROR;

        pDosHeader = (PIMAGE_DOS_HEADER)FileMapping;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            goto _PE_ERROR;

        pNtHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) 
            goto _PE_ERROR;

        if (pNtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
            goto _PE_ERROR;

        pImageImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)RVATOVA(pDosHeader,
            pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        if (pImageImportDesc == NULL)
            goto _PE_ERROR;

        for (; pImageImportDesc->FirstThunk; pImageImportDesc++) {

            ULONG ThunkOffset = 0;
            PIMAGE_THUNK_DATA pThunks = (PIMAGE_THUNK_DATA)RVATOVA(pDosHeader, pImageImportDesc->FirstThunk);
            for (; pThunks->u1.AddressOfData; pThunks++) {
                
                PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)RVATOVA(pDosHeader, pThunks->u1.AddressOfData);
                if (!IMAGE_SNAP_BY_ORDINAL(pThunks->u1.Ordinal)) {

                    /*
                    printf("Function: %.8X \"%s\"\n", 
                        (pImageImportDesc->FirstThunk + ThunkOffset), 
                        pImportByName->Name);
                    */

                    if (strcmp(pImportByName->Name, szImportName) == 0) {
                        Offset = pImageImportDesc->FirstThunk + ThunkOffset;

                        UnmapViewOfFile(FileMapping);
                        CloseHandle(hMappedFile);
                        CloseHandle(hFile);

                        return Offset;
                    }
                }

                ThunkOffset += sizeof(ULONG);
            }
        }
        
_PE_ERROR:
        UnmapViewOfFile(FileMapping);
_MAPPING_VIEW_ERROR:
        CloseHandle(hMappedFile);
_MAPPING_CREATE_ERR:
        CloseHandle(hFile);
        return NULL;
    }

    VOID AddModuleToList(CONST PCHAR szModuleName, CONST ULONG Address, CONST ULONG Size)
    {
        TRACKED_MODULE_INFO TMI;
        if (TrackedModules.find(Address) != TrackedModules.end())
                return;

        strncpy_s(TMI.ImageName, szModuleName, 32);
        TMI.ImageNameHash = djb2_hash((PUCHAR)szModuleName);
        TMI.Address = Address;
        TMI.Size = Size;

        TrackedModules[Address] = TMI;
    }

    BOOL FillBblFileRecordInfo(BBL_TRACKING_ENTRY& Track, FILE_BBL_TRACKING_ENTRY& FileEntry)
    {
        ULONG Base;
        ULONG End;
        ULONG Address = (ULONG)Track.Address;

        for (CONST auto& TM : TrackedModules) {

            TRACKED_MODULE_INFO TMI = TM.second;
            Base = TMI.Address;
            End = TMI.Address + TMI.Size;

            if (Address > Base && Address < End) {

                FileEntry.Address = (Address - Base);
                FileEntry.ImageNameHash = TMI.ImageNameHash;
                FileEntry.HitCount = Track.HitCount;
                return TRUE;
            }
        }

        return FALSE;
    }

    BOOL CopyCodeCoverageCapture(CONST PCHAR szFilePath)
    {
        PBBL_TRACKING_ENTRY BblsList;
        FILE_BBL_TRACKING_ENTRY BblFileRecord;
        ULONG OldCaptureState;
        ULONG CaptureSize;
        ULONG RecordCount;
        PVOID CaptureContent;
        ULONG BytesReturned;
        BOOL Result;

        OldCaptureState = KtCapture.Extended.CodeCov.Record;
        KtCapture.Extended.CodeCov.Record = 0;
        SetCaptureStatus(&KtCapture);

        Result = DeviceIoControl(hKrnTracerHandle,
            KFL_IOCTL_GET_BBL_COV_CAPTURES,
            NULL,
            0,
            &CaptureSize,
            sizeof(ULONG),
            &BytesReturned,
            NULL);

        if (!Result) {
            KtCapture.Extended.CodeCov.Record = OldCaptureState;
            SetCaptureStatus(&KtCapture);
            return Result;
        }
         
        CaptureContent = HEAP_ALLOC(CaptureSize);
        if (CaptureContent != NULL) {

            Result = DeviceIoControl(hKrnTracerHandle,
                KFL_IOCTL_GET_BBL_COV_CAPTURES,
                NULL,
                0,
                CaptureContent,
                CaptureSize,
                &BytesReturned,
                NULL);

            if (!Result) {

                KtCapture.Extended.CodeCov.Record = OldCaptureState;
                SetCaptureStatus(&KtCapture);

                HEAP_FREE(CaptureContent);
                return Result;
            }

            HANDLE hFile = CreateFile(szFilePath,
                GENERIC_WRITE, 
                FILE_SHARE_READ, 
                NULL, 
                CREATE_ALWAYS, 
                0, 
                NULL);

            if (hFile == INVALID_HANDLE_VALUE) {

                KtCapture.Extended.CodeCov.Record = OldCaptureState;
                SetCaptureStatus(&KtCapture);

                HEAP_FREE(CaptureContent);
                return FALSE;
            }

            BblsList = (PBBL_TRACKING_ENTRY)CaptureContent;
            RecordCount = CaptureSize / sizeof(BBL_TRACKING_ENTRY);
            for (ULONG i = 0; i < RecordCount; i++) {
                
                if (BblsList[i].Address) {

                    FillBblFileRecordInfo(BblsList[i], BblFileRecord);
                    WriteFile(hFile, &BblFileRecord, sizeof(BblFileRecord), NULL, NULL);
                }
            }

            CloseHandle(hFile);
        }

        KtCapture.Extended.CodeCov.Record = OldCaptureState;
        SetCaptureStatus(&KtCapture);

        HEAP_FREE(CaptureContent);
        return TRUE;
    }
};
}
#endif
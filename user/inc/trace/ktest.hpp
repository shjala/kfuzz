/*
 * Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
 * All rights reserved.
 */

#include <Windows.h>
#include <stdlib.h>
#include <time.h>
#include "ktrace.hpp"

#define KTEST                      0x1337
#define KTEST_GET_TEST_ENTRY       CTL_CODE(KTEST, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KTEST_SET_TEST_ENTRY       CTL_CODE(KTEST, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KTEST_GET_TEST_ENTRY_COUNT CTL_CODE(KTEST, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KTEST_CALL_TEST_ENTRY      CTL_CODE(KTEST, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define DBG_WAIT()                 while (IsDebuggerPresent() == FALSE)

namespace ktest {

typedef struct _TEST_ENTRY {
    PVOID KernelTestFunctionAddress;
    CHAR TestName[64];
    CHAR TestDescription[256];
} TEST_ENTRY, * PTEST_ENTRY;

class Test {
public:
    Test(PCHAR szBasicBlockFile) {
        srand((unsigned int)time(NULL));
        strncpy_s(BasicBlockFile, szBasicBlockFile, MAX_PATH);
    }

    BOOL Simple(VOID) {
        hDriverHandle = GetTestDriverHandle();
        if (hDriverHandle == INVALID_HANDLE_VALUE) {

            LOG_ERR("Invalid KTEST driver handle.\n");
            return FALSE;
        }

        /* Show a list of available test functions */
        PrintAvailableTestsList();

        auto kt = ktrace::Tracer();
        kt.TraceCodeCoverage(BasicBlockFile);
        kt.TraceMemoryAllocations(kKtestDriverName, kKtestDriverPath);

        PBYTE RandomStream = (PBYTE)HEAP_ALLOC(128);
        if (RandomStream == NULL) {

            LOG_ERR("Insufficent resource to allocate required memorye.\n");
            return FALSE;
        }

        LOG_INFO("Press Any Key to Start!"); getchar();

        kt.ResetEdgeTransMap();

        for (ULONG i = 0; i < GetTestRoutinesCount(); i++) {
            TEST_ENTRY TestInfo;
            RtlZeroMemory(&TestInfo, sizeof(TEST_ENTRY));
            GetTestEntryInfo(i, &TestInfo);

            LOG_INFO("Trying (%d):%s test!\n", i, TestInfo.TestName);
            SetCurrentTest(i);

            kt.StartRecording();

            LOG_INFO("QUERY::EDGE      : %lld!\n", kt.QueryCounter(ktrace::QUERY::EDGE));
            LOG_INFO("QUERY::BBL       : %lld!\n", kt.QueryCounter(ktrace::QUERY::BBL));
            LOG_INFO("QUERY::MEM_ALLOC : %lld!\n", kt.QueryCounter(ktrace::QUERY::MEMORY_ALLOC));
            LOG_INFO("QUERY::MEM_FREE  : %lld!\n", kt.QueryCounter(ktrace::QUERY::MEMORY_FREE));
            
            for (ULONG t = 0; t < 10; t++) {
                for (ULONG i = 0; i < 128; i++)
                    RandomStream[i] = rand();

                ExerciseCurrentTestRoutine(RandomStream, 128);
            }

            LOG_INFO("-------------------TEST-FINISHED-------------------\n");

            LOG_INFO("QUERY::EDGE      : %lld!\n", kt.QueryCounter(ktrace::QUERY::EDGE));
            LOG_INFO("QUERY::BBL       : %lld!\n", kt.QueryCounter(ktrace::QUERY::BBL));
            LOG_INFO("QUERY::MEM_ALLOC : %lld!\n", kt.QueryCounter(ktrace::QUERY::MEMORY_ALLOC));
            LOG_INFO("QUERY::MEM_FREE  : %lld!\n", kt.QueryCounter(ktrace::QUERY::MEMORY_FREE));

            printf("\n\n");

            kt.StopRecording();

            LOG_INFO("Saved coverage info to file ktestcov.bin\n");
            kt.SaveCoverageCapture((PCHAR)"ktestcov.bin");
        }

        HEAP_FREE(RandomStream);

        LOG_INFO("Press Any Key to Exit!"); getchar();
        return TRUE;
    }

private:
    HANDLE hDriverHandle;
    PCHAR kKtestDriverName = (PCHAR)"ktest.sys";
    PCHAR kKtestDriverPath = (PCHAR)"ktest.sys";
    PCHAR kKtestDevicePath = (PCHAR)"\\\\.\\KTEST";
    CHAR BasicBlockFile[MAX_PATH] = { 0 };

    HANDLE GetTestDriverHandle(VOID) {

        HANDLE hDevice = CreateFile(kKtestDevicePath,
            GENERIC_WRITE | GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        return hDevice;
    }

    ULONG GetTestRoutinesCount(VOID) {
        ULONG ulTestCount = 0;
        ULONG dwBytesReturned = 0;
        BOOL bResult;

        bResult = DeviceIoControl(hDriverHandle,
            KTEST_GET_TEST_ENTRY_COUNT,
            NULL,
            0,
            &ulTestCount,
            sizeof(ULONG),
            &dwBytesReturned,
            NULL);

        if (bResult == TRUE)
            return ulTestCount;

        return 0;
    }


    BOOL GetTestEntryInfo(ULONG TestNumber, PTEST_ENTRY pTestEntry) {
        ULONG dwBytesReturned = 0;
        BOOL bResult;

        bResult = DeviceIoControl(hDriverHandle,
            KTEST_GET_TEST_ENTRY,
            &TestNumber,
            sizeof(ULONG),
            pTestEntry,
            sizeof(TEST_ENTRY),
            &dwBytesReturned,
            NULL);

        return bResult;
    }

    BOOL PrintAvailableTestsList(VOID) {
        TEST_ENTRY TestEntry;
        ULONG i = 0;
        ULONG ulTestCount = 0;
        ULONG dwBytesReturned = 0;
        BOOL bResult;

        bResult = DeviceIoControl(hDriverHandle,
            KTEST_GET_TEST_ENTRY_COUNT,
            NULL, 0,
            &ulTestCount,
            sizeof(ULONG),
            &dwBytesReturned,
            NULL);

        if (bResult == TRUE) {

            for (i = 0; i < ulTestCount; i++) {

                bResult = DeviceIoControl(hDriverHandle,
                    KTEST_GET_TEST_ENTRY,
                    &i,
                    sizeof(ULONG),
                    &TestEntry,
                    sizeof(TEST_ENTRY),
                    &dwBytesReturned,
                    NULL);

                if (bResult == TRUE)
                    printf("(%d) %s : %s\n", i, TestEntry.TestName, TestEntry.TestDescription);
            }
        }

        return bResult;
    }


    BOOL SetCurrentTest(ULONG dwTestNumber) {
        ULONG dwBytesReturned = 0;
        BOOL bResult;

        bResult = DeviceIoControl(hDriverHandle,
            KTEST_SET_TEST_ENTRY,
            &dwTestNumber,
            sizeof(ULONG),
            NULL,
            0,
            &dwBytesReturned,
            NULL);

        return bResult;
    }

    BOOL ExerciseCurrentTestRoutine(PBYTE pInputBuffer, ULONG dwInputBufferSize) {
        ULONG dwBytesReturned = 0;
        BOOL bResult;

        bResult = DeviceIoControl(hDriverHandle,
            KTEST_CALL_TEST_ENTRY,
            pInputBuffer,
            dwInputBufferSize,
            NULL,
            0,
            &dwBytesReturned,
            NULL);

        return bResult;
    }
};
}
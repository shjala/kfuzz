/*
 * Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
 * All rights reserved.
 */

#include "tests.h"
#pragma warning( disable : 4706 )

TEST_ENTRY TestEntries[] = {

#ifdef ENABLE_BENCHMARKING
    {RdtscBenchmark,                    "RdtscBenchmark",                       "Benchmark KFLOG overhead using RDTSC."},
#endif

    {FourDependentBranchesTest,         "FourDependentBranchesTest",            "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 1 M, 16 S                                */
    {CounterTest,                       "CounterTest",                          "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 0 M, 10 S                                */
    {CxxTokensTest,                     "CxxTokensTest",                        "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 6 M, 35 S (TODO: cmpsX instrumentation)  */
    {FourIndependentBranchesTest,       "FourIndependentBranchesTest",          "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 5 M, 37 S                                */
    {FullCoverageSetTest,               "FullCoverageSetTest",                  "No description available."},           /* Failed, Hard to pass and needs smt solver (probably)                 */
    {MemcmpTest,                        "MemcmpTest",                           "No description available."},           /* Failed, needs internal hook or cmpsX instrumentation                 */
    {NullDerefTest,                     "NullDerefTest",                        "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 1 M, 0 S                                 */
    {SimpleCmpTest,                     "SimpleCmpTest",                        "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 0 M, 11 S (using CMP dict)               */
    {StrcmpTest,                        "StrcmpTest",                           "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 4 M, 48 S                                */
    {SimpleStrncmpTest,                 "SimpleStrncmpTest",                    "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 0 M, 47 S                                */
    {StrncmpTest,                       "StrncmpTest",                          "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 22 M, 16 S                               */
    {SwitchTest,                        "SwitchTest",                           "No description available."},           /* Failed, needs cmp instrumentation                                    */
    {ShortSwitchTest,                   "ShortSwitchTest",                      "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 0 M, 11 S (using CMP dict)               */
    {LongSwitchTest,                    "LongSwitchTest",                       "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 0 M, 34 S (using CMP dict)               */
    {CmpTest,                           "CmpTest",                              "No description available."},           /* Failed, needs cmp instrumentation                                    */
    {AbsNegAndConstantTest,             "AbsNegAndConstantTest",                "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 0 M, 33 S (using CMP dict)               */
    {AbsNegAndConstantTest64,           "AbsNegAndConstantTest64",              "No description available."},
    {CleanseTest,                       "CleanseTest",                          "No description available."},
    {SimpleStrcmpTest,                  "SimpleStrcmpTest",                     "No description available."},           /* Failed, left for loop detection approach                             */
    {SimpleStrncmpTest,                 "SimpleStrncmpTest",                    "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 0 M, 46 S                                */
    {SimpleStricmpTest,                 "SimpleStricmpTest",                    "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 1 M, 8 S                                 */
    {SimpleStrnicmpTest,                "SimpleStrnicmpTest",                   "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 0 M, 45 S                                */
    {SimpleWcscmpTest,                  "SimpleWcscmpTest",                     "No description available."},           /* Failed, left for loop detection approach                             */
    {SimpleWcsicmpTest,                 "SimpleWcsicmpTest",                    "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 3 M, 22 S                                */
    {SimpleWcsncmpTest,                 "SimpleWcsncmpTest",                    "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 8 M, 9 S                                 */
    {SimpleWcsnicmpTest,                "SimpleWcsnicmpTest",                   "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 4 M, 36 S                                */
    {SimpleRtlCompareMemoryTest,        "SimpleRtlCompareMemoryTest",           "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 1 M, 17 S                                */
    {SimpleRtlCompareStringTest,        "SimpleRtlCompareStringTest",           "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 1 M, 28 S                                */
    {SimpleRtlEqualStringTest,          "SimpleRtlEqualStringTest",             "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 1 M, 7 S                                 */
    {SimpleRtlCompareUnicodeStringTest, "SimpleRtlCompareUnicodeStringTest",    "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 4 M, 59 S                                */
    {SimpleRtlEqualUnicodeStringTest,   "SimpleRtlEqualUnicodeStringTest",      "No description available."},           /* Passed, RUN TIME: 0 D, 0 H, 4 M, 20 S                                */
    {DrillerTest,                       "DrillerTest",                          "Challenge from Driller paper."},
    {StructureTest,                     "StructureTest",                        "No description available."},
    {HashCalcTest,                      "HashCalcTest",                         "No description available."},
    {MemoryAllocTest,                   "MemoryAllocTest",                         "No description available."},
    
};


ULONG
GetTestEntriesCount(
    VOID
    )
{
    return (sizeof(TestEntries)/sizeof(TestEntries[0]));
}


ULONG
GetTestEntrySize(
    VOID
    )
{
    return sizeof(TestEntries[0]);
}


PTEST_ENTRY
GetTestEntry(
    IN ULONG Index
    )
{
    return &TestEntries[Index];
}


// fuzzer test functions, some garbed from LllvmFuzzer tests
// https://github.com/llvm-mirror/llvm/tree/master/lib/Fuzzer/test

unsigned long djb2_hash(unsigned char *str)
{
    unsigned long hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

static volatile INT sink;

BOOLEAN
LongSwitch(
    CONST PUCHAR Data,
    SIZE_T       Size
    ) 
{
    ULONGLONG X;

    if (Size < sizeof(X)) 
        return FALSE;

    memcpy(&X, Data, sizeof(X));
    switch (X) {

        case 1: sink = __LINE__; break;
        case 101: sink = __LINE__; break;
        case 1001: sink = __LINE__; break;
        case 10001: sink = __LINE__; break;
        case 100001: sink = __LINE__; break;
        case 1000001: sink = __LINE__; break;
        case 10000001: sink = __LINE__; break;
        case 100000001: return TRUE;
    }

    return FALSE;
}


BOOLEAN
ShortSwitch(
    CONST PUCHAR Data, 
    SIZE_T       Size
    )
{
    SHORT X;

    if (Size < sizeof(short)) 
        return FALSE;

    memcpy(&X, Data, sizeof(short));
    switch(X) {
    case 42: sink = __LINE__; break;
    case 402: sink = __LINE__; break;
    case 4002: sink = __LINE__; break;
    case 5002: sink = __LINE__; break;
    case 7002: sink = __LINE__; break;
    case 9002: sink = __LINE__; break;
    case 14002: sink = __LINE__; break;
    case 21402: return TRUE;
    }

    return FALSE;
}

BOOLEAN 
EqualString(
    CONST PUCHAR Data, 
    SIZE_T       Size, 
    CONST PCHAR  Str
    )
{
    CHAR Buff[1024];
    INT res;
    SIZE_T Len = strlen(Str);

    if (Size < Len) 
        return FALSE;

    if (Len >= sizeof(Buff)) 
        return FALSE;

    memcpy(Buff, (char*)Data, Len);
    Buff[Len] = 0;
    res = strcmp(Buff, Str);

    return (res == 0);
}


NTSTATUS
CounterTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    ULONG Num = 0, i;

    for (i = 0; i < BufferLen; i++) {

        if (Buffer[i] == 'A' + i)
            Num++;
    }

    if (Num >= 4) {

        TEST_SUCCESS_DBG_BREAK();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the CounterTest!\n");

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
CxxTokensTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    if (BufferLen < 24) 
        return STATUS_UNSUCCESSFUL;

    if (!memcmp(&Buffer[0], "thread_local", 12)) {

        if (Buffer[12] == ' ') {

            if (!memcmp(&Buffer[13], "unsigned", 8)) {

                if (Buffer[21] == ' ') {

                    if (Buffer[22] == 'A') {

                        if (Buffer[23] == ';') {

                            TEST_SUCCESS_DBG_BREAK();
                            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the CxxTokensTest!\n");

                            return STATUS_SUCCESS;
                        }
                    }
                }
            }
        }
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
FourIndependentBranchesTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    INT bits = 0;

    if (BufferLen > 0 && Buffer[0] == 'F') bits |= 1;
    if (BufferLen > 1 && Buffer[1] == 'U') bits |= 2; 
    if (BufferLen > 2 && Buffer[2] == 'Z') bits |= 4;
    if (BufferLen > 3 && Buffer[3] == 'Z') bits |= 8;
    if (bits == 15) {

        TEST_SUCCESS_DBG_BREAK();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "[KTEST] passed the FourIndependentBranchesTest!\n");

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
CleanseTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    if (BufferLen >= 20 && Buffer[1] == '1' && Buffer[5] == '5' && Buffer[10] == 'A' && Buffer[19] == 'Z') {

        TEST_SUCCESS_DBG_BREAK();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the CleanseTest!\n");

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
FullCoverageSetTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    INT bits = 0;

    if (BufferLen > 0 && Buffer[0] == 'F') bits |= 1;  
    if (BufferLen > 1 && Buffer[1] == 'U') bits |= 2;  
    if (BufferLen > 2 && Buffer[2] == 'Z') bits |= 4;  
    if (BufferLen > 3 && Buffer[3] == 'Z') bits |= 8;  
    if (BufferLen > 4 && Buffer[4] == 'E') bits |= 16; 
    if (BufferLen > 5 && Buffer[5] == 'R') bits |= 32; 
    if (bits == 63) {

        TEST_SUCCESS_DBG_BREAK();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the FullCoverageSetTest!\n");

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
MemcmpTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    if (BufferLen >= 8 && !memcmp(Buffer, "01234567", 8)) {

        if (BufferLen >= 12 && !memcmp(Buffer + 8, "ABCD", 4)) {

            if (BufferLen >= 14 && !memcmp(Buffer + 12, "XY", 2)) {

                if (BufferLen >= 16 && !memcmp(Buffer + 14, "KLM", 3)) {

                    TEST_SUCCESS_DBG_BREAK();
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the MemcmpTest!\n");

                    return STATUS_SUCCESS;
                }
            }
        }
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
NullDerefTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    if (BufferLen > 0 && Buffer[0] == 'H') {

        if (BufferLen > 1 && Buffer[1] == 'i') {

            if (BufferLen > 2 && Buffer[2] == '!') {

                TEST_SUCCESS_DBG_BREAK();
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the NullDerefTest!\n");

                return STATUS_SUCCESS;
            }
        }
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
CmpTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    ULONGLONG x = 0;
    ULONGLONG  y = 0;
    USHORT a = 0;
    INT z = 0;

    if (BufferLen < 14) 
        return STATUS_UNSUCCESSFUL;

    RtlCopyMemory(&x, Buffer, 8);
    RtlCopyMemory(&y, Buffer + BufferLen - 8, 8);
    RtlCopyMemory(&z, Buffer + BufferLen / 2, sizeof(z));
    RtlCopyMemory(&a, Buffer + BufferLen / 2 + 4, sizeof(a));

    if (x > 1234567890 &&
        x < 1234567895 &&
        y >= 987654321 &&
        y <= 987654325 &&
        z < -10000 &&
        z >= -10005 &&
        z != -10003 &&
        a == 4242) {

            TEST_SUCCESS_DBG_BREAK();
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the CmpTest!\n");

            return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
SimpleCmpTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    INT x = 0;

    if (BufferLen < 4) 
        return STATUS_UNSUCCESSFUL;

    RtlCopyMemory(&x, Buffer, 4);
    if (x == 12345678) {

            TEST_SUCCESS_DBG_BREAK();
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the SimpleCmpTest!\n");

            return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
StrcmpTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    if (EqualString(Buffer, BufferLen, "AAA") &&
        BufferLen >= 3 && EqualString(Buffer + 3, BufferLen - 3, "BBBB") &&
        BufferLen >= 7 && EqualString(Buffer + 7, BufferLen - 7, "CCCCCC") &&
        BufferLen >= 14 && Buffer[13] == 42) {

            TEST_SUCCESS_DBG_BREAK();
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the StrcmpTest!\n");

            return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
StrncmpTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    CHAR *S = (PCHAR)Buffer;

    if (BufferLen >= 8 && strncmp(S, "01234567", 8) == 0) {
        if (BufferLen >= 12 && strncmp(S + 8, "ABCD", 4) == 0) {
            if (BufferLen >= 14 && strncmp(S + 12, "XY", 2) == 0) {
                if (BufferLen >= 16 && strncmp(S + 14, "KLM", 3) == 0) {

                    TEST_SUCCESS_DBG_BREAK();
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the StrncmpTest!\n");

                    return STATUS_SUCCESS;
                }
            }
        }
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
ShortSwitchTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    if (BufferLen >= 4  && ShortSwitch(Buffer, 2)) {

            TEST_SUCCESS_DBG_BREAK();
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the ShortSwitchTest!\n");

            return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
LongSwitchTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    if (BufferLen >= 4  && LongSwitch(Buffer, BufferLen)) {

            TEST_SUCCESS_DBG_BREAK();
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the LongSwitchTest!\n");

            return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
SwitchTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    if (BufferLen >= 4  && LongSwitch(Buffer, BufferLen) &&
        BufferLen >= 12 && LongSwitch(Buffer + 4, BufferLen - 4) &&
        BufferLen >= 14 && ShortSwitch(Buffer + 12, 2)) {

            TEST_SUCCESS_DBG_BREAK();
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the SwitchTest!\n");

            return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
FourDependentBranchesTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    if (BufferLen < 8)
            return STATUS_UNSUCCESSFUL;

    if (Buffer[0] == 1) {

        if (Buffer[3] > 0x10) {

            if (Buffer[5] == 0x41) {

                if (Buffer[7] < 0x90) {

                    TEST_SUCCESS_DBG_BREAK();
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] FourDependentBranchesTest, final stage passed!\n");

                    return STATUS_SUCCESS;
                }
            }
        }
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
AbsNegAndConstantTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    INT x;
    ULONG y;

    if (BufferLen < 8) 
        return STATUS_UNSUCCESSFUL;

    RtlCopyMemory(&x, Buffer, sizeof(x));
    RtlCopyMemory(&y, Buffer + sizeof(x), sizeof(y));

    if (abs(x) < 0 && y == 0xbaddcafe) {

        TEST_SUCCESS_DBG_BREAK();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] AbsNegAndConstantTest passed; x=0x%x y=0x%x\n", x, y);

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
AbsNegAndConstantTest64(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    INT64 x;
    ULONG64 y;

    if (BufferLen < 16) 
        return STATUS_UNSUCCESSFUL;

    RtlCopyMemory(&x, Buffer, sizeof(x));
    RtlCopyMemory(&y, Buffer + sizeof(x), sizeof(y));

    if (_abs64(x) < 0 && y == 0xbaddcafedeadbeefULL) {

        TEST_SUCCESS_DBG_BREAK();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] AbsNegAndConstantTest64 passed; x=0x%x y=0x%x\n", x, y);

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
SimpleStrcmpTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    CHAR *S = (PCHAR)Buffer;
    S[BufferLen - 1] = '\0';

    if (BufferLen >= 3 && strcmp(S, "012") == 0) {

        TEST_SUCCESS_DBG_BREAK();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the SimpleStrcmpTest!\n");

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
SimpleStrncmpTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    CHAR *S = (PCHAR)Buffer;

    if (BufferLen >= 3 && strncmp(S, "012", 3) == 0) {

        TEST_SUCCESS_DBG_BREAK();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the SimpleStrncmpTest!\n");

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
SimpleStricmpTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    CHAR *S = (PCHAR)Buffer;

    if (BufferLen < 3)
        return STATUS_UNSUCCESSFUL;

    S[BufferLen - 1] = '\0';
    if (_stricmp(S, "aBc") == 0) {

        TEST_SUCCESS_DBG_BREAK();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the SimpleStricmpTest!\n");

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
SimpleStrnicmpTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    CHAR *S = (PCHAR)Buffer;

    if (BufferLen < 3)
        return STATUS_UNSUCCESSFUL;

    S[BufferLen - 1] = '\0';
    if (_strnicmp(S, "aBc", 3) == 0) {

        TEST_SUCCESS_DBG_BREAK();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the SimpleStrnicmpTest!\n");

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
SimpleWcscmpTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    WCHAR *S = (PWCHAR)Buffer;

    if (BufferLen < (3 * sizeof(WCHAR)))
        return STATUS_UNSUCCESSFUL;

    S[(BufferLen/sizeof(WCHAR)) - sizeof(WCHAR)] = L'\0';
    if (wcscmp(S, L"012") == 0) {

        TEST_SUCCESS_DBG_BREAK();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the SimpleWcscmpTest!\n");

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
SimpleWcsicmpTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    WCHAR *S = (PWCHAR)Buffer;

    if (BufferLen < (3 * sizeof(WCHAR)))
        return STATUS_UNSUCCESSFUL;

    S[(BufferLen/sizeof(WCHAR)) - sizeof(WCHAR)] = L'\0';
    if (_wcsicmp(S, L"aBc") == 0) {

        TEST_SUCCESS_DBG_BREAK();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the SimpleWcsicmpTest!\n");

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
SimpleWcsncmpTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    WCHAR *S = (PWCHAR)Buffer;

    if (BufferLen < (3 * sizeof(WCHAR)))
        return STATUS_UNSUCCESSFUL;

    S[(BufferLen/sizeof(WCHAR)) - sizeof(WCHAR)] = L'\0';
    if (wcsncmp(S, L"aBc", 3) == 0) {

        TEST_SUCCESS_DBG_BREAK();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the SimpleWcsncmpTest!\n");

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
SimpleWcsnicmpTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    WCHAR *S = (PWCHAR)Buffer;

    if (BufferLen < (3 * sizeof(WCHAR)))
        return STATUS_UNSUCCESSFUL;

    S[(BufferLen/sizeof(WCHAR)) - sizeof(WCHAR)] = L'\0';
    if (_wcsnicmp(S, L"aBc", 3) == 0) {

        TEST_SUCCESS_DBG_BREAK();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the SimpleWcsnicmpTest!\n");

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
SimpleRtlCompareMemoryTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    CHAR *S = (PCHAR)Buffer;

    if (BufferLen > 3 && RtlCompareMemory(S, "abc", 3) == 3) {

        TEST_SUCCESS_DBG_BREAK();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the SimpleRtlCompareMemoryTest!\n");

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
SimpleRtlCompareStringTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    STRING Dst;
    STRING Src;
    CHAR *S = (PCHAR)Buffer;

    if (BufferLen > 3) {
        
        S[BufferLen - 1] = '\0';
        RtlInitAnsiString(&Dst, "abc");
        RtlInitAnsiString(&Src, (PCSZ)S);

        if (RtlCompareString(&Src, &Dst, TRUE) == 0) {

            TEST_SUCCESS_DBG_BREAK();
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the SimpleRtlCompareStringTest!\n");

            return STATUS_SUCCESS;
        }
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
SimpleRtlEqualStringTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    STRING Dst;
    STRING Src;
    CHAR *S = (PCHAR)Buffer;

    if (BufferLen > 3) {
        
        S[BufferLen - 1] = '\0';
        RtlInitAnsiString(&Dst, "abc");
        RtlInitAnsiString(&Src, (PCSZ)S);

        if (RtlEqualString(&Src, &Dst, TRUE) == TRUE) {

            TEST_SUCCESS_DBG_BREAK();
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the SimpleRtlEqualStringTest!\n");

            return STATUS_SUCCESS;
        }
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
SimpleRtlCompareUnicodeStringTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    UNICODE_STRING Dst;
    UNICODE_STRING Src;
    WCHAR *S = (PWCHAR)Buffer;

    if (BufferLen > (3 * sizeof(WCHAR))) {
        
        S[(BufferLen/sizeof(WCHAR)) - sizeof(WCHAR)] = L'\0';
        RtlInitUnicodeString(&Dst, L"abc");
        RtlInitUnicodeString(&Src, (PWSTR)S);

        if (RtlCompareUnicodeString(&Src, &Dst, TRUE) == 0) {

            TEST_SUCCESS_DBG_BREAK();
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the SimpleRtlCompareUnicodeStringTest!\n");

            return STATUS_SUCCESS;
        }
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
SimpleRtlEqualUnicodeStringTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    UNICODE_STRING Dst;
    UNICODE_STRING Src;
    WCHAR *S = (PWCHAR)Buffer;
    
    if (BufferLen > (3 * sizeof(WCHAR))) {
        
        S[(BufferLen/sizeof(WCHAR)) - sizeof(WCHAR)] = L'\0';
        RtlInitUnicodeString(&Dst, L"abc");
        RtlInitUnicodeString(&Src, (PWSTR)S);

        if (RtlEqualUnicodeString(&Src, &Dst, TRUE) == TRUE) {

            TEST_SUCCESS_DBG_BREAK();
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the SimpleRtlEqualUnicodeStringTest!\n");

            return STATUS_SUCCESS;
        }
    }

    return STATUS_UNSUCCESSFUL;
}



BOOLEAN IsPrime(
    INT Num
    )
{
    INT i;

    for (i = 2; i < Num; i++) {

        if (Num % i == 0) {

            return FALSE;
        }
    }

    return TRUE;
}


NTSTATUS
BenchmarkPrimeCalc(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    LARGE_INTEGER Rate;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER EndTime;
    LARGE_INTEGER Delta;
    INT           i = 1, PrimeCount = 0;

    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(BufferLen);

    StartTime = KeQueryPerformanceCounter(&Rate);

    do
    {
        /* Without calling to PROBE_JMP_ALLOC, Kflog switches to slow `Interrupt Probes`,
           which is unfair for benchmarking, because the we use `Interrupt Probes` only on 
           small blocks or blocks with a CALL at start, and these only consist 2-5% of a binary 
           basic blocks.
        */
        PROBE_JMP_ALLOC();
        if (IsPrime(i)) {

            PROBE_JMP_ALLOC();
            PrimeCount++;
        }

    } while (i++ < 200000);

    EndTime = KeQueryPerformanceCounter(&Rate);

    Delta.QuadPart = EndTime.QuadPart - StartTime.QuadPart;
    Delta.QuadPart = KSCONVERT_PERFORMANCE_TIME(Rate.QuadPart, Delta); /* Convert ticks to 100ns units */
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] BenchmarkPrimeCalc Execution took : %lld (100ns units)\n", Delta.QuadPart);
    Delta.QuadPart /= 10000; /* Convert to milliseconds, may lose precision */
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] BenchmarkPrimeCalc Execution took : %lld ms\n", Delta.QuadPart);

    return STATUS_SUCCESS;
}


NTSTATUS
RdtscBenchmark(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    INT i = 1, PrimeCount = 0;
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(BufferLen);

    {
        EXEC_MEASURE_DEFINE();

        EXEC_MEASURE_START();

        do
        {
            if (IsPrime(i))
                PrimeCount++;

        } while (++i < BENCHMARK_LOOP);

        EXEC_MEASURE_END();

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] Execution took : %lld TICS\n", EXEC_MEASURE_DIFF());
    }

    return STATUS_SUCCESS;
}


NTSTATUS
DrillerTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    PDRILLER_TEST_CONFIG pConfig;

    if (BufferLen < sizeof(DRILLER_TEST_CONFIG))
        return STATUS_INVALID_BUFFER_SIZE;

    pConfig = (PDRILLER_TEST_CONFIG)Buffer;

    if (pConfig->Magic != DRILLER_TEST_MAGIC) {
        
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] Bad magic number\n");
        return STATUS_INVALID_PARAMETER;
    }

    if(!strncmp(pConfig->Directive, "crashstring", 64)) {
        
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the DrillerTest (crashstring)!\n");
        return STATUS_SUCCESS;
    }
    else if(!strncmp(pConfig->Directive, "setoption", 64)) {

        /* setoption(config->directives[1]); */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the DrillerTest! (setoption)\n");
        return STATUS_SUCCESS;
    }
    else {

        /* _default(); */
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] DrillerTest called the _default()\n");
        return STATUS_INVALID_PARAMETER;
    }
}


NTSTATUS
StructureTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    PTEST_STRUCT_PARNET pParentStruct;

    if (BufferLen < sizeof(TEST_STRUCT_PARENT))
        return STATUS_INVALID_BUFFER_SIZE;

    pParentStruct = (PTEST_STRUCT_PARNET)Buffer;

    if ((pParentStruct->ParentFlag & TEST_STRUCT_FLAG1) != TEST_STRUCT_FLAG1)
        return STATUS_INVALID_PARAMETER;

    if (pParentStruct->Counter > TEST_STRUCT_SZIE) {

        if (pParentStruct->ChildStructOne.ChildFlag == TEST_STRUCT_FLAG2 && 
            !strncmp(pParentStruct->ChildStructOne.Buffer, "ChildStructOne", 128)) {
                
                try {
                    
                    ProbeForRead(pParentStruct->ChildStructTwo, sizeof(TEST_STRUCT_CHILD_TWO), sizeof(UCHAR));
                    ProbeForRead(pParentStruct->ChildStructTwo->Buffer, sizeof(ULONG), sizeof(UCHAR));

                    if ((pParentStruct->ChildStructTwo->ChildFlag & TEST_STRUCT_FLAG3) == TEST_STRUCT_FLAG3) {

                        if (*(PULONG)pParentStruct->ChildStructTwo->Buffer == TEST_STRUCT_FLAG4)
                            return STATUS_SUCCESS;
                    }
                }
                except(EXCEPTION_EXECUTE_HANDLER) {
                    
                    return GetExceptionCode();
                }
        }
    }

    return STATUS_INVALID_PARAMETER;
}


NTSTATUS
HashCalcTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    UCHAR HashTestBuffer[] = "HASH_ME_TEST";

    if (BufferLen < 32)
        return STATUS_INVALID_BUFFER_SIZE;

    Buffer[31] = (UCHAR)'\0';

    if (djb2_hash(HashTestBuffer) == djb2_hash(Buffer)) {

        TEST_SUCCESS_DBG_BREAK();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"[KTEST] passed the HashCalcTest!\n");

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


NTSTATUS
MemoryAllocTest(
    IN PUCHAR Buffer,
    IN ULONG  BufferLen
    )
{
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(BufferLen);

    PVOID pExAllocatePool =  ExAllocatePool(PagedPool, 1024);
    PVOID pExAllocatePoolWithTag = ExAllocatePoolWithTag(PagedPool, 1024, (ULONG)"aMtK");

    if (pExAllocatePool)
        ExFreePool(pExAllocatePool);
    if (pExAllocatePoolWithTag)
        ExFreePoolWithTag(pExAllocatePoolWithTag, (ULONG)"aMtK");

    return STATUS_SUCCESS;
}

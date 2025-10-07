# KFuzz | Windows Kernel Code Coverage and Instrumentation

This is **legacy project** (2016-2017) of mine, published here for edutional purposed. You have to find a way to compile it using current WDK and VS, I included sample `.vcxproj` that can be helpfull. Checkout blog post [Fuzzing and Instrumenting Windows Kernel (2017)](https://defense.sh/oldblog/fuzzing/kernel/2017/04/27/kfuzz-a-fuzzer-story.html) for some introduction.

---

## Overview

KFuzz is a modular Windows kernel fuzzer designed for speed and high coverage when fuzzing kernel drivers without source code access. It implements several new techniques to achieve near-native performance while providing comprehensive code coverage analysis.

## Instrumentation

KFuzz solves the challenge of instrumenting binary kernel drivers by using traditional 5-byte long jumps for large basic blocks (≥5 bytes) and a novel approach for small basic blocks (<5 bytes) by leveraging illegal instruction exceptions with custom IDT handlers for 2-byte instrumentation, resulting in complete coverage of all basic blocks with minimal overhead.

It uses shared memory counters to provide direct user-mode access to edge counters for efficient data collection. To eliminate some disk I/O bottlenecks it can store test cases in a sector‑aligned flat file that bypasses filesystem (FILE_FLAG_NO_BUFFERING and FILE_FLAG_WRITE_THROUGH for no filesystem overhead), it can be placed on a network‑mapped RAM disk to remain persistent across VM crashes.

## Components

### KFLOG (Kernel Logger)
- Instrumentation engine
- Edge tracking
- Multi-threaded worker pool : per-thread location tracking
- Memory allocation tracking : hooking of kernel allocation APIs (ExAllocatePool*, NtAllocateVirtualMemory, etc.)
- Focus blocks : Kernel event signaling for specific basic blocks 
- IRQL-aware tracing
- Process/thread filtering : selective tracing by PID, kernel-only, user-only, or global modes
- Real-time basic block hit counting
- Atomic patch management : safe kernel memory rewriting

### User-Mode Fuzzer
- Corpus management
- Coverage-guided mutation
- Flat filesystem
- Dictionary/BBL extraction script
- Focus function support: prioritized fuzzing of specific functions with a weighting multiplier
- Memory tracking hooks : instrumentation of allocation APIs (ExAllocatePool, NtAllocateVirtualMemory, etc.)

### KTEST (Testing Driver)
- Test suite for testing various fuzzing techniques.

## Usage Example

To use KFuzz, you first need to extract basic block information from your target driver using IDA Pro:

1. **Extract Basic Blocks**: Load your target driver in IDA Pro and run the basic block enumeration script:
   ```
   File → Script file → user/script/ida/ida_bbl_enum_gui.py
   ```
   This will generate a basic block file containing address information needed for instrumentation.

2. **Set up Fuzzing**: Use the generated basic block file to initialize the tracer and begin fuzzing:

```cpp
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
```

3. **Visualize Coverage in IDA Pro**: After (or during) fuzzing, use the coverage visualization script to see exactly which code paths were executed:
   ```
   File → Script file → user/script/ida/trace/ida_cfg_trace_color_gui.py
   ```
   Load the coverage file (e.g., `ktestcov.bin`) to:
   - **Color-code basic blocks** based on hit frequency (blue highlighting)
   - **Identify missed code paths** and untested branches
   - **Add hit count annotations** as comments in the disassembly
   - **Detect small missed blocks**
   - **Sort coverage data** by hit count to prioritize high/low traffic areas

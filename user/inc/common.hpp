/*
 * Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
 * All rights reserved.
 */

#ifndef COMMON_HEADER_FILE
#define COMMON_HEADER_FILE
#define NOMINMAX
#include <Windows.h>
#include <string>
#include <sstream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <algorithm>
#include <random>
#include <thread>
#include <chrono>
#include <mutex>
#include <unordered_set>
#include <numeric>
#include <assert.h>
#include <intrin.h>

#define AC_RED     "\x1b[31m"
#define AC_GREEN   "\x1b[32m"
#define AC_YELLOW  "\x1b[33m"
#define AC_BLUE    "\x1b[34m"
#define AC_MAGENTA "\x1b[35m"
#define AC_CYAN    "\x1b[36m"
#define AC_RESET   "\x1b[0m"

#ifdef _DEBUG
#define LOG_INFO(fmt, ...) printf("%s:%d (INFO) " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG_WRN(fmt, ...)  printf("%s:%d (WRN) " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)  printf("%s:%d (ERR) " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG_DBG(fmt, ...)  printf("%s:%d (DBG) " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define DBG_WAIT()         while (IsDebuggerPresent() == FALSE)
#else                      
#define LOG_INFO(fmt, ...) printf("(INFO) " fmt, ##__VA_ARGS__)
#define LOG_WRN(fmt, ...)  printf("(WRN) " fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)  printf("(ERR) " fmt, ##__VA_ARGS__)
#define LOG_DBG(fmt, ...)
#define DBG_WAIT()
#endif //_DEBUG

#define KB                 1024
#define MB                 (KB * 1024)
#define ROUND_UP(N, S)     ((((N) + (S) - 1) / (S)) * (S))

#define HEAP_ALLOC(a)      HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, a)
#define HEAP_FREE(a)       if (a != NULL ) HeapFree(GetProcessHeap(), 0, a); a = NULL;

inline uint8_t  Bswap(uint8_t x) { return x; }
inline uint16_t Bswap(uint16_t x) { return _byteswap_ushort(x); }
inline uint32_t Bswap(uint32_t x) { return _byteswap_ulong(x); }
inline uint64_t Bswap(uint64_t x) { return _byteswap_uint64(x); }

bool WriteToFile(const uint8_t* Data, size_t Size, const std::string& Path) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    ULONG Written = 0;

    hFile = CreateFile(Path.c_str(),
        GENERIC_WRITE,
        0, 
        NULL,
        CREATE_ALWAYS,
        0,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_ERR("failed to open file \"%s\"!\n", Path.c_str());
        return false;
    }

    auto Result = WriteFile(hFile, Data, Size, &Written, NULL);
    FlushFileBuffers(hFile); CloseHandle(hFile);
    if (!Result || Written != Size) {
        LOG_ERR("failed to write to file \"%s\"!\n", Path.c_str());
        return false;
    }

    return true;
}

std::string FileToString(const std::string & Path) {
    std::ifstream T(Path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(T)),
        std::istreambuf_iterator<char>());
}

long GetEpoch(const std::string & Path) {
    struct stat St;
    if (stat(Path.c_str(), &St))
        return 0;  // Can't stat, be conservative.
    return static_cast<long>(St.st_mtime);
}

std::string DirPlusFile(const std::string & DirPath,
    const std::string & FileName) {
    return DirPath + '\\' + FileName;
}

bool IsFile(const std::string & Path, const ULONG & FileAttributes) {

    if (FileAttributes & FILE_ATTRIBUTE_NORMAL)
        return true;

    if (FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        return false;

    HANDLE FileHandle(
        CreateFileA(Path.c_str(), 0, FILE_SHARE_READ, NULL, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS, 0));

    if (FileHandle == INVALID_HANDLE_VALUE) {
        LOG_ERR("CreateFileA() failed for \"%s\" (Error code: %lu).\n", Path.c_str(),
            GetLastError());
        return false;
    }

    ULONG FileType = GetFileType(FileHandle);

    if (FileType == FILE_TYPE_UNKNOWN) {
        LOG_ERR("GetFileType() failed for \"%s\" (Error code: %lu).\n", Path.c_str(),
            GetLastError());
        CloseHandle(FileHandle);
        return false;
    }

    if (FileType != FILE_TYPE_DISK) {
        CloseHandle(FileHandle);
        return false;
    }

    CloseHandle(FileHandle);
    return true;
}

bool IsFile(const std::string & Path) {
    ULONG Att = GetFileAttributesA(Path.c_str());

    if (Att == INVALID_FILE_ATTRIBUTES) {
        LOG_ERR("GetFileAttributesA() failed for \"%s\" (Error code: %lu).\n",
            Path.c_str(), GetLastError());
        return false;
    }

    return IsFile(Path, Att);
}

bool FileExist(const std::string & Path) {
    if (GetFileAttributes(Path.c_str()) == INVALID_FILE_ATTRIBUTES &&
        GetLastError() == ERROR_FILE_NOT_FOUND)
        return false;

    return true;
}

void ListFilesInDirRecursive(const std::string & Dir, long* Epoch,
    std::vector<std::string> * V, bool TopDir) {
    auto E = GetEpoch(Dir);
    if (Epoch)
        if (E && *Epoch >= E) return;

    std::string Path(Dir);
    assert(!Path.empty());
    if (Path.back() != '\\')
        Path.push_back('\\');
    Path.push_back('*');

    // Get the first directory entry.
    WIN32_FIND_DATAA FindInfo;
    HANDLE FindHandle(FindFirstFileA(Path.c_str(), &FindInfo));
    if (FindHandle == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_FILE_NOT_FOUND)
            return;
        LOG_ERR("No such file or directory: %s; exiting\n", Dir.c_str());
        exit(1);
    }

    do {
        std::string FileName = DirPlusFile(Dir, FindInfo.cFileName);

        if (FindInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            size_t FilenameLen = strlen(FindInfo.cFileName);
            if ((FilenameLen == 1 && FindInfo.cFileName[0] == '.') ||
                (FilenameLen == 2 && FindInfo.cFileName[0] == '.' &&
                    FindInfo.cFileName[1] == '.'))
                continue;

            ListFilesInDirRecursive(FileName, Epoch, V, false);
        }
        else if (IsFile(FileName, FindInfo.dwFileAttributes))
            V->push_back(FileName);
    } while (FindNextFileA(FindHandle, &FindInfo));

    ULONG LastError = GetLastError();
    if (LastError != ERROR_NO_MORE_FILES)
        LOG_ERR("FindNextFileA failed (Error code: %lu).\n", LastError);

    FindClose(FindHandle);
    if (Epoch && TopDir)
        *Epoch = E;
}

std::vector<uint8_t> FileToVector(const std::string & Path, bool ExitOnError) {
    std::ifstream T(Path, std::ios::binary);
    if (ExitOnError && !T) {
        LOG_ERR("No such directory: %s; exiting\n", Path.c_str());
        exit(1);
    }

    T.seekg(0, T.end);
    size_t EndPos = static_cast<size_t>(T.tellg());
    if (EndPos < 0) return {};
    size_t FileLen = EndPos;

    T.seekg(0, T.beg);
    std::vector<uint8_t> Res(FileLen);
    T.read(reinterpret_cast<char*>(Res.data()), FileLen);
    return Res;
}

void PrintASCIIByte(uint8_t Byte) {
    if (Byte == '\\')
        printf("\\\\");
    else if (Byte == '"')
        printf("\\\"");
    else if (Byte >= 32 && Byte < 127)
        printf("%c", Byte);
    else
        printf("\\x%02x", Byte);
}

void PrintASCII(const uint8_t * Data, size_t Size, const char* PrintAfter = "") {
    for (size_t i = 0; i < Size; i++)
        PrintASCIIByte(Data[i]);
    printf("%s", PrintAfter);
}

void PrintASCII(const std::vector<uint8_t> & U, const char* PrintAfter = "") {
    PrintASCII(U.data(), U.size(), PrintAfter);
}

bool ToASCII(uint8_t * Data, size_t Size) {
    bool Changed = false;
    for (size_t i = 0; i < Size; i++) {
        uint8_t& X = Data[i];
        auto NewX = X;
        NewX &= 127;
        if (!isspace(NewX) && !isprint(NewX))
            NewX = ' ';
        Changed |= NewX != X;
        X = NewX;
    }
    return Changed;
}

bool HyperThreadingSupported(void) {
    int r[4];
    if ((__cpuid(r, 0), r[0]) > 0) {
        __cpuid(r, 1);
        int EDX = r[3];
        return (EDX & (1 << 28)) != 0;
    }

    return false;
}

/* Describe integer. Uses 12 cyclic static buffers for return values. The value
   returned should be five characters or less for all the integers we reasonably
   expect to see. */
static char* DI(uint64_t val) {

    static char tmp[12][16];
    static uint8_t cur;


    cur = (cur + 1) % 12;

#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast) do { \
    if (val < (_divisor) * (_limit_mult)) { \
      sprintf_s(tmp[cur], _fmt, ((_cast)val) / (_divisor)); \
      return tmp[cur]; \
    } \
  } while (0)

    /* 0-9999 */
    CHK_FORMAT(1, 10000, "%llu", uint64_t);

    /* 10.0k - 99.9k */
    CHK_FORMAT(1000, 99.95, "%0.01fk", double);

    /* 100k - 999k */
    CHK_FORMAT(1000, 1000, "%lluk", uint64_t);

    /* 1.00M - 9.99M */
    CHK_FORMAT(1000 * 1000, 9.995, "%0.02fM", double);

    /* 10.0M - 99.9M */
    CHK_FORMAT(1000 * 1000, 99.95, "%0.01fM", double);

    /* 100M - 999M */
    CHK_FORMAT(1000 * 1000, 1000, "%lluM", uint64_t);

    /* 1.00G - 9.99G */
    CHK_FORMAT(1000LL * 1000 * 1000, 9.995, "%0.02fG", double);

    /* 10.0G - 99.9G */
    CHK_FORMAT(1000LL * 1000 * 1000, 99.95, "%0.01fG", double);

    /* 100G - 999G */
    CHK_FORMAT(1000LL * 1000 * 1000, 1000, "%lluG", uint64_t);

    /* 1.00T - 9.99G */
    CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 9.995, "%0.02fT", double);

    /* 10.0T - 99.9T */
    CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 99.95, "%0.01fT", double);

    /* 100T+ */
    strcpy_s(tmp[cur], "infty");
    return tmp[cur];

}

char* DTD(uint64_t cur_ms, uint64_t event_ms) {

    static char tmp[64];
    uint64_t delta;
    int32_t t_d, t_h, t_m, t_s;

    if (!event_ms) return (char*)"none seen yet";

    delta = cur_ms - event_ms;

    t_d = (int32_t)(delta / 1000 / 60 / 60 / 24);
    t_h = (int32_t)((delta / 1000 / 60 / 60) % 24);
    t_m = (int32_t)((delta / 1000 / 60) % 60);
    t_s = (int32_t)((delta / 1000) % 60);

    sprintf_s(tmp, "%s days, %u hrs, %u min, %u sec", DI(t_d), t_h, t_m, t_s);
    return tmp;
}

char* BytesToSize(uint64_t Bytes, char* Buffer) {
    float tb = 1099511627776;
    float gb = 1073741824;
    float mb = 1048576;
    float kb = 1024;

    if (Bytes >= tb)
        sprintf(Buffer, "%.2f TB", (float)Bytes / tb);
    else if (Bytes >= gb && Bytes < tb)
        sprintf(Buffer, "%.2f GB", (float)Bytes / gb);
    else if (Bytes >= mb && Bytes < gb)
        sprintf(Buffer, "%.2f MB", (float)Bytes / mb);
    else if (Bytes >= kb && Bytes < mb)
        sprintf(Buffer, "%.2f KB", (float)Bytes / kb);
    else if (Bytes < kb)
        sprintf(Buffer, "%lld Bytes", Bytes);
    else
        sprintf(Buffer, "%lld Bytes", Bytes);

    return Buffer;
}

// A simple POD sized array of bytes.
template <size_t kMaxSizeT> class FixedWord {
public:
    static const size_t kMaxSize = kMaxSizeT;
    FixedWord() {}
    FixedWord(const uint8_t* B, uint8_t S) { Set(B, S); }

    void Set(const uint8_t* B, uint8_t S) {
        assert(S <= kMaxSize);
        memcpy(Data, B, S);
        Size = S;
    }

    bool operator==(const FixedWord<kMaxSize>& w) const {
        return Size == w.Size && 0 == memcmp(Data, w.Data, Size);
    }

    static size_t GetMaxSize() { return kMaxSize; }
    const uint8_t* data() const { return Data; }
    uint8_t size() const { return Size; }

private:
    uint8_t Size = 0;
    uint8_t Data[kMaxSize];
};
typedef FixedWord<64> Word;

class Random : public std::minstd_rand {
public:
    Random(unsigned int seed) : std::minstd_rand(seed) {}
    result_type operator()() { return this->std::minstd_rand::operator()(); }
    size_t Rand() { return this->operator()(); }
    bool RandBool() { return Rand() % 2; }
    size_t SkewTowardsLast(size_t n) {
        size_t T = this->operator()(n * n);
        size_t Res = static_cast<size_t>(sqrt(T));
        return Res;
    }
    size_t operator()(size_t n) { return n ? Rand() % n : 0; }
    intptr_t operator()(intptr_t From, intptr_t To) {
        assert(From < To);
        intptr_t RangeSize = To - From + 1;
        return operator()(RangeSize) + From;
    }
};

std::string RandString(size_t length)
{
    auto randchar = []() -> char
    {
        const char charset[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 1);
        return charset[rand() % max_index];
    };

    std::string str(length, 0);
    std::generate_n(str.begin(), length, randchar);
    return str;
}

#endif
/*
 * Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
 * All rights reserved.
 */

#ifndef FLATFAT_HEADER_FILE_H
#define FLATFAT_HEADER_FILE_H
#include "..\common.hpp"
#include <unordered_map>
#include <stdexcept>
#include <vector>
#include <string>
#include <cstdint>
#include <cstdio>

namespace flatfat {

class FlatFat {
public:
    FlatFat(const std::string& FileFullPath, uint32_t MaxFileCount, uint32_t FileSize = (5 * KB)) :
        FlatFilePath (FileFullPath), MaxFileCount(MaxFileCount), kWriteMaxSize(FileSize){

        FlatFileSize = ROUND_UP((kWriteMaxSize * MaxFileCount), kSectorSize);
        if (!CreateLinearDataFile())
            throw std::runtime_error("Failed to create file required!");

        DiskDataMemmory = (uint8_t*)HEAP_ALLOC(kWriteMaxSize + sizeof(FLAT_FILE_INFO) + (kSectorSize * 2));
        if (DiskDataMemmory == nullptr)
            throw std::runtime_error("Failed to allocate memory for file content!");

        /* We need a SECTOR_SIZE aligned memory... */
        DiskDataMemmoryAligned = (uint8_t*)(((uint32_t)DiskDataMemmory + (kSectorSize - 1)) & ~(kSectorSize - 1));
    }

    ~FlatFat() {
        HEAP_FREE(DiskDataMemmory);
        CloseHandle(FlatFileHanlde);
    }

    bool Write(const uint8_t* InputBuffer, uint32_t InputBufferLen) {
        ULONG FileSize = 0, Written = 0;

        if (InputBuffer == NULL || InputBufferLen == 0 || InputBufferLen > kWriteMaxSize - sizeof(FLAT_FILE_INFO))
            return false;

        FLAT_FILE_INFO FFInfo;
        FFInfo.FileSize = InputBufferLen;
        FFInfo.MaxFileSize = kWriteMaxSize;
        RtlCopyMemory(DiskDataMemmoryAligned, &FFInfo, sizeof(FLAT_FILE_INFO));
        RtlCopyMemory(DiskDataMemmoryAligned + sizeof(FLAT_FILE_INFO), InputBuffer, InputBufferLen);

        if (FileCount >= MaxFileCount)
            FileCount = 0;

        FileSize = ROUND_UP((InputBufferLen + sizeof(FLAT_FILE_INFO)), kSectorSize);
        if (WriteLinear(DiskDataMemmoryAligned, FileSize, FileCount)) {

            FileCount++;
            return true;
        }

        return false;
    }

private:
    const uint32_t kSectorSize = 512;
    const uint32_t kWriteMaxSize;
    uint32_t FlatFileSize;
    uint32_t MaxFileCount;
    std::string FlatFilePath;
    uint32_t FileCount = 0;
    uint8_t* DiskDataMemmory = nullptr;
    uint8_t* DiskDataMemmoryAligned = nullptr;
    HANDLE FlatFileHanlde = INVALID_HANDLE_VALUE;

    typedef struct _FLAT_FILE_INFO
    {
        uint32_t MaxFileSize;
        uint32_t FileSize;
    } FLAT_FILE_INFO, *PFLAT_FILE_INFO;

    bool CreateLinearDataFile() {
        FlatFileHanlde = CreateFile(FlatFilePath.c_str(),
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            0,
            NULL);

        if (FlatFileHanlde == INVALID_HANDLE_VALUE) {
            LOG_ERR("Failed to open file \"%s\"! (GLE: %d)\n", FlatFilePath.c_str(), GetLastError());
            return false;
        }

        ULONG Written = 0;
        std::vector<uint8_t> FileContent(FlatFileSize);
        std::fill(std::begin(FileContent), std::end(FileContent), 0);

        auto Result = WriteFile(FlatFileHanlde, FileContent.data(), FlatFileSize, &Written, NULL);
        CloseHandle(FlatFileHanlde);

        if (!Result || FlatFileSize != Written) {
            LOG_ERR("Failed to write content to file!\n");
            return false;
        }

        FlatFileHanlde = CreateFile(FlatFilePath.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
            NULL);

        if (FlatFileHanlde == INVALID_HANDLE_VALUE) {
            LOG_ERR("Failed to re-open file \"%s\" with NO_BUFFERING|WRITE_THROUGH!\n", FlatFilePath.c_str());
            return false;
        }

        return true;
    }

    bool WriteLinear(const uint8_t* InputBuffer, uint32_t InputBufferLen, uint32_t Offset) {
        ULONG Written = 0;

        auto Result = WriteFile(FlatFileHanlde, InputBuffer, InputBufferLen, &Written, NULL);
        if (!Result || InputBufferLen != Written) {

            LOG_ERR("failed to write content to fil!\n");
            return false;
        }

        if (SetFilePointer(FlatFileHanlde, (Offset * kWriteMaxSize), NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {

            LOG_ERR("failed to advance the file pointer!\n");
            return false;
        }

        return true;
    }
};
}
#endif
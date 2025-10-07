/*
 * Copyright (c) 2025 Shahriyar Jalayeri <shahriyar@posteo.de>
 * All rights reserved.
 */

#ifndef CORPUS_HEADER_FILE_H
#define CORPUS_HEADER_FILE_H
#include "..\common.hpp"
#include "sha1.hpp"

namespace corpus{

class Corpus {
public:
    struct InputInfo {
        std::vector<uint8_t> U;                     // The actual input data.
        uint8_t Sha1[sha1::Sha1::kSHA1NumBytes];    // Checksum.
        size_t NumFeatures = 0;
        bool HasFocusFunction = false;
    };
    std::vector<InputInfo> Inputs;

    Corpus(std::string Path) : CorporaPath(Path) {

        ReadCorpora(0, false);
    }

    ~Corpus() {
        delete CorpusLock;
    }

    size_t CorpusMemSize(void) {
        auto MemUsed = 0;
        for (auto& I : Inputs)
            MemUsed += I.U.size();

        MemUsed += sizeof(std::vector<InputInfo>) + (sizeof(InputInfo) * Inputs.size());
        return MemUsed;
    }

    void UpdateCorpora() {
        ReadCorpora(0, false);
    }

    size_t MaxCorpSize(void) {
        return MaxLoadedInputSize;
    }

    bool AddToCorpus(const uint8_t* Data, size_t Size, const std::string& Prefix, size_t NumFeatures) {
        sha1::Sha1 SHA1;
        InputInfo II;
        II.U.resize(Size);
        memcpy(II.U.data(), Data, Size);
        assert(!II.U.empty());

        SHA1.ComputeSHA1(II.U.data(), II.U.size(), II.Sha1);
        auto Sha1Str = SHA1.Sha1ToString(II.Sha1);
        auto Path = CorporaPath + '\\' + Prefix + Sha1Str;

        std::lock_guard<std::mutex> Guard(*CorpusLock);
        if (Hashes.find(Sha1Str) == Hashes.end()) {
            II.NumFeatures = NumFeatures;
            Hashes.insert(Sha1Str);
            Inputs.push_back(II);
            if (MaxLoadedInputSize < II.U.size())
                MaxLoadedInputSize = II.U.size();

            UpdateCorpusDistribution();

            if (!FileExist(Path))
                return WriteToFile(II.U.data(), II.U.size(), Path.c_str());
        }

        return true;
    }

    bool WriteToCorpus(const uint8_t* Data, size_t Size, const std::string& Prefix, size_t NumFeatures) {
        uint8_t Hash[sha1::Sha1::kSHA1NumBytes];
        sha1::Sha1 SHA1;
        
        SHA1.ComputeSHA1(Data, Size, Hash);
        auto Sha1Str = SHA1.Sha1ToString(Hash);
        auto Path = CorporaPath + '\\' + Prefix + Sha1Str;

        std::lock_guard<std::mutex> Guard(*CorpusLock);
        if (!FileExist(Path))
            return WriteToFile(Data, Size, Path.c_str());

        return true;
    }

    InputInfo& ChooseUnitToMutate(Random& Rand) {
        InputInfo& II = Inputs[ChooseUnitIdxToMutate(Rand)];
        assert(!II.U.empty());
        return II;
    }

private:
    std::piecewise_constant_distribution<double> CorpusDistribution;
    std::vector<double> Intervals;
    std::vector<double> Weights;
    std::unordered_set<std::string> Hashes;
    std::string CorporaPath;
    size_t MaxLoadedInputSize = 0;
    bool Reload = true;
    std::mutex* CorpusLock = new std::mutex();

    void UpdateCorpusDistribution() {
        size_t N = Inputs.size();
        assert(N);
        Intervals.resize(N + 1);
        Weights.resize(N);
        std::iota(Intervals.begin(), Intervals.end(), 0);
        for (size_t i = 0; i < N; i++)
            Weights[i] = Inputs[i].NumFeatures ? 
            (i + 1) * (Inputs[i].HasFocusFunction ? 1000 : 1) : 0.;
        
        CorpusDistribution = std::piecewise_constant_distribution<double>(
            Intervals.begin(), Intervals.end(), Weights.begin());
    }

    size_t ChooseUnitIdxToMutate(Random& Rand) {
        size_t Idx = static_cast<size_t>(CorpusDistribution(Rand));
        assert(Idx < Inputs.size());
        return Idx;
    }

    void ReadCorpora(long* Epoch, bool ExitOnError) {
        long E = Epoch ? *Epoch : 0;
        size_t NumLoaded = 0;
        std::vector<std::string> Files;

        ListFilesInDirRecursive(CorporaPath.c_str(), Epoch, &Files, /*TopDir*/true);
        for (size_t i = 0; i < Files.size(); i++) {
            auto& X = Files[i];
            if (Epoch && GetEpoch(X) < E) continue;
            NumLoaded++;
            auto S = FileToVector(X, ExitOnError);
            if (!S.empty()) {
                InputInfo II;
                sha1::Sha1 SHA1;
                II.U = S;
                SHA1.ComputeSHA1(II.U.data(), II.U.size(), II.Sha1);
                auto Sha1Str = SHA1.Sha1ToString(II.Sha1);

                std::lock_guard<std::mutex> Guard(*CorpusLock);
                if (Hashes.find(Sha1Str) == Hashes.end()) {
                    Hashes.insert(Sha1Str);
                    Inputs.push_back(II);

                    if (i % 1000 == 0)
                        LOG_INFO("Loading corpus (%d/%d)...\n", i, Files.size());

                    if (i == Files.size() - 1)
                        LOG_INFO("Loadded (%d/%d) unique corpus.\n", Inputs.size(), Files.size());

                    if (MaxLoadedInputSize < II.U.size())
                        MaxLoadedInputSize = II.U.size();
                }
            }
        }
    }
};
}
#endif
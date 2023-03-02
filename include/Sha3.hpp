#pragma once

#include <string>
#include <array>
#include <vector>

namespace Okane
{
    class Sha3
    {
    public:
        std::string sha256(const std::string &str);

        std::string sha512(const std::string &str);

    private:
        const size_t ROUNDS = 24;

        const uint64_t RC[24]{
            0x0000000000000001,
            0x0000000000008082,
            0x800000000000808A,
            0x8000000080008000,
            0x000000000000808B,
            0x0000000080000001,
            0x8000000080008081,
            0x8000000000008009,
            0x000000000000008A,
            0x0000000000000088,
            0x0000000080008009,
            0x000000008000000A,
            0x000000008000808B,
            0x800000000000008B,
            0x8000000000008089,
            0x8000000000008003,
            0x8000000000008002,
            0x8000000000000080,
            0x000000000000800A,
            0x800000008000000A,
            0x8000000080008081,
            0x8000000000008080,
            0x0000000080000001,
            0x8000000080008008,
        };

        const uint64_t R[5][5] = {
            {0, 36, 3, 41, 18},
            {1, 44, 10, 45, 2},
            {62, 6, 43, 15, 61},
            {28, 55, 25, 21, 56},
            {27, 20, 39, 8, 14}};

        std::string padding(const std::string& str, size_t bitrate);

        void keccakf(std::array<std::array<uint64_t, 5>, 5> &state);

        std::string keccak(const std::string &str, size_t capacity, size_t bitrate);

        inline uint64_t rotl(uint64_t x, uint64_t y);
    };
}

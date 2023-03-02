#include "Sha3.hpp"

#include <sstream>
#include <cmath>
#include <bitset>

namespace Okane
{
    std::string Sha3::sha256(const std::string &str)
    {
        return keccak(str, 512, 1088);
    }

    std::string Sha3::sha512(const std::string &str)
    {
        return keccak(str, 1024, 576);
    }

    uint64_t Sha3::rotl(uint64_t x, uint64_t y)
    {
        return (((x) << (y)) | ((x) >> (64 - (y))));
    }

    std::string Sha3::padding(const std::string &str, size_t bitrate)
    {
        std::string binary{};

        for (const auto &c : str)
            binary += std::bitset<8>(c).to_string();

        size_t length = binary.length();

        if ((length + 3) % bitrate == 0)
            return binary + "101";

        binary += "1";

        while ((length = binary.length() + 1) % bitrate != 0)
            binary += "0";

        return binary + "1";
    }

    void Sha3::keccakf(std::array<std::array<uint64_t, 5>, 5> &A)
    {
        for (size_t i = 0; i < ROUNDS; i++)
        {
            // θ step
            std::array<uint64_t, 5> C{0}, D{0};

            for (size_t x = 0; x < 5; x++)
                C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4];

            for (size_t x = 0; x < 5; x++)
            {
                D[x] = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);

                for (size_t y = 0; y < 5; y++)
                    A[x][y] ^= D[x];
            }

            // ρ and π steps
            std::array<std::array<uint64_t, 5>, 5> B{0};

            for (size_t x = 0; x < 5; x++)
            {
                for (size_t y = 0; y < 5; y++)
                    B[y][(2 * x + 3 * y) % 5] = rotl(A[x][y], R[x][y]);
            }

            // χ step

            for (size_t x = 0; x < 5; x++)
            {
                for (size_t y = 0; y < 5; y++)
                    A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]);
            }

            // ι step
            A[0][0] ^= RC[i];
        }
    }

    std::string Sha3::keccak(const std::string &str, size_t capacity, size_t bitrate)
    {
        // Padding

        // d = 2^|Mbits| + sum for i=0..|Mbits|-1 of 2^i*Mbits[i]
        // P = Mbytes || d || 0x00 || … || 0x00
        // P xor (0x00 || … || 0x00 || 0x80)

        // Init
        std::array<std::array<uint64_t, 5>, 5> S{0};

        // Absorbin phase

        // for each block Pi in P
        // S[x,y] = S[x,y] xor Pi[x+5*y],          for (x,y) such that x+5*y < bitrate / 64
        // S = Keccak-f[r+c](S)

        // Squeezing phase
        std::string Z{};

        // while output is requested
        // Z = Z || S[x, y], for (x, y) such that x + 5 *y < bitrate / 64
        keccakf(S);

        return Z;
    }
}
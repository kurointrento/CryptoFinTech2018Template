#ifndef RANDOM_HPP
#define RANDOM_HPP

#include <random>
#include <iostream>
#include <libff/common/utils.hpp>

namespace unitn_crypto_fintech {

class RandomBitVectorGenerator {
        std::minstd_rand engine;
        std::uniform_int_distribution<unsigned> uniform_dist;

public:
        RandomBitVectorGenerator(unsigned seed = 0) :
                        engine(seed), uniform_dist(0, 1) {};

        libff::bit_vector generate_random_bit_vector(size_t width);
};

} // unitn_crypto_fintech

#endif // RANDOM_HPP

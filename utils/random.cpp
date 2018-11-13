#include "random.hpp"

#include <algorithm>
#include <iostream>

using libff::bit_vector;
using std::generate;

namespace unitn_crypto_fintech {

bit_vector RandomBitVectorGenerator::generate_random_bit_vector(size_t width) {
        bit_vector result(width);

        generate(result.begin(), result.end(),
                        [&]() { return uniform_dist(engine); });

        return result;
}

} // unitn_crypto_fintech

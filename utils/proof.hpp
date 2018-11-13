#ifndef PROOF_HPP
#define PROOF_HPP

#include <libsnark/gadgetlib1/protoboard.hpp>

namespace unitn_crypto_fintech {

// Using the protoboard provided, this function generates a keypair, a proof and
// then verifies it.
template<typename ppT>
bool test_proof_from_protoboard(const libsnark::protoboard<libff::Fr<ppT>> &pb);

// Using the protoboard provided, this function generates a proof, but tries to
// verify it with a witness that is completely set to 0.
template<typename ppT>
bool test_proof_wrong_witness_from_protoboard(
        const libsnark::protoboard<libff::Fr<ppT>> &pb,
        const libsnark::r1cs_primary_input<libff::Fr<ppT>> wrong_witness);

} // unitn_crypto_fintech

#include "proof.tcc"

#endif

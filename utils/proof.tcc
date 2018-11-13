#ifndef PROOF_TCC
#define PROOF_TCC

#include "proof.hpp"

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>

using libsnark::protoboard;
using libsnark::r1cs_ppzksnark_generator;
using libsnark::r1cs_ppzksnark_keypair;
using libsnark::r1cs_ppzksnark_prover;
using libsnark::r1cs_ppzksnark_proof;
using libsnark::r1cs_ppzksnark_verifier_strong_IC;
using libsnark::r1cs_primary_input;
using libff::Fr;
using libff::start_profiling;
using libff::enter_block;
using libff::leave_block;

namespace unitn_crypto_fintech {

template<typename ppT>
bool test_proof_from_protoboard(const protoboard<Fr<ppT>> &pb)
{
    libff::print_header("Benchmarking Gadget");
    start_profiling();

    enter_block("Key generation");
    // Generate keypair
    r1cs_ppzksnark_keypair<ppT> keypair = r1cs_ppzksnark_generator<ppT>(
                    pb.get_constraint_system());
    leave_block("Key generation");

    auto commitment = pb.primary_input();

    enter_block("Proof generation");
    // Generate proof
    r1cs_ppzksnark_proof<ppT> proof = r1cs_ppzksnark_prover<ppT>(
                    keypair.pk, commitment, pb.auxiliary_input());
    leave_block("Proof generation");

    enter_block("Proof verification");
    // Verify generated proof
    auto res = r1cs_ppzksnark_verifier_strong_IC<ppT>(
                    keypair.vk, commitment, proof);
    leave_block("Proof verification");

    return res;
}

template<typename ppT>
bool test_proof_wrong_witness_from_protoboard(const protoboard<Fr<ppT>> &pb,
        const r1cs_primary_input<Fr<ppT>> wrong_witness)
{
    // Generate keypair
    r1cs_ppzksnark_keypair<ppT> keypair = r1cs_ppzksnark_generator<ppT>(
                    pb.get_constraint_system());

    auto commitment = pb.primary_input();

    // Generate proof
    r1cs_ppzksnark_proof<ppT> proof = r1cs_ppzksnark_prover<ppT>(
                    keypair.pk, commitment, pb.auxiliary_input());

    assert(wrong_witness.size() == commitment.size());

    // Verify generated proof
    return r1cs_ppzksnark_verifier_strong_IC<ppT>(
                    keypair.vk, wrong_witness, proof);
}

} // unitn_crypto_fintech

#endif

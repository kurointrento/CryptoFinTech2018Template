#ifndef SHA256_COMMITMENT_GADGET_HPP
#define SHA256_COMMITMENT_GADGET_HPP

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

namespace unitn_crypto_fintech {

template<typename FieldT>
class SHA256CommitmentGadget : public libsnark::gadget<FieldT> {

	libsnark::dual_variable_gadget<FieldT> value;

	libsnark::pb_variable<FieldT> padding;
	libsnark::digest_variable<FieldT> randomness;
	std::shared_ptr<libsnark::sha256_two_to_one_hash_gadget<FieldT>> sha256_hasher;

	std::shared_ptr<libsnark::multipacking_gadget<FieldT>> commitment_packer;
	libsnark::pb_variable_array<FieldT> commitment;


public:
	SHA256CommitmentGadget(libsnark::protoboard<FieldT> &pb,
			const libsnark::pb_variable<FieldT> &value,
			const libsnark::pb_variable_array<FieldT> &commitment,
			const std::string &annotation_prefix);

	void generate_r1cs_constraints();
	void generate_r1cs_witness(const libff::bit_vector& random_vector);

	const libsnark::pb_variable_array<FieldT>& get_value_bits() const;

};

} // unitn_crypto_fintech

#include "sha256_commitment_gadget.tcc"

#endif // SHA256_COMMITMENT_GADGET_HPP

#ifndef SHA256_COMMITMENT_GADGET_TCC
#define SHA256_COMMITMENT_GADGET_TCC

#include "sha256_commitment_gadget.hpp"

using libsnark::gadget;
using libsnark::protoboard;
using libsnark::pb_variable;
using libsnark::pb_variable_array;
using libsnark::SHA256_digest_size;
using libsnark::sha256_two_to_one_hash_gadget;
using libsnark::digest_variable;
using libsnark::dual_variable_gadget;
using libsnark::multipacking_gadget;
using libsnark::generate_r1cs_equals_const_constraint;
using libff::bit_vector;
using std::make_shared;
using std::string;

namespace unitn_crypto_fintech {

template<typename FieldT>
SHA256CommitmentGadget<FieldT>::SHA256CommitmentGadget(
		protoboard<FieldT> &pb,
		const pb_variable<FieldT> &value,
		const pb_variable_array<FieldT> &commitment,
		const string &annotation_prefix) :
	gadget<FieldT>(pb, annotation_prefix),
	value(pb, value, FieldT::size_in_bits(),
			FMT(this->annotation_prefix, " value")),
	randomness(pb, SHA256_digest_size, // New variable allocation
			FMT(this->annotation_prefix, " randomness")),
	commitment(commitment)
{
	// New variable allocation
	this->padding.allocate(pb, FMT(this->annotation_prefix, " padding"));

	// Reuses value
	auto value_digest = digest_variable<FieldT>(
			pb, SHA256_digest_size, this->value.bits, padding,
			FMT(this->annotation_prefix, " value_digest"));

	// New variable allocation
	auto hasher_output = digest_variable<FieldT>(
			pb, SHA256_digest_size,
			FMT(this->annotation_prefix, " hasher_output"));

	// Connects value_digest, randomness (inputs) with hasher_output
	this->sha256_hasher = make_shared<sha256_two_to_one_hash_gadget<FieldT>>(
			pb, value_digest, randomness, hasher_output,
			FMT(this->annotation_prefix, " sha256_hasher"));

	// Connects hasher_output with circuit output (this->commitment)
	this->commitment_packer = make_shared<multipacking_gadget<FieldT>>(
			pb, hasher_output.bits, this->commitment, FieldT::capacity(),
			FMT(this->annotation_prefix, " commitment_packer"));
	
}

template<typename FieldT>
void SHA256CommitmentGadget<FieldT>::generate_r1cs_constraints()
{
	value.generate_r1cs_constraints(true); // Enforce bitness on value
	// Constraints for value_digest not needed because of constraints for
	// value
	generate_r1cs_equals_const_constraint<FieldT>(this->pb, padding, FieldT::zero(),
			FMT(this->annotation_prefix, " padding_zero"));
	randomness.generate_r1cs_constraints();
	sha256_hasher->generate_r1cs_constraints();
	// Constraints for hasher_output not needed because of constraints for
	// commitment_packer
	commitment_packer->generate_r1cs_constraints(true); // Enforce bitness on commitment
}

template<typename FieldT>
void SHA256CommitmentGadget<FieldT>::generate_r1cs_witness(const bit_vector& random_vector)
{
	this->pb.val(padding) = FieldT::zero();
	value.generate_r1cs_witness_from_packed();
	randomness.generate_r1cs_witness(random_vector);
	sha256_hasher->generate_r1cs_witness();
	commitment_packer->generate_r1cs_witness_from_bits();
}

template<typename FieldT>
const pb_variable_array<FieldT>& SHA256CommitmentGadget<FieldT>::get_value_bits() const
{
	return value.bits;
}

} // unitn_crypto_fintech

#endif // SHA256_COMMITMENT_GADGET_TCC

#ifndef SHA256_COMPARISON_GADGET_TCC
#define SHA256_COMPARISON_GADGET_TCC

#include "sha256_comparison_gadget.hpp"

using libsnark::gadget;
using libsnark::protoboard;
using libsnark::pb_variable;
using libsnark::pb_variable_array;
using libsnark::comparison_gadget;
using libsnark::generate_r1cs_equals_const_constraint;
using libff::bit_vector;
using std::string;
using std::make_shared;

namespace unitn_crypto_fintech {

template<typename FieldT>
SHA256ComparisonGadget<FieldT>::SHA256ComparisonGadget(
		protoboard<FieldT> &pb,
		const pb_variable<FieldT> &value,
		const pb_variable_array<FieldT> &commitment,
		const string &annotation_prefix) :
	gadget<FieldT>(pb, annotation_prefix),
	value(value), commitment(commitment),
	commitment_gadget(new SHA256CommitmentGadget<FieldT>(
			pb, value, commitment,
			FMT(this->annotation_prefix, " commitment_gadget")))
{
	// New variable allocations
	zero.allocate(pb, FMT(this->annotation_prefix, " zero"));
	less.allocate(pb, FMT(this->annotation_prefix, " less"));
	less_or_eq.allocate(pb, FMT(this->annotation_prefix, " less_or_eq"));

	// Compares value with zero and return the result in less and less_or_eq
	comp_gadget = make_shared<comparison_gadget<FieldT>>(
			pb, FieldT::capacity(), value, zero, less, less_or_eq,
			FMT(this->annotation_prefix, " comp_gadget"));
}

template<typename FieldT>
void SHA256ComparisonGadget<FieldT>::generate_r1cs_constraints_shared()
{
	commitment_gadget->generate_r1cs_constraints();
	generate_r1cs_equals_const_constraint<FieldT>(
			this->pb, zero, FieldT::zero(),
			FMT(this->annotation_prefix, " zero_zero"));
	comp_gadget->generate_r1cs_constraints();
}

template<typename FieldT>
void SHA256ComparisonGadget<FieldT>::generate_r1cs_witness_shared(const bit_vector& random_vector)
{
	commitment_gadget->generate_r1cs_witness(random_vector);

	// generate_r1cs_witness has to be called on comp_gadget even if the
	// result is overwritten afterwards. It is necessary to set the
	// intermediate variables.
	this->pb.val(zero) = FieldT::zero();
	comp_gadget->generate_r1cs_witness();
}

template<typename FieldT>
void SHA256CompLessGadget<FieldT>::generate_r1cs_constraints()
{
	this->generate_r1cs_constraints_shared();

	// value < 0
	generate_r1cs_equals_const_constraint<FieldT>(
			this->pb, this->less, FieldT::one(),
			FMT(this->annotation_prefix, " less_one"));
	generate_r1cs_equals_const_constraint<FieldT>(
			this->pb, this->less_or_eq, FieldT::one(),
			FMT(this->annotation_prefix, " less_or_eq_one"));
}

template<typename FieldT>
void SHA256CompLessGadget<FieldT>::generate_r1cs_witness(const bit_vector &random_vector)
{
	this->generate_r1cs_witness_shared(random_vector);

	// value < 0
	this->pb.val(this->less) = FieldT::one();
	this->pb.val(this->less_or_eq) = FieldT::one();
}

template<typename FieldT>
void SHA256CompLessEqGadget<FieldT>::generate_r1cs_constraints()
{
	this->generate_r1cs_constraints_shared();

	// value <= 0
	generate_r1cs_equals_const_constraint<FieldT>(
			this->pb, this->less_or_eq, FieldT::one(),
			FMT(this->annotation_prefix, " less_or_eq_one"));
}

template<typename FieldT>
void SHA256CompLessEqGadget<FieldT>::generate_r1cs_witness(const bit_vector &random_vector)
{
	this->generate_r1cs_witness_shared(random_vector);

	// value <= 0
	this->pb.val(this->less_or_eq) = FieldT::one();
}

template<typename FieldT>
void SHA256CompGreaterGadget<FieldT>::generate_r1cs_constraints()
{
	this->generate_r1cs_constraints_shared();

	// value > 0
	generate_r1cs_equals_const_constraint<FieldT>(
			this->pb, this->less, FieldT::zero(),
			FMT(this->annotation_prefix, " less_one"));
	generate_r1cs_equals_const_constraint<FieldT>(
			this->pb, this->less_or_eq, FieldT::zero(),
			FMT(this->annotation_prefix, " less_or_eq_one"));
}

template<typename FieldT>
void SHA256CompGreaterGadget<FieldT>::generate_r1cs_witness(const bit_vector &random_vector)
{
	this->generate_r1cs_witness_shared(random_vector);

	// value > 0
	this->pb.val(this->less) = FieldT::zero();
	this->pb.val(this->less_or_eq) = FieldT::zero();
}

template<typename FieldT>
void SHA256CompGreaterEqGadget<FieldT>::generate_r1cs_constraints()
{
	this->generate_r1cs_constraints_shared();

	// value >= 0
	generate_r1cs_equals_const_constraint<FieldT>(
			this->pb, this->less, FieldT::zero(),
			FMT(this->annotation_prefix, " less_one"));
}

template<typename FieldT>
void SHA256CompGreaterEqGadget<FieldT>::generate_r1cs_witness(const bit_vector &random_vector)
{
	this->generate_r1cs_witness_shared(random_vector);

	// value >= 0
	this->pb.val(this->less) = FieldT::zero();
}

} // unitn_crypto_fintech

#endif // SHA256_COMPARISON_GADGET_TCC

#ifndef SHA256_VALUE_COMPARISON_GADGET_TCC
#define SHA256_VALUE_COMPARISON_GADGET_TCC

#include "sha256_value_comparison_gadget.hpp"

using libsnark::gadget;
using libsnark::protoboard;
using libsnark::r1cs_constraint;
using libsnark::pb_variable;
using libsnark::pb_variable_array;
using libsnark::comparison_gadget;
using libsnark::generate_r1cs_equals_const_constraint;
using libff::bit_vector;
using std::string;
using std::make_shared;

namespace unitn_crypto_fintech {

template<typename FieldT>
SHA256ValueComparisonGadget<FieldT>::SHA256ValueComparisonGadget(
		libsnark::protoboard<FieldT> &pb,
		const libsnark::pb_variable<FieldT> &value1,
		const libsnark::pb_variable<FieldT> &value2,
		const libsnark::pb_variable_array<FieldT> &commitment1,
		const libsnark::pb_variable_array<FieldT> &commitment2,
		const std::string &annotation_prefix) :
	gadget<FieldT>(pb, annotation_prefix),
	value1(value1), value2(value2),
	commitment1(commitment1), commitment2(commitment2),
	commitment_gadget1(new SHA256CommitmentGadget<FieldT>(
			pb, value1, commitment1,
			FMT(this->annotation_prefix, " commitment_gadget1"))),
	commitment_gadget2(new SHA256CommitmentGadget<FieldT>(
			pb, value2, commitment2,
			FMT(this->annotation_prefix, " commitment_gadget2")))
{}

template<typename FieldT>
void SHA256ValueComparisonGadget<FieldT>::generate_r1cs_constraints_shared()
{
	commitment_gadget1->generate_r1cs_constraints();
	commitment_gadget2->generate_r1cs_constraints();
}

template<typename FieldT>
void SHA256ValueComparisonGadget<FieldT>::generate_r1cs_witness_shared(
			const libff::bit_vector &random_vector1,
			const libff::bit_vector &random_vector2)
{
	commitment_gadget1->generate_r1cs_witness(random_vector1);
	commitment_gadget2->generate_r1cs_witness(random_vector2);
}

template<typename FieldT>
void SHA256ValueEqualGadget<FieldT>::generate_r1cs_constraints()
{
	SHA256ValueComparisonGadget<FieldT>::generate_r1cs_constraints_shared();

	// value1 == value2
	this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(1, this->value1 - this->value2, 0),
			FMT(this->annotation_prefix, " equals_constraint"));
			
}

template<typename FieldT>
void SHA256ValueEqualGadget<FieldT>::generate_r1cs_witness(
			const libff::bit_vector &random_vector1,
			const libff::bit_vector &random_vector2)
{
	SHA256ValueComparisonGadget<FieldT>::generate_r1cs_witness_shared(
			random_vector1, random_vector2);
}

template<typename FieldT>
SHA256ValueGreaterEqGadget<FieldT>::SHA256ValueGreaterEqGadget(
		libsnark::protoboard<FieldT> &pb,
		const libsnark::pb_variable<FieldT> &value1,
		const libsnark::pb_variable<FieldT> &value2,
		const libsnark::pb_variable_array<FieldT> &commitment1,
		const libsnark::pb_variable_array<FieldT> &commitment2,
		const std::string &annotation_prefix) :
	SHA256ValueComparisonGadget<FieldT>(pb,
			value1, value2, commitment1, commitment2,
			annotation_prefix)
{
	less.allocate(pb, FMT(this->annotation_prefix, " less"));
	less_or_eq.allocate(pb, FMT(this->annotation_prefix, " less_or_eq"));

	comp_gadget = make_shared<comparison_gadget<FieldT>>(
			pb, FieldT::capacity(), this->value1, this->value2,
			less, less_or_eq,
			FMT(this->annotation_prefix, " comp_gadget"));
}

template<typename FieldT>
void SHA256ValueGreaterEqGadget<FieldT>::generate_r1cs_constraints()
{
	SHA256ValueComparisonGadget<FieldT>::generate_r1cs_constraints_shared();

	comp_gadget->generate_r1cs_constraints();

	// value1 >= value2
	generate_r1cs_equals_const_constraint<FieldT>(
			this->pb, this->less, FieldT::zero(),
			FMT(this->annotation_prefix, " less_zero"));
}

template<typename FieldT>
void SHA256ValueGreaterEqGadget<FieldT>::generate_r1cs_witness(
			const libff::bit_vector &random_vector1,
			const libff::bit_vector &random_vector2)
{
	SHA256ValueComparisonGadget<FieldT>::generate_r1cs_witness_shared(
			random_vector1, random_vector2);

	comp_gadget->generate_r1cs_witness();

	// value1 >= value2
	this->pb.val(this->less) = FieldT::zero();
}

} // unitn_crypto_fintech

#endif // SHA256_VALUE_COMPARISON_GADGET_TCC

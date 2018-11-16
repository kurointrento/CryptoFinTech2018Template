#ifndef SHA256_DOUBLE_COMPARISON_GADGET_TCC
#define SHA256_DOUBLE_COMPARISON_GADGET_TCC

#include "sha256_double_comparison_gadget.hpp"

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
SHA256DoubleComparisonGadget<FieldT>::SHA256DoubleComparisonGadget(
		protoboard<FieldT> &pb,
		const pb_variable<FieldT> &value,
		const pb_variable_array<FieldT> &commitment,
		const pb_variable<FieldT> &lower_bound,
		const pb_variable<FieldT> &upper_bound,
		const string &annotation_prefix) :
	gadget<FieldT>(pb, annotation_prefix),
	value(value), commitment(commitment),
	commitment_gadget(new SHA256CommitmentGadget<FieldT>(
			pb, value, commitment,
			FMT(this->annotation_prefix, " commitment_gadget"))),
	lower_bound(lower_bound), upper_bound(upper_bound)
{
	// New variable allocations
	lower_less.allocate(pb,
			FMT(this->annotation_prefix, " lower_less"));
	lower_less_or_eq.allocate(pb,
			FMT(this->annotation_prefix, " lower_less_or_eq"));
	upper_less.allocate(pb,
			FMT(this->annotation_prefix, " upper_less"));
	upper_less_or_eq.allocate(pb,
			FMT(this->annotation_prefix, " upper_less_or_eq"));

	// Compares lower_bound with value, so it needs to be a <=
	comp_lower_gadget = make_shared<comparison_gadget<FieldT>>(
			pb, FieldT::capacity(), lower_bound, value, 
			lower_less, lower_less_or_eq,
			FMT(this->annotation_prefix, " comp_lower_gadget"));

	// Compares value with upper_bound, so it needs to be a <=
	comp_upper_gadget = make_shared<comparison_gadget<FieldT>>(
			pb, FieldT::capacity(), value, upper_bound,
			upper_less, upper_less_or_eq,
			FMT(this->annotation_prefix, " comp_upper_gadget"));
}

template<typename FieldT>
void SHA256DoubleComparisonGadget<FieldT>::generate_r1cs_constraints()
{
	commitment_gadget->generate_r1cs_constraints();

	comp_lower_gadget->generate_r1cs_constraints();
	comp_upper_gadget->generate_r1cs_constraints();

	// lower_bound <= value <= upper_bound
	generate_r1cs_equals_const_constraint<FieldT>(
			this->pb, lower_less_or_eq, FieldT::one(),
			FMT(this->annotation_prefix, " lower_less_or_eq_one"));
	generate_r1cs_equals_const_constraint<FieldT>(
			this->pb, upper_less_or_eq, FieldT::one(),
			FMT(this->annotation_prefix, " upper_less_or_eq_one"));
}

template<typename FieldT>
void SHA256DoubleComparisonGadget<FieldT>::generate_r1cs_witness(
		const bit_vector& random_vector)
{
	commitment_gadget->generate_r1cs_witness(random_vector);
	
	comp_lower_gadget->generate_r1cs_witness();
	comp_upper_gadget->generate_r1cs_witness();

	// lower_bound <= value <= upper_bound
	this->pb.val(lower_less_or_eq) = FieldT::one();
	this->pb.val(upper_less_or_eq) = FieldT::one();
}

} // unitn_crypto_fintech

#endif // SHA256_DOUBLE_COMPARISON_GADGET_TCC

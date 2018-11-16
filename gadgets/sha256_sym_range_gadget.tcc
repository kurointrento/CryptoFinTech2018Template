#ifndef SHA256_SYM_RANGE_GADGET_TCC
#define SHA256_SYM_RANGE_GADGET_TCC

#include "sha256_sym_range_gadget.hpp"

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
SHA256SymmetricRangeGadget<FieldT>::SHA256SymmetricRangeGadget(
		protoboard<FieldT> &pb,
		const pb_variable<FieldT> &value,
		const pb_variable_array<FieldT> &commitment,
		const pb_variable<FieldT> &bound,
		const string &annotation_prefix) :
	gadget<FieldT>(pb, annotation_prefix),
	bound(bound)
{
	// New variable allocation
	inverse_bound.allocate(pb,
			FMT(this->annotation_prefix, " inverse_bound"));

	// Compares value with inverse_bound and bound
	double_comp_gadget = make_shared<SHA256DoubleComparisonGadget<FieldT>>(
			pb, value, commitment, inverse_bound, this->bound,
			FMT(this->annotation_prefix, " double_comp_gadget"));
}

template<typename FieldT>
void SHA256SymmetricRangeGadget<FieldT>::generate_r1cs_constraints()
{
	// 1 * (bound + inverse_bound) == 0
	this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(1, bound + inverse_bound, 0),
			FMT(this->annotation_prefix, " inverse_constraint"));

	double_comp_gadget->generate_r1cs_constraints();
}

template<typename FieldT>
void SHA256SymmetricRangeGadget<FieldT>::generate_r1cs_witness(
		const libff::bit_vector &random_vector)
{
	this->pb.val(inverse_bound) = - this->pb.val(bound);
	double_comp_gadget->generate_r1cs_witness(random_vector);
}

} // unitn_crypto_fintech

#endif // SHA256_SYM_RANGE_GADGET_TCC

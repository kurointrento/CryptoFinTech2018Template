#ifndef SHA256_DOUBLE_COMPARISON_GADGET_HPP
#define SHA256_DOUBLE_COMPARISON_GADGET_HPP

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

#include <gadgets/sha256_commitment_gadget.hpp>

namespace unitn_crypto_fintech {

template<typename FieldT>
class SHA256DoubleComparisonGadget : public libsnark::gadget<FieldT> {

	libsnark::pb_variable<FieldT> value;
	libsnark::pb_variable_array<FieldT> commitment;

	std::shared_ptr<SHA256CommitmentGadget<FieldT>> commitment_gadget;

	std::shared_ptr<libsnark::comparison_gadget<FieldT>> comp_lower_gadget;
	std::shared_ptr<libsnark::comparison_gadget<FieldT>> comp_upper_gadget;

	// Only less_or_eq will be used since two <= are necessary
	libsnark::pb_variable<FieldT> lower_less;
	libsnark::pb_variable<FieldT> lower_less_or_eq;
	libsnark::pb_variable<FieldT> upper_less;
	libsnark::pb_variable<FieldT> upper_less_or_eq;

	libsnark::pb_variable<FieldT> lower_bound;
	libsnark::pb_variable<FieldT> upper_bound;

public:
	SHA256DoubleComparisonGadget(libsnark::protoboard<FieldT> &pb,
			const libsnark::pb_variable<FieldT> &value,
			const libsnark::pb_variable_array<FieldT> &commitment,
			const libsnark::pb_variable<FieldT> &lower_bound,
			const libsnark::pb_variable<FieldT> &upper_bound,
			const std::string &annotation_prefix);

	void generate_r1cs_constraints();
	void generate_r1cs_witness(const libff::bit_vector &random_vector);
};

} // unitn_crypto_fintech

#include "sha256_double_comparison_gadget.tcc"

#endif // SHA256_DOUBLE_COMPARISON_GADGET_HPP

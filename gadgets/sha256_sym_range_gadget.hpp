#ifndef SHA256_SYM_RANGE_GADGET_HPP
#define SHA256_SYM_RANGE_GADGET_HPP

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

#include <gadgets/sha256_double_comparison_gadget.hpp>

namespace unitn_crypto_fintech {

template<typename FieldT>
class SHA256SymmetricRangeGadget : public libsnark::gadget<FieldT> {

	libsnark::pb_variable<FieldT> bound;
	libsnark::pb_variable<FieldT> inverse_bound;
	std::shared_ptr<SHA256DoubleComparisonGadget<FieldT>> double_comp_gadget;

public:
	SHA256SymmetricRangeGadget(libsnark::protoboard<FieldT> &pb,
			const libsnark::pb_variable<FieldT> &value,
			const libsnark::pb_variable_array<FieldT> &commitment,
			const libsnark::pb_variable<FieldT> &bound,
			const std::string &annotation_prefix);

	void generate_r1cs_constraints();
	void generate_r1cs_witness(const libff::bit_vector &random_vector);
};

} // unitn_crypto_fintech

#include "sha256_sym_range_gadget.tcc"

#endif // SHA256_SYM_RANGE_GADGET_HPP

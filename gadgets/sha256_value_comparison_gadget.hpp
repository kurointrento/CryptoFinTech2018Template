#ifndef SHA256_VALUE_COMPARISON_GADGET_HPP
#define SHA256_VALUE_COMPARISON_GADGET_HPP

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

#include <gadgets/sha256_commitment_gadget.hpp>

namespace unitn_crypto_fintech {

template<typename FieldT>
class SHA256ValueComparisonGadget : public libsnark::gadget<FieldT> {

	libsnark::pb_variable_array<FieldT> commitment1;
	libsnark::pb_variable_array<FieldT> commitment2;

	std::shared_ptr<SHA256CommitmentGadget<FieldT>> commitment_gadget1;
	std::shared_ptr<SHA256CommitmentGadget<FieldT>> commitment_gadget2;

protected:
	// These need to be accessible from the derived classes so that they
	// can impose further constraints on the relation between the values
	libsnark::pb_variable<FieldT> value1;
	libsnark::pb_variable<FieldT> value2;

	// These need to be called before the overridden methods in subclasses
	void generate_r1cs_constraints_shared();
	void generate_r1cs_witness_shared(
			const libff::bit_vector &random_vector1,
			const libff::bit_vector &random_vector2);

public:
	SHA256ValueComparisonGadget(libsnark::protoboard<FieldT> &pb,
			const libsnark::pb_variable<FieldT> &value1,
			const libsnark::pb_variable<FieldT> &value2,
			const libsnark::pb_variable_array<FieldT> &commitment1,
			const libsnark::pb_variable_array<FieldT> &commitment2,
			const std::string &annotation_prefix);
	
	virtual void generate_r1cs_constraints() = 0;
	virtual void generate_r1cs_witness(
			const libff::bit_vector &random_vector1,
			const libff::bit_vector &random_vector2) = 0;
};

template<typename FieldT>
class SHA256ValueEqualGadget : public SHA256ValueComparisonGadget<FieldT> {
public:
	using SHA256ValueComparisonGadget<FieldT>::SHA256ValueComparisonGadget;

	virtual void generate_r1cs_constraints() override;
	virtual void generate_r1cs_witness(
			const libff::bit_vector &random_vector1,
			const libff::bit_vector &random_vector2) override;
};

template<typename FieldT>
class SHA256ValueGreaterEqGadget : public SHA256ValueComparisonGadget<FieldT> {

	std::shared_ptr<libsnark::comparison_gadget<FieldT>> comp_gadget;

	libsnark::pb_variable<FieldT> less;
	libsnark::pb_variable<FieldT> less_or_eq;

public:
	SHA256ValueGreaterEqGadget(libsnark::protoboard<FieldT> &pb,
			const libsnark::pb_variable<FieldT> &value1,
			const libsnark::pb_variable<FieldT> &value2,
			const libsnark::pb_variable_array<FieldT> &commitment1,
			const libsnark::pb_variable_array<FieldT> &commitment2,
			const std::string &annotation_prefix);

	virtual void generate_r1cs_constraints() override;
	virtual void generate_r1cs_witness(
			const libff::bit_vector &random_vector1,
			const libff::bit_vector &random_vector2) override;
};

} // unitn_crypto_fintech

#include "sha256_value_comparison_gadget.tcc"

#endif // SHA256_VALUE_COMPARISON_GADGET_HPP

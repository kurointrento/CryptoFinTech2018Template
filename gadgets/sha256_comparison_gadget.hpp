#ifndef SHA256_COMPARISON_GADGET_HPP
#define SHA256_COMPARISON_GADGET_HPP

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

#include <gadgets/sha256_commitment_gadget.hpp>

namespace unitn_crypto_fintech {

template<typename FieldT>
class SHA256ComparisonGadget : public libsnark::gadget<FieldT> {

	libsnark::pb_variable<FieldT> value;
	libsnark::pb_variable_array<FieldT> commitment;

	std::shared_ptr<SHA256CommitmentGadget<FieldT>> commitment_gadget;

	libsnark::pb_variable<FieldT> zero;
	std::shared_ptr<libsnark::comparison_gadget<FieldT>> comp_gadget;

protected:
	// These need to be accessible to subclasses that want to set them and
	// impose constraints on them.
	libsnark::pb_variable<FieldT> less;
	libsnark::pb_variable<FieldT> less_or_eq;

	// These should be called at the beginning of the virtual methods by
	// subclasses.
	void generate_r1cs_constraints_shared();
	void generate_r1cs_witness_shared(const libff::bit_vector &random_vector);

public:
	SHA256ComparisonGadget(libsnark::protoboard<FieldT> &pb,
			const libsnark::pb_variable<FieldT> &value,
			const libsnark::pb_variable_array<FieldT> &commitment,
			const std::string &annotation_prefix);

	virtual void generate_r1cs_constraints() = 0;
	virtual void generate_r1cs_witness(const libff::bit_vector &random_vector) = 0;
};

template<typename FieldT>
class SHA256CompLessGadget : public SHA256ComparisonGadget<FieldT> {

public:
	using SHA256ComparisonGadget<FieldT>::SHA256ComparisonGadget;
	void generate_r1cs_constraints() override;
	void generate_r1cs_witness(const libff::bit_vector &random_vector) override;
};

template<typename FieldT>
class SHA256CompLessEqGadget : public SHA256ComparisonGadget<FieldT> {

public:
	using SHA256ComparisonGadget<FieldT>::SHA256ComparisonGadget;
	void generate_r1cs_constraints() override;
	void generate_r1cs_witness(const libff::bit_vector &random_vector) override;
};

template<typename FieldT>
class SHA256CompGreaterGadget : public SHA256ComparisonGadget<FieldT> {

public:
	using SHA256ComparisonGadget<FieldT>::SHA256ComparisonGadget;
	void generate_r1cs_constraints() override;
	void generate_r1cs_witness(const libff::bit_vector &random_vector) override;
};

template<typename FieldT>
class SHA256CompGreaterEqGadget : public SHA256ComparisonGadget<FieldT> {

public:
	using SHA256ComparisonGadget<FieldT>::SHA256ComparisonGadget;
	void generate_r1cs_constraints() override;
	void generate_r1cs_witness(const libff::bit_vector &random_vector) override;
};

} // unitn_crypto_fintech

#include "sha256_comparison_gadget.tcc"

#endif // SHA256_COMPARISON_GADGET_HPP

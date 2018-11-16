#include <gtest/gtest.h>

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libff/algebra/curves/public_params.hpp>
#include <libff/common/default_types/ec_pp.hpp>

#include <utils/proof.hpp>
#include <utils/random.hpp>
#include <gadgets/sha256_sym_range_gadget.hpp>

using std::shared_ptr;
using std::make_shared;

using libsnark::r1cs_constraint;
using libsnark::protoboard;
using libsnark::pb_variable;
using libsnark::pb_variable_array;
using libsnark::SHA256_digest_size;
using libff::div_ceil;
using libff::default_ec_pp;

using unitn_crypto_fintech::SHA256SymmetricRangeGadget;
using unitn_crypto_fintech::RandomBitVectorGenerator;
using unitn_crypto_fintech::test_proof_from_protoboard;
using unitn_crypto_fintech::test_proof_wrong_witness_from_protoboard;

typedef libff::Fr<default_ec_pp> DefaultField;

class SHA256SymmetricRangeTest : public ::testing::Test {
protected:
	RandomBitVectorGenerator generator;
	// Should not be default initialized before init_public_params()
	shared_ptr<protoboard<DefaultField>> pb;

	pb_variable<DefaultField> value;
	pb_variable_array<DefaultField> commitment;

	pb_variable<DefaultField> bound;

	shared_ptr<SHA256SymmetricRangeGadget<DefaultField>> sha256_sym_range_gadget;

	SHA256SymmetricRangeTest() {
		// General initialization
		default_ec_pp::init_public_params();
		pb = make_shared<protoboard<DefaultField>>();

		// Circuit initialization
		size_t commitment_size = div_ceil(SHA256_digest_size, DefaultField::capacity());
		// Commitment needs to be allocated before value, since it will
		// be the primary input for the constraint system
		commitment.allocate(*pb, commitment_size, "commitment");
		bound.allocate(*pb, "bound");

		// Primary input is commitment + bound
		pb->set_input_sizes(commitment_size + 1);

		value.allocate(*pb, "value");
		sha256_sym_range_gadget = make_shared<SHA256SymmetricRangeGadget<DefaultField>>(
				*pb, value, commitment, bound,
				"sha256_sym_range_gadget");

		// Constaints enforcement
		sha256_sym_range_gadget->generate_r1cs_constraints();
	}
};

TEST_F(SHA256SymmetricRangeTest, ValueInRangeSatisfiesCircuit) {
	pb->val(value) = 0;
	pb->val(bound) = 1;

	sha256_sym_range_gadget->generate_r1cs_witness(
			generator.generate_random_bit_vector(256));

	EXPECT_TRUE(pb->is_satisfied());
}

TEST_F(SHA256SymmetricRangeTest, ValueOnLowerBoundSatisfiesCircuit) {
	pb->val(value) = -1;
	pb->val(bound) = 1;

	sha256_sym_range_gadget->generate_r1cs_witness(
			generator.generate_random_bit_vector(256));

	EXPECT_TRUE(pb->is_satisfied());
}

TEST_F(SHA256SymmetricRangeTest, ValueOnUpperBoundSatisfiesCircuit) {
	pb->val(value) = 1;
	pb->val(bound) = 1;

	sha256_sym_range_gadget->generate_r1cs_witness(
			generator.generate_random_bit_vector(256));

	EXPECT_TRUE(pb->is_satisfied());
}

TEST_F(SHA256SymmetricRangeTest, ValueNotInRangeDoesNotSatisfyCircuit) {
	pb->val(value) = -2;
	pb->val(bound) = 1;

	sha256_sym_range_gadget->generate_r1cs_witness(
			generator.generate_random_bit_vector(256));

	EXPECT_FALSE(pb->is_satisfied());
}

TEST_F(SHA256SymmetricRangeTest, CircuitGeneratesCorrectProof) {
	pb->val(value) = 0;
	pb->val(bound) = 1;

	sha256_sym_range_gadget->generate_r1cs_witness(
			generator.generate_random_bit_vector(256));

	EXPECT_TRUE(test_proof_from_protoboard<default_ec_pp>(*pb));
}

TEST_F(SHA256SymmetricRangeTest, CircuitRecognizesWrongBound) {
	pb->val(value) = 0;
	pb->val(bound) = 1;

	sha256_sym_range_gadget->generate_r1cs_witness(
			generator.generate_random_bit_vector(256));

	// Keep same commitment but substitute bound
	r1cs_primary_input<DefaultField> wrong_witness(pb->primary_input());
	wrong_witness.pop_back();
	wrong_witness.push_back(2); // New bound with field element 2

	EXPECT_FALSE(test_proof_wrong_witness_from_protoboard<default_ec_pp>(*pb, wrong_witness));
}

int main(int argc, char **argv) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

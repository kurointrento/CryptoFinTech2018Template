#include <gtest/gtest.h>

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libff/algebra/curves/public_params.hpp>
#include <libff/common/default_types/ec_pp.hpp>

#include <utils/proof.hpp>
#include <utils/random.hpp>
#include <gadgets/sha256_double_comparison_gadget.hpp>

using std::shared_ptr;
using std::make_shared;

using libsnark::r1cs_constraint;
using libsnark::protoboard;
using libsnark::pb_variable;
using libsnark::pb_variable_array;
using libsnark::SHA256_digest_size;
using libff::div_ceil;
using libff::default_ec_pp;

using unitn_crypto_fintech::SHA256DoubleComparisonGadget;
using unitn_crypto_fintech::RandomBitVectorGenerator;
using unitn_crypto_fintech::test_proof_from_protoboard;
using unitn_crypto_fintech::test_proof_wrong_witness_from_protoboard;

typedef libff::Fr<default_ec_pp> DefaultField;

class SHA256DoubleComparisonTest : public ::testing::Test {
protected:
	RandomBitVectorGenerator generator;
	// Should not be default initialized before init_public_params()
	shared_ptr<protoboard<DefaultField>> pb;

	pb_variable<DefaultField> value;
	pb_variable_array<DefaultField> commitment;

	pb_variable<DefaultField> lower_bound;
	pb_variable<DefaultField> upper_bound;

	shared_ptr<SHA256DoubleComparisonGadget<DefaultField>> sha256_double_comp_gadget;

	SHA256DoubleComparisonTest() {
		// General initialization
		default_ec_pp::init_public_params();
		pb = make_shared<protoboard<DefaultField>>();

		// Circuit initialization
		size_t commitment_size = div_ceil(SHA256_digest_size, DefaultField::capacity());
		// Commitment needs to be allocated before value, since it will
		// be the primary input for the constraint system
		commitment.allocate(*pb, commitment_size, "commitment");
		lower_bound.allocate(*pb, "lower_bound");
		upper_bound.allocate(*pb, "upper_bound");

		// Primary input is commitment + lower_bound + upper_bound
		pb->set_input_sizes(commitment_size + 2);

		value.allocate(*pb, "value");
		sha256_double_comp_gadget = make_shared<SHA256DoubleComparisonGadget<DefaultField>>(
				*pb, value, commitment, lower_bound, upper_bound,
				"sha256_double_comp_gadget");

		// Constaints enforcement
		sha256_double_comp_gadget->generate_r1cs_constraints();
	}
};

TEST_F(SHA256DoubleComparisonTest, ValueInRangeSatisfiesCircuit) {
	pb->val(lower_bound) = -1;
	pb->val(value) = 0;
	pb->val(upper_bound) = 1;

	sha256_double_comp_gadget->generate_r1cs_witness(
			generator.generate_random_bit_vector(256));

	EXPECT_TRUE(pb->is_satisfied());
}

TEST_F(SHA256DoubleComparisonTest, ValueOnLowerBoundSatisfiesCircuit) {
	pb->val(lower_bound) = -1;
	pb->val(value) = -1;
	pb->val(upper_bound) = 1;

	sha256_double_comp_gadget->generate_r1cs_witness(
			generator.generate_random_bit_vector(256));

	EXPECT_TRUE(pb->is_satisfied());
}

TEST_F(SHA256DoubleComparisonTest, ValueOnUpperBoundSatisfiesCircuit) {
	pb->val(lower_bound) = -1;
	pb->val(value) = 1;
	pb->val(upper_bound) = 1;

	sha256_double_comp_gadget->generate_r1cs_witness(
			generator.generate_random_bit_vector(256));

	EXPECT_TRUE(pb->is_satisfied());
}

TEST_F(SHA256DoubleComparisonTest, ValueNotInRangeDoesNotSatisfyCircuit) {
	pb->val(lower_bound) = -1;
	pb->val(value) = -2;
	pb->val(upper_bound) = 1;

	sha256_double_comp_gadget->generate_r1cs_witness(
			generator.generate_random_bit_vector(256));

	EXPECT_FALSE(pb->is_satisfied());
}

TEST_F(SHA256DoubleComparisonTest, CircuitGeneratesCorrectProof) {
	pb->val(lower_bound) = -1;
	pb->val(value) = 0;
	pb->val(upper_bound) = 1;

	sha256_double_comp_gadget->generate_r1cs_witness(
			generator.generate_random_bit_vector(256));

	EXPECT_TRUE(test_proof_from_protoboard<default_ec_pp>(*pb));
}

TEST_F(SHA256DoubleComparisonTest, CircuitRecognizesWrongProof) {
	pb->val(lower_bound) = -1;
	pb->val(value) = 0;
	pb->val(upper_bound) = 1;

	sha256_double_comp_gadget->generate_r1cs_witness(
			generator.generate_random_bit_vector(256));

	r1cs_primary_input<DefaultField> wrong_witness(pb->primary_input().size(), 0);

	EXPECT_FALSE(test_proof_wrong_witness_from_protoboard<default_ec_pp>(*pb, wrong_witness));
}

int main(int argc, char **argv) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

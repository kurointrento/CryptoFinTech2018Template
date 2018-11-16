#include <gtest/gtest.h>

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libff/algebra/curves/public_params.hpp>
#include <libff/common/default_types/ec_pp.hpp>

#include <utils/proof.hpp>
#include <utils/random.hpp>
#include <gadgets/sha256_value_comparison_gadget.hpp>

using std::shared_ptr;
using std::make_shared;

using libsnark::r1cs_constraint;
using libsnark::protoboard;
using libsnark::pb_variable;
using libsnark::pb_variable_array;
using libsnark::SHA256_digest_size;
using libff::div_ceil;
using libff::default_ec_pp;

using unitn_crypto_fintech::SHA256ValueEqualGadget;
using unitn_crypto_fintech::RandomBitVectorGenerator;
using unitn_crypto_fintech::test_proof_from_protoboard;
using unitn_crypto_fintech::test_proof_wrong_witness_from_protoboard;

typedef libff::Fr<default_ec_pp> DefaultField;

class SHA256ValueEqualTest : public ::testing::Test {
protected:
	RandomBitVectorGenerator generator;
	// Should not be default initialized before init_public_params()
	shared_ptr<protoboard<DefaultField>> pb;

	pb_variable<DefaultField> value1;
	pb_variable<DefaultField> value2;
	pb_variable_array<DefaultField> commitment1;
	pb_variable_array<DefaultField> commitment2;

	shared_ptr<SHA256ValueEqualGadget<DefaultField>> sha256_value_equal_gadget;

	SHA256ValueEqualTest() {
		// General initialization
		default_ec_pp::init_public_params();
		pb = make_shared<protoboard<DefaultField>>();

		// Circuit initialization
		size_t commitment_size = div_ceil(SHA256_digest_size, DefaultField::capacity());
		// Commitment needs to be allocated before value, since it will
		// be the primary input for the constraint system
		commitment1.allocate(*pb, commitment_size, "commitment1");
		commitment2.allocate(*pb, commitment_size, "commitment2");

		// Primary input is commitment1 + commitment2
		pb->set_input_sizes(2 * commitment_size);

		value1.allocate(*pb, "value1");
		value2.allocate(*pb, "value2");
		sha256_value_equal_gadget = make_shared<SHA256ValueEqualGadget<DefaultField>>(
				*pb, value1, value2, commitment1, commitment2,
				"sha256_value_equal_gadget");

		// Constaints enforcement
		sha256_value_equal_gadget->generate_r1cs_constraints();
	}
};

TEST_F(SHA256ValueEqualTest, EqualValuesSatisfyCircuit) {
	pb->val(value1) = 1;
	pb->val(value2) = 1;

	sha256_value_equal_gadget->generate_r1cs_witness(
			generator.generate_random_bit_vector(256),
			generator.generate_random_bit_vector(256));

	EXPECT_TRUE(pb->is_satisfied());
}

TEST_F(SHA256ValueEqualTest, DifferentValuesDoNotSatisfyCircuit) {
	pb->val(value1) = 1;
	pb->val(value2) = 2;

	sha256_value_equal_gadget->generate_r1cs_witness(
			generator.generate_random_bit_vector(256),
			generator.generate_random_bit_vector(256));

	EXPECT_FALSE(pb->is_satisfied());
}

TEST_F(SHA256ValueEqualTest, CircuitGeneratesCorrectProof) {
	pb->val(value1) = 1;
	pb->val(value2) = 1;

	sha256_value_equal_gadget->generate_r1cs_witness(
			generator.generate_random_bit_vector(256),
			generator.generate_random_bit_vector(256));

	EXPECT_TRUE(test_proof_from_protoboard<default_ec_pp>(*pb));
}

TEST_F(SHA256ValueEqualTest, CircuitRecognizesWrongProof) {
	pb->val(value1) = 1;
	pb->val(value2) = 1;

	sha256_value_equal_gadget->generate_r1cs_witness(
			generator.generate_random_bit_vector(256),
			generator.generate_random_bit_vector(256));

	r1cs_primary_input<DefaultField> wrong_witness(pb->primary_input().size(), 0);

	EXPECT_FALSE(test_proof_wrong_witness_from_protoboard<default_ec_pp>(*pb, wrong_witness));
}

int main(int argc, char **argv) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

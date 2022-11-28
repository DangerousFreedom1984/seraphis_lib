// Copyright (c) 2022, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "crypto/crypto.h"
#include "crypto/x25519.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "crypto/generators.h"
#include "device/device.hpp"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/sp_core_enote_utils.h"
#include "seraphis/sp_core_types.h"
#include "seraphis_crypto/sp_composition_proof.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_generator_factory.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_misc_utils.h"
#include "seraphis_crypto/sp_multiexp.h"

#include "boost/multiprecision/cpp_int.hpp"
#include "gtest/gtest.h"

#include <memory>
#include <vector>


//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::secret_key make_secret_key()
{
    return rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_secret_key(crypto::secret_key &skey_out)
{
    skey_out = make_secret_key();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_fake_sp_masked_address(crypto::secret_key &mask,
    crypto::secret_key &view_stuff,
    crypto::secret_key &spendkey,
    rct::key &masked_address)
{
    make_secret_key(mask);
    make_secret_key(view_stuff);
    make_secret_key(spendkey);

    // K" = x G + kv_stuff X + ks U
    sp::make_seraphis_spendkey(view_stuff, spendkey, masked_address);
    sp::mask_key(mask, masked_address, masked_address);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <std::size_t Sz>
static void bitshift_array_right(const std::size_t bits, unsigned char (&arr)[Sz])
{
    ASSERT_TRUE(bits <= 8);
    static_assert(Sz > 0, "");

    unsigned char bits_for_next{0};
    unsigned char saved_bits{0};
    for (int i{Sz - 1}; i >= 0; --i)
    {
        bits_for_next = arr[i] & ((unsigned char)255 >> (8 - bits));
        arr[i] >>= bits;
        arr[i] |= saved_bits << (8 - bits);
        saved_bits = bits_for_next;
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <std::size_t Sz>
static void bitshift_array_left(const std::size_t bits, unsigned char (&arr)[Sz])
{
    ASSERT_TRUE(bits <= 8);
    static_assert(Sz > 0, "");

    unsigned char bits_for_next{0};
    unsigned char saved_bits{0};
    for (std::size_t i{0}; i <= Sz - 1; ++i)
    {
        bits_for_next = arr[i] & ((unsigned char)255 << (8 - bits));
        arr[i] <<= bits;
        arr[i] |= saved_bits >> (8 - bits);
        saved_bits = bits_for_next;
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_crypto, composition_proof)
{
    rct::key K;
    crypto::key_image KI;
    crypto::secret_key x, y, z;
    const rct::key message{rct::zero()};
    sp::SpCompositionProof proof;

    try
    {
        make_fake_sp_masked_address(x, y, z, K);
        sp::make_sp_composition_proof(message, K, x, y, z, proof);

        sp::make_seraphis_key_image(y, z, KI);
        EXPECT_TRUE(sp::verify_sp_composition_proof(proof, message, K, KI));
    }
    catch (...)
    {
        EXPECT_TRUE(false);
    }
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_crypto, multiexp_utility)
{
    rct::key result;

    // {1 G} == G
    sp::SpMultiexpBuilder builder1{rct::identity(), 0, 0};
    builder1.add_G_element(rct::identity());

    sp::SpMultiexp{{builder1}}.get_result(result);
    ASSERT_TRUE(result == crypto::get_G());

    // {I + 1 G} == G
    sp::SpMultiexpBuilder builder2{rct::identity(), 0, 1};
    builder2.add_element(rct::identity(), rct::identity());
    builder2.add_G_element(rct::identity());

    sp::SpMultiexp{{builder2}}.get_result(result);
    ASSERT_TRUE(result == crypto::get_G());

    // {1 G + I} == G
    sp::SpMultiexpBuilder builder3{rct::identity(), 0, 1};
    builder3.add_G_element(rct::identity());
    builder3.add_element(rct::identity(), rct::identity());

    sp::SpMultiexp{{builder3}}.get_result(result);
    ASSERT_TRUE(result == crypto::get_G());

    // {1 G + 1 G} == 2 G
    sp::SpMultiexpBuilder builder4{rct::identity(), 0, 0};
    std::vector<rct::MultiexpData> rct_builder4;
    builder4.add_G_element(rct::identity());
    rct_builder4.emplace_back(rct::identity(), crypto::get_G_p3());
    builder4.add_G_element(rct::identity());
    rct_builder4.emplace_back(rct::identity(), crypto::get_G_p3());

    sp::SpMultiexp{{builder4}}.get_result(result);
    ASSERT_TRUE(result == rct::pippenger(rct_builder4));

    // {1 G + 2 H + 3 U + 4 X} == G + H + U + X
    sp::SpMultiexpBuilder builder5{rct::identity(), 0, 0};
    std::vector<rct::MultiexpData> rct_builder5;
    rct::key temp_int_5{rct::identity()};
    builder5.add_G_element(temp_int_5);
    rct_builder5.emplace_back(temp_int_5, crypto::get_G_p3());
    sc_add(temp_int_5.bytes, temp_int_5.bytes, rct::identity().bytes);
    builder5.add_H_element(temp_int_5);
    rct_builder5.emplace_back(temp_int_5, crypto::get_H_p3());
    sc_add(temp_int_5.bytes, temp_int_5.bytes, rct::identity().bytes);
    builder5.add_U_element(temp_int_5);
    rct_builder5.emplace_back(temp_int_5, crypto::get_U_p3());
    sc_add(temp_int_5.bytes, temp_int_5.bytes, rct::identity().bytes);
    builder5.add_X_element(temp_int_5);
    rct_builder5.emplace_back(temp_int_5, crypto::get_X_p3());

    sp::SpMultiexp{{builder5}}.get_result(result);
    ASSERT_TRUE(result == rct::pippenger(rct_builder5));

    // {1 G + 1 P} == G + P
    sp::SpMultiexpBuilder builder6{rct::identity(), 0, 1};
    std::vector<rct::MultiexpData> rct_builder6;
    builder6.add_G_element(rct::identity());
    rct_builder6.emplace_back(rct::identity(), crypto::get_G_p3());
    rct::key temp_pk6{rct::pkGen()};
    builder6.add_element(rct::identity(), temp_pk6);
    rct_builder6.emplace_back(rct::identity(), temp_pk6);

    sp::SpMultiexp{{builder6}}.get_result(result);
    ASSERT_TRUE(result == rct::pippenger(rct_builder6));

    // {x G} == x G
    sp::SpMultiexpBuilder builder7{rct::identity(), 0, 0};
    std::vector<rct::MultiexpData> rct_builder7;
    rct::key temp_sk7{rct::skGen()};
    builder7.add_G_element(temp_sk7);
    rct_builder7.emplace_back(temp_sk7, crypto::get_G_p3());

    sp::SpMultiexp{{builder7}}.get_result(result);
    ASSERT_TRUE(result == rct::pippenger(rct_builder7));

    // {x G + y P} == x G + y P
    sp::SpMultiexpBuilder builder8{rct::identity(), 0, 1};
    std::vector<rct::MultiexpData> rct_builder8;
    rct::key temp_sk8_1{rct::skGen()};
    rct::key temp_sk8_2{rct::skGen()};
    rct::key temp_pk8{rct::pkGen()};
    builder8.add_G_element(temp_sk8_1);
    rct_builder8.emplace_back(temp_sk8_1, crypto::get_G_p3());
    builder8.add_element(temp_sk8_2, temp_pk8);
    rct_builder8.emplace_back(temp_sk8_2, temp_pk8);

    sp::SpMultiexp{{builder8}}.get_result(result);
    ASSERT_TRUE(result == rct::pippenger(rct_builder8));

    // {x G + y G[0] + z G[1]} == x G + y G[0] + z G[1]
    sp::SpMultiexpBuilder builder9{rct::identity(), 2, 0};
    std::vector<rct::MultiexpData> rct_builder9;
    rct::key temp_sk9_1{rct::skGen()};
    rct::key temp_sk9_2{rct::skGen()};
    rct::key temp_sk9_3{rct::skGen()};
    builder9.add_G_element(temp_sk9_1);
    rct_builder9.emplace_back(temp_sk9_1, crypto::get_G_p3());
    builder9.add_element(temp_sk9_2, sp::generator_factory::get_generator_at_index(0));
    rct_builder9.emplace_back(temp_sk9_2, rct::pk2rct(sp::generator_factory::get_generator_at_index(0)));
    builder9.add_element(temp_sk9_3, sp::generator_factory::get_generator_at_index(1));
    rct_builder9.emplace_back(temp_sk9_3, rct::pk2rct(sp::generator_factory::get_generator_at_index(1)));

    sp::SpMultiexp{{builder9}}.get_result(result);
    ASSERT_TRUE(result == rct::pippenger(rct_builder9));

    // {x P1 + y P2} == x P1 + y P2
    sp::SpMultiexpBuilder builder10{rct::identity(), 0, 1};
    std::vector<rct::MultiexpData> rct_builder10;
    rct::key temp_sk10_1{rct::skGen()};
    rct::key temp_sk10_2{rct::skGen()};
    rct::key temp_pk10_1{rct::pkGen()};
    rct::key temp_pk10_2{rct::pkGen()};
    builder10.add_element(temp_sk10_1, temp_pk10_1);
    rct_builder10.emplace_back(temp_sk10_1, temp_pk10_1);
    builder10.add_element(temp_sk10_2, temp_pk10_2);
    rct_builder10.emplace_back(temp_sk10_2, temp_pk10_2);

    sp::SpMultiexp{{builder10}}.get_result(result);
    ASSERT_TRUE(result == rct::pippenger(rct_builder10));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_crypto, x25519_sample_tests)
{
    // 1. x25519 private keys are byte buffers like rct::key
    crypto::x25519_scalar test1;
    const rct::key testrct{rct::skGen()};
    memcpy(test1.data, testrct.bytes, 32);
    ASSERT_TRUE(memcmp(test1.data, testrct.bytes, 32) == 0);

    // 2. x * G == x * G
    crypto::x25519_scalar test2_privkey;
    crypto::rand(32, test2_privkey.data);

    crypto::x25519_pubkey test2_key_port1;
    crypto::x25519_pubkey test2_key_port2;
    crypto::x25519_pubkey test2_key_auto1;
    crypto::x25519_pubkey test2_key_auto2;

    crypto::x25519_scmul_base(test2_privkey, test2_key_port1);
    crypto::x25519_scmul_base(test2_privkey, test2_key_auto1);

    const crypto::x25519_pubkey generator_G{crypto::get_x25519_G()};

    crypto::x25519_scmul_key(test2_privkey, generator_G, test2_key_port2);
    crypto::x25519_scmul_key(test2_privkey, generator_G, test2_key_auto2);

    ASSERT_TRUE(memcmp(&test2_key_port1, &test2_key_auto1, 32) == 0);
    ASSERT_TRUE(memcmp(&test2_key_port1, &test2_key_port2, 32) == 0);
    ASSERT_TRUE(memcmp(&test2_key_port1, &test2_key_auto2, 32) == 0);

    // 3. derive canonical x25519 scalar: H_n_x25519[k](x)
    for (int i{0}; i < 1000; ++i)
    {
        crypto::x25519_scalar test3_scalar;
        const rct::key test3_derivation_key{rct::skGen()};
        std::string test3_data{};

        sp::sp_derive_x25519_key(test3_derivation_key.bytes, test3_data, test3_scalar.data);
        ASSERT_TRUE(crypto::x25519_scalar_is_canonical(test3_scalar));
    }
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_crypto, x25519_invmul_key_test)
{
    rct::key temp{};
    temp.bytes[0] = 255;
    temp.bytes[1] = 255;
    temp.bytes[2] = 255;
    rct::key temp2{temp};
    bitshift_array_left(3, temp2.bytes);
    bitshift_array_right(3, temp2.bytes);
    ASSERT_TRUE(temp == temp2);

    // 1. make a scalar x >= 2^255 and x % 64 == 0
    crypto::x25519_scalar x{};
    x.data[0] = 255 - 63;
    x.data[31] = 128;

    // 2. 1/x
    // note: x25519 scalars are stored mul8 via bit shift, so we do (1/(8*reduce_32(x)) << 3)
    rct::key x_inv;
    memcpy(x_inv.bytes, x.data, 32);
    sc_reduce32(x_inv.bytes);  //mod l
    sc_mul(x_inv.bytes, rct::EIGHT.bytes, x_inv.bytes);  //8*x
    x_inv = sp::invert(x_inv);  //1/(8*x)
    bitshift_array_left(3, x_inv.bytes);  //1/(8*x) << 3

    rct::key x_recovered;
    memcpy(x_recovered.bytes, x_inv.bytes, 32);
    sc_reduce32(x_recovered.bytes);  //mod l
    sc_mul(x_recovered.bytes, rct::EIGHT.bytes, x_recovered.bytes);  //8*(1/x)
    x_recovered = sp::invert(x_recovered);  //1/(8*(1/x))
    bitshift_array_left(3, x_recovered.bytes);  //1/(8*(1/x)) << 3

    ASSERT_TRUE(memcmp(x.data, x_recovered.bytes, 32) == 0);  //can recover x by reversing the inversion

    crypto::x25519_scalar x_inv_copy;
    memcpy(x_inv_copy.data, x_inv.bytes, 32);
    ASSERT_TRUE(crypto::x25519_scalar_is_canonical(x_inv_copy));  //make sure result is canonical 

    // 3. P = 1/ (1/x) * G
    // note: 1/ (1/x) = x, which is invalid and should cause mx25519_invkey() to return an error, but then
    //       x25519_invkey_mul() handles that case
    crypto::x25519_pubkey P;
    crypto::x25519_invmul_key({x_inv_copy}, crypto::get_x25519_G(), P);

    // 4. expect: P == 8 * [(x >> 3) * G]  (the last bit of any scalar is ignored, so we first make x smaller by 8
    //    then mul8 [can't do div2, mul2 because the first 3 bits of any scalar are ignored so mul2 isn't possible])
    crypto::x25519_scalar x_shifted{x};
    bitshift_array_right(3, x_shifted.data);  //x >> 3

    crypto::x25519_pubkey P_reproduced;
    crypto::x25519_scmul_base(x_shifted, P_reproduced);  //(x >> 3) * G

    const crypto::x25519_scalar eight{crypto::x25519_eight()};
    crypto::x25519_scmul_key(eight, P_reproduced, P_reproduced);  //8 * [(x >> 3) * G]

    ASSERT_TRUE(P == P_reproduced);  //P == 8 * [(x >> 3) * G]
}
//-------------------------------------------------------------------------------------------------------------------

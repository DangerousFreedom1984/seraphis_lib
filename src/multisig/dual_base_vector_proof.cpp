// Copyright (c) 2021, The Monero Project
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

//paired header
#include "dual_base_vector_proof.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_crypto_utils.h"

//third party headers

//standard headers
#include <vector>

namespace config  //todo: move to config file
{
    const char HASH_KEY_CRYPTO_DUAL_BASE_VECTOR_PROOF[] = "dual_base_vector_proof";
}

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "crypto"

namespace crypto
{
//-------------------------------------------------------------------------------------------------------------------
// compute: A_inout += k * P
//-------------------------------------------------------------------------------------------------------------------
static void mul_add(const rct::key &k, const crypto::public_key &P, ge_p3 &A_inout)
{
    ge_p3 temp_p3;
    ge_cached temp_cache;
    ge_p1p1 temp_p1p1;

    CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&temp_p3, to_bytes(P)) == 0, "ge_frombytes_vartime failed!");
    ge_scalarmult_p3(&temp_p3, k.bytes, &temp_p3);  //k * P
    ge_p3_to_cached(&temp_cache, &temp_p3);
    ge_add(&temp_p1p1, &A_inout, &temp_cache);  //+ k * P
    ge_p1p1_to_p3(&A_inout, &temp_p1p1);
}
//-------------------------------------------------------------------------------------------------------------------
// Initialize transcript
//-------------------------------------------------------------------------------------------------------------------
static void transcript_init(rct::key &transcript)
{
    const std::string salt{config::HASH_KEY_CRYPTO_DUAL_BASE_VECTOR_PROOF};
    rct::cn_fast_hash(transcript, salt.data(), salt.size());
}
//-------------------------------------------------------------------------------------------------------------------
// Aggregation coefficient 'mu' for concise structure
//
// mu = H_n(H("domain-sep"), message, G_1, G_2, {V_1}, {V_2})
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_base_aggregation_coefficient(const rct::key &message,
    const crypto::public_key &G_1,
    const crypto::public_key &G_2,
    const std::vector<crypto::public_key> &V_1,
    const std::vector<crypto::public_key> &V_2)
{
    CHECK_AND_ASSERT_THROW_MES(V_1.size() == V_2.size(), "Transcript challenge inputs have incorrect size!");

    // initialize transcript message
    rct::key challenge;
    transcript_init(challenge);

    // collect challenge string
    std::string hash;
    hash.reserve((2 + 2*(V_1.size() + 1))*sizeof(rct::key));
    hash.append(reinterpret_cast<const char*>(challenge.bytes), sizeof(rct::key));
    hash.append(reinterpret_cast<const char*>(message.bytes), sizeof(rct::key));
    hash.append(reinterpret_cast<const char*>(G_1.data), sizeof(crypto::public_key));
    hash.append(reinterpret_cast<const char*>(G_2.data), sizeof(crypto::public_key));
    for (const crypto::public_key &V : V_1)
        hash.append(reinterpret_cast<const char*>(V.data), sizeof(crypto::public_key));
    for (const crypto::public_key &V : V_2)
        hash.append(reinterpret_cast<const char*>(V.data), sizeof(crypto::public_key));
    CHECK_AND_ASSERT_THROW_MES(hash.size() > 1, "Bad hash input size!");

    // challenge
    rct::hash_to_scalar(challenge, hash.data(), hash.size());

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge.bytes), "Transcript challenge must be nonzero!");

    return challenge;
}
//-------------------------------------------------------------------------------------------------------------------
// Fiat-Shamir challenge message
// challenge_message = H(message)
//
// note: in practice, this extends the aggregation coefficient (i.e. message = mu)
// challenge_message = H(H_n(H("domain-sep"), message, {V_1}, {V_2}))
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_challenge_message(const rct::key &message)
{
    rct::key challenge;
    std::string hash;
    hash.append(reinterpret_cast<const char*>(message.bytes), sizeof(rct::key));
    CHECK_AND_ASSERT_THROW_MES(hash.size() > 1, "Bad hash input size!");
    rct::cn_fast_hash(challenge, hash.data(), hash.size());

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge.bytes), "Transcript challenge must be nonzero!");

    return challenge;
}
//-------------------------------------------------------------------------------------------------------------------
// Fiat-Shamir challenge
// c = H_n(challenge_message, [V_1 proof key], [V_2 proof key])
//-------------------------------------------------------------------------------------------------------------------
static rct::key compute_challenge(const rct::key &message,
    const rct::key &V_1_proofkey,
    const rct::key &V_2_proofkey)
{
    rct::key challenge;
    std::string hash;
    hash.reserve(3*sizeof(rct::key));
    hash.append(reinterpret_cast<const char*>(message.bytes), sizeof(rct::key));
    hash.append(reinterpret_cast<const char*>(V_1_proofkey.bytes), sizeof(rct::key));
    hash.append(reinterpret_cast<const char*>(V_2_proofkey.bytes), sizeof(rct::key));
    CHECK_AND_ASSERT_THROW_MES(hash.size() > 1, "Bad hash input size!");
    rct::hash_to_scalar(challenge, hash.data(), hash.size());

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(challenge.bytes), "Transcript challenge must be nonzero!");

    return challenge;
}
//-------------------------------------------------------------------------------------------------------------------
// Proof response
// r = alpha - c * sum_i(mu^i * k_i)
//-------------------------------------------------------------------------------------------------------------------
static void compute_response(const std::vector<crypto::secret_key> &k,
    const rct::keyV &mu_pows,
    const rct::key &alpha,
    const rct::key &challenge,
    rct::key &r_out)
{
    CHECK_AND_ASSERT_THROW_MES(k.size() == mu_pows.size(), "Not enough keys!");

    // compute response
    // r = alpha - c * sum_i(mu^i * k_i)
    rct::key r_temp;
    rct::key r_sum_temp{rct::zero()};
    auto a_wiper = epee::misc_utils::create_scope_leave_handler([&]{
        // cleanup: clear secret prover data at the end
        memwipe(&r_temp, sizeof(rct::key));
        memwipe(&r_sum_temp, sizeof(rct::key));
    });

    for (std::size_t i{0}; i < k.size(); ++i)
    {
        sc_mul(r_temp.bytes, mu_pows[i].bytes, to_bytes(k[i]));  // mu^i * k_i
        sc_add(r_sum_temp.bytes, r_sum_temp.bytes, r_temp.bytes);  // sum_i(...)
    }
    sc_mulsub(r_out.bytes, challenge.bytes, r_sum_temp.bytes, alpha.bytes);  // alpha - c * sum_i(...)
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
DualBaseVectorProof dual_base_vector_prove(const rct::key &message,
    const crypto::public_key &G_1,
    const crypto::public_key &G_2,
    const std::vector<crypto::secret_key> &k)
{
    /// input checks and initialization
    const std::size_t num_keys{k.size()};
    CHECK_AND_ASSERT_THROW_MES(num_keys > 0, "Not enough keys to make a proof!");

    DualBaseVectorProof proof;
    proof.m = message;

    crypto::secret_key k_i_inv8_temp;
    std::vector<crypto::public_key> V_1_mul8;
    std::vector<crypto::public_key> V_2_mul8;
    V_1_mul8.reserve(num_keys);
    V_2_mul8.reserve(num_keys);
    proof.V_1.reserve(num_keys);
    proof.V_2.reserve(num_keys);

    for (std::size_t i{0}; i < num_keys; ++i)
    {
        CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(k[i])), "Bad private key (k[i] zero)!");
        CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(k[i])) == 0, "Bad private key (k[i])!");

        // k[i] * (1/8)
        sc_mul(to_bytes(k_i_inv8_temp), to_bytes(k[i]), rct::INV_EIGHT.bytes);

        // create the pubkey vectors
        proof.V_1.emplace_back(rct::rct2pk(rct::scalarmultKey(rct::pk2rct(G_1), rct::sk2rct(k_i_inv8_temp))));
        proof.V_2.emplace_back(rct::rct2pk(rct::scalarmultKey(rct::pk2rct(G_2), rct::sk2rct(k_i_inv8_temp))));
        V_1_mul8.emplace_back(rct::rct2pk(rct::scalarmult8(rct::pk2rct(proof.V_1.back()))));
        V_2_mul8.emplace_back(rct::rct2pk(rct::scalarmult8(rct::pk2rct(proof.V_2.back()))));

        CHECK_AND_ASSERT_THROW_MES(!(rct::pk2rct(V_1_mul8.back()) == rct::identity()),
            "Bad proof key (V_1[i] identity)!");
        CHECK_AND_ASSERT_THROW_MES(!(rct::pk2rct(V_2_mul8.back()) == rct::identity()),
            "Bad proof key (V_2[i] identity)!");
    }


    /// signature openers: alpha * G_1, alpha * G_2
    const crypto::secret_key alpha{rct::rct2sk(rct::skGen())};
    const rct::key alpha_1_pub{rct::scalarmultKey(rct::pk2rct(G_1), rct::sk2rct(alpha))};
    const rct::key alpha_2_pub{rct::scalarmultKey(rct::pk2rct(G_2), rct::sk2rct(alpha))};


    /// challenge message and aggregation coefficient
    const rct::key mu{compute_base_aggregation_coefficient(proof.m, G_1, G_2, V_1_mul8, V_2_mul8)};
    const rct::keyV mu_pows{sp::powers_of_scalar(mu, num_keys)};

    const rct::key m{compute_challenge_message(mu)};


    /// compute proof challenge
    proof.c = compute_challenge(m, alpha_1_pub, alpha_2_pub);


    /// responses
    compute_response(k, mu_pows, rct::sk2rct(alpha), proof.c, proof.r);


    /// done
    return proof;
}
//-------------------------------------------------------------------------------------------------------------------
bool dual_base_vector_verify(const DualBaseVectorProof &proof,
    const crypto::public_key &G_1,
    const crypto::public_key &G_2)
{
    /// input checks and initialization
    const std::size_t num_keys{proof.V_1.size()};

    CHECK_AND_ASSERT_THROW_MES(num_keys > 0, "Proof has no keys!");
    CHECK_AND_ASSERT_THROW_MES(num_keys == proof.V_2.size(), "Input key sets not the same size (V_2)!");

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(proof.r.bytes), "Bad response (r zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(proof.r.bytes) == 0, "Bad resonse (r)!");

    // recover the proof keys
    std::vector<crypto::public_key> V_1_mul8;
    std::vector<crypto::public_key> V_2_mul8;
    V_1_mul8.reserve(num_keys);
    V_2_mul8.reserve(num_keys);

    for (std::size_t key_index{0}; key_index < num_keys; ++key_index)
    {
        V_1_mul8.emplace_back(rct::rct2pk(rct::scalarmult8(rct::pk2rct(proof.V_1[key_index]))));
        V_2_mul8.emplace_back(rct::rct2pk(rct::scalarmult8(rct::pk2rct(proof.V_2[key_index]))));
    }


    /// challenge message and aggregation coefficient
    const rct::key mu{compute_base_aggregation_coefficient(proof.m, G_1, G_2, V_1_mul8, V_2_mul8)};
    const rct::keyV mu_pows{sp::powers_of_scalar(mu, num_keys)};

    const rct::key m{compute_challenge_message(mu)};


    /// challenge pieces

    // V_1 part: [r G_1 + c * sum_i(mu^i * V_1[i])]
    // V_2 part: [r G_2 + c * sum_i(mu^i * V_2[i])]
    ge_p3 V_1_part_p3;
    CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&V_1_part_p3, rct::identity().bytes) == 0,
        "ge_frombytes_vartime failed!");
    ge_p3 V_2_part_p3{V_1_part_p3};

    rct::key coeff_temp;

    for (std::size_t i{0}; i < num_keys; ++i)
    {
        // c * mu^i
        coeff_temp = proof.c;
        sc_mul(coeff_temp.bytes, coeff_temp.bytes, mu_pows[i].bytes);

        // V_1_part: + c * mu^i * V_1[i]
        mul_add(coeff_temp, V_1_mul8[i], V_1_part_p3);

        // V_2_part: + c * mu^i * V_2[i]
        mul_add(coeff_temp, V_2_mul8[i], V_2_part_p3);
    }

    // r G_1 + V_1_part
    mul_add(proof.r, G_1, V_1_part_p3);

    // r G_2 + V_2_part
    mul_add(proof.r, G_2, V_2_part_p3);


    /// compute nominal challenge and validate proof
    rct::key V_1_part;
    rct::key V_2_part;
    ge_p3_tobytes(V_1_part.bytes, &V_1_part_p3);
    ge_p3_tobytes(V_2_part.bytes, &V_2_part_p3);

    return compute_challenge(m, V_1_part, V_2_part) == proof.c;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace crypto

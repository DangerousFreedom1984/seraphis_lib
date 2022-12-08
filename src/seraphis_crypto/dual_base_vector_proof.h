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

////
// Schnorr-like dual-base proof for a pair of vectors: V_1 = {k_1 G1, k_2 G1, ...}, V_2 = {k_1 G2, k_2 G2, ...}
// - demonstrates knowledge of all k_1, k_2, k_3, ...
// - demonstrates that members of V_1 have a 1:1 discrete-log equivalence with the members of V_2, across base keys G1, G2
// - guarantees that V_1 and V_2 contain canonical prime-order subgroup group elements (they are stored multiplied by
//   (1/8) then multiplied by 8 before verification)
//
// proof outline
// 0. preliminaries
//    H_32(...) = blake2b(...) -> 32 bytes   hash to 32 bytes (domain separated)
//    H_n(...)  = H_64(...) mod l            hash to ed25519 scalar (domain separated)
//    G1, G2: assumed to be ed25519 keys
// 1. proof nonce and challenge
//    given: m, G_1, G_2, {k}
//    {V_1} = {k} * G_1
//    {V_2} = {k} * G_2
//    mu = H_n(m, G_1, G_2, {V_1}, {V_2})  aggregation coefficient
//    cm = H(mu)                           challenge message
//    a = rand()                           prover nonce
//    c = H_n(cm, [a*G1], [a*G2])
// 2. aggregate response
//    r = a - c * sum_i(mu^i * k_i)
// 3. proof: {m, c, r, {V_1}, {V_2}}
//
// verification
// 1. mu, cm = ...
// 2. c' = H_n(cm, [r*G1 + c*sum_i(mu^i*V_1[i])], [r*G2 + c*sum_i(mu^i*V_2[i])])
// 3. if (c' == c) then the proof is valid
//
// note: proof are 'concise' using the powers-of-aggregation coefficient approach from Triptych
//
// References:
// - Triptych (Sarang Noether): https://eprint.iacr.org/2020/018
// - Zero to Monero 2 (koe, Kurt Alonso, Sarang Noether): https://web.getmonero.org/library/Zero-to-Monero-2-0-0.pdf
//   - informational reference: Sections 3.1 and 3.2
///

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"

//third party headers
#include <boost/utility/string_ref.hpp>

//standard headers
#include <vector>

//forward declarations
namespace sp { class SpTranscriptBuilder; }

namespace sp
{

struct DualBaseVectorProof
{
    // message
    rct::key m;
    // challenge
    rct::key c;
    // response
    rct::key r;
    // pubkeys (stored multiplied by (1/8))
    std::vector<crypto::public_key> V_1;
    std::vector<crypto::public_key> V_2;
};
inline const boost::string_ref container_name(const DualBaseVectorProof&) { return "DualBaseVectorProof"; }
void append_to_transcript(const DualBaseVectorProof &container, SpTranscriptBuilder &transcript_inout);

/**
* brief: make_dual_base_vector_proof - create a dual base vector proof
* param: message - message to insert in Fiat-Shamir transform hash
* param: G_1 - base key of first vector
* param: G_2 - base key of second vector
* param: privkeys - secret keys k_1, k_2, ...
* outparam: proof_out - the proof
*/
void make_dual_base_vector_proof(const rct::key &message,
    const crypto::public_key &G_1,
    const crypto::public_key &G_2,
    const std::vector<crypto::secret_key> &privkeys,
    DualBaseVectorProof &proof_out);
/**
* brief: verify_dual_base_vector_proof - verify a dual base vector proof
* param: proof - proof to verify
* param: G_1 - base key of first vector
* param: G_2 - base key of second vector
* return: true/false on verification result
*/
bool verify_dual_base_vector_proof(const DualBaseVectorProof &proof,
    const crypto::public_key &G_1,
    const crypto::public_key &G_2);

} //namespace sp

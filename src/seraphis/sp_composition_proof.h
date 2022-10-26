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

// NOT FOR PRODUCTION

////
// Schnorr-like composition proof for a secret key of the form K = x*G + y*X + z*U
// - demonstrates knowledge of x, y, z
//   - x >= 0
//   - y, z > 0
// - shows that key image KI = (z/y)*U
//
// proof outline
// 0. preliminaries
//    H_32(...) = blake2b(...) -> 32 bytes    hash to 32 bytes
//    H_n(...)  = H_64(...) mod l             hash to ed25519 scalar
//    G, X, U: ed25519 generators
// 1. pubkeys
//    K    = x*G + y*X + z*U
//    K_t1 = (x/y)*G + X + (z/y)*U
//    K_t2 = (x/y)*G            = K_t1 - X - KI
//    KI   = (z/y)*U
// 2. proof nonces and challenge
//    cm = H_32(X, U, m, K, KI, K_t1)   challenge message
//    a_t1, a_t2, a_ki = rand()                       prover nonces
//    c = H_n(cm, [a_t1 K], [a_t2 G], [a_ki U])       challenge
// 3. responses
//    r_t1 = a_t1 - c*(1/y)
//    r_t2 = a_t2 - c*(x/y)
//    r_ki = a_ki - c*(z/y)
// 4. proof: {m, c, r_t1, r_t2, r_ki, K, K_t1, KI}
//
// verification
// 1. K_t2 = K_t1 - X - KI, cm = ...
// 2. c' = H_n(cm, [r_t1*K + c*K_t1], [r_t2*G + c*K_t2], [r_ki*U + c*KI])
// 3. if (c' == c) then the proof is valid
//
// note: G_0 = G, G_1 = X, G_2 = U (for Seraphis paper notation)
// note: in practice, K is a masked address from a Seraphis enote image, and KI is the corresponding linking tag
// note: assume key image KI is in the prime subgroup (canonical bytes) and non-identity
//   - WARNING: the caller must validate KI (and check non-identity); either...
//     - 1) l*KI == identity
//     - 2) store (1/8)*KI with proof material (e.g. in a transaction); pass 8*[(1/8)*KI] as input to composition proof
//          validation
//
// multisig notation: alpha_{a,n,e}
// - a: indicates which part of the proof this is for
// - n: for MuSig2-style bi-nonce signing, alpha_{b,1,e} is nonce 'D', alpha_{b,2,e} is nonce 'E' (in their notation)
// - e: multisig signer index
//
// References:
// - Seraphis (UkoeHB): https://github.com/UkoeHB/Seraphis (temporary reference)
//
// Multisig references:
// - MuSig2 (Nick): https://eprint.iacr.org/2020/1261
// - FROST (Komlo): https://eprint.iacr.org/2020/852
// - Multisig/threshold security (Crites): https://eprint.iacr.org/2021/1375
// - MRL-0009 (Brandon Goodell and Sarang Noether): https://web.getmonero.org/resources/research-lab/pubs/MRL-0009.pdf
// - Zero to Monero: 2nd Edition Chapter 9 (UkoeHB): https://web.getmonero.org/library/Zero-to-Monero-2-0-0.pdf
// - (Technical Note) Multisig - Defeating Drijvers with Bi-Nonce Signing (UkoeHB):
//     https://github.com/UkoeHB/drijvers-multisig-tech-note
///


#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "sp_multisig_nonce_record.h"

//third party headers
#include <boost/utility/string_ref.hpp>

//standard headers
#include <string>
#include <unordered_map>
#include <vector>

//forward declarations
namespace sp { class SpTranscriptBuilder; }


namespace sp
{

////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////// Types ////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

////
// Seraphis composition proof
///
struct SpCompositionProof final
{
    // challenge
    rct::key c;
    // responses
    rct::key r_t1, r_t2, r_ki;
    // intermediate proof key (stored as (1/8)*K_t1)
    rct::key K_t1;
    // key image KI: not stored with proof
    // main proof key K: not stored with proof
    // message m: not stored with proof

    static std::size_t get_size_bytes() { return 32*5; }
};
inline const boost::string_ref get_container_name(const SpCompositionProof&) { return "SpCompositionProof"; }
void append_to_transcript(const SpCompositionProof &container, SpTranscriptBuilder &transcript_inout);

////
// Multisig signature proposal
// - all parts required to make signature, other than the (KI component) split between multisig participants
//
// WARNING: must only use a 'proposal' to make ONE 'signature' (or signature attempt),
//          after that the opening privkeys should be deleted immediately
///
struct SpCompositionProofMultisigProposal final
{
    // message
    rct::key message;
    // main proof key K
    rct::key K;
    // key image KI
    crypto::key_image KI;

    // signature nonce (shared component): alpha_t1
    crypto::secret_key signature_nonce_K_t1;
    // signature nonce (shared component): alpha_t2
    crypto::secret_key signature_nonce_K_t2;
};

////
// Multisig partially signed composition proof (from one multisig participant)
// - multisig assumes only proof component KI is subject to multisig signing (key z is split between signers)
// - store signature opening for KI component (response r_ki)
///
struct SpCompositionProofMultisigPartial final
{
    // message
    rct::key message;
    // main proof key K
    rct::key K;
    // key image KI
    crypto::key_image KI;

    // challenge
    rct::key c;
    // responses r_t1, r_t2
    rct::key r_t1, r_t2;
    // intermediate proof key K_t1
    rct::key K_t1;

    // partial response for r_ki (from one multisig participant)
    rct::key r_ki_partial;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////// Main /////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
* brief: sp_composition_prove - create a Seraphis composition proof
* param: message - message to insert in Fiat-Shamir transform hash
* param: K - main proof key = x G + y X + z U
* param: x - secret key
* param: y - secret key
* param: z - secret key
* return: Seraphis composition proof
*/
SpCompositionProof sp_composition_prove(const rct::key &message,
    const rct::key &K,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z);
/**
* brief: sp_composition_verify - verify a Seraphis composition proof
* param: proof - proof to verify
* param: message - message to insert in Fiat-Shamir transform hash
* param: K - main proof key = x G + y X + z U
* param: KI - proof key image = (z/y) U
* return: true/false on verification result
*/
bool sp_composition_verify(const SpCompositionProof &proof,
    const rct::key &message,
    const rct::key &K,
    const crypto::key_image &KI);

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////// Multisig ///////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
* brief: sp_composition_multisig_proposal - propose to make a multisig Seraphis composition proof
* param: message - message to insert in the proof's Fiat-Shamir transform hash
* param: K - main proof key
* param: KI - key image
* return: Seraphis composition proof multisig proposal
*/
SpCompositionProofMultisigProposal sp_composition_multisig_proposal(const rct::key &message,
    const rct::key &K,
    const crypto::key_image &KI);
/**
* brief: sp_composition_multisig_partial_sig - make local multisig signer's partial signature for a Seraphis composition
*        proof
*   - caller must validate 'proposal'
*       - is the key image well-made?
*       - is the main key legitimate?
*       - is the message correct?
* param: proposal - proof proposal to construct proof partial signature from
* param: x - secret key
* param: y - secret key
* param: z_e - secret key of multisig signer e
* param: signer_pub_nonces - signature nonce pubkeys (1/8) * {alpha_{ki,1,e}*U,  alpha_{ki,2,e}*U} from all signers
*                            (including local signer)
* param: local_nonce_1_priv - alpha_{ki,1,e} for local signer
* param: local_nonce_2_priv - alpha_{ki,2,e} for local signer
* return: partially signed Seraphis composition proof
*/
SpCompositionProofMultisigPartial sp_composition_multisig_partial_sig(const SpCompositionProofMultisigProposal &proposal,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z_e,
    const std::vector<MultisigPubNonces> &signer_pub_nonces,
    const crypto::secret_key &local_nonce_1_priv,
    const crypto::secret_key &local_nonce_2_priv);
/**
* brief: try_make_sp_composition_multisig_partial_sig - make a partial signature using a nonce record (nonce safety guarantee)
*        proof
*   - caller must validate 'proposal'
*       - is the key image well-made?
*       - is the main key legitimate?
*       - is the message correct?
* param: ...(see sp_composition_multisig_partial_sig())
* param: filter - filter representing a multisig signer group that is supposedly working on this signature
* inoutparam: nonce_record_inout - a record of nonces for makeing partial signatures; used nonces will be cleared
* outparam: partial_sig_out - the partial signature
* return: true if creating the partial signature succeeded
*/
bool try_make_sp_composition_multisig_partial_sig(
    const SpCompositionProofMultisigProposal &proposal,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const crypto::secret_key &z_e,
    const std::vector<MultisigPubNonces> &signer_pub_nonces,
    const multisig::signer_set_filter filter,
    MultisigNonceRecord &nonce_record_inout,
    SpCompositionProofMultisigPartial &partial_sig_out);
/**
* brief: sp_composition_prove_multisig_final - create a Seraphis composition proof from multisig partial signatures
* param: partial_sigs - partial signatures from enough multisig participants to complete a full proof
* return: Seraphis composition proof
*/
SpCompositionProof sp_composition_prove_multisig_final(const std::vector<SpCompositionProofMultisigPartial> &partial_sigs);

} //namespace sp

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

// NOT FOR PRODUCTION

// Seraphis transaction component types.


#pragma once

//local headers
#include "common/variant.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/bulletproofs_plus2.h"
#include "seraphis_crypto/grootle.h"
#include "seraphis_crypto/sp_composition_proof.h"
#include "sp_core_types.h"
#include "tx_binned_reference_set.h"
#include "tx_extra.h"

//third party headers
#include <boost/utility/string_ref.hpp>

//standard headers
#include <string>

//forward declarations
namespace sp { class SpTranscriptBuilder; }


namespace sp
{

////
// SpCoinbaseEnoteV1
///
struct SpCoinbaseEnoteV1 final
{
    /// enote core (one-time address, amount)
    SpCoinbaseEnoteCore m_core;

    /// addr_tag_enc
    jamtis::encrypted_address_tag_t m_addr_tag_enc;
    /// view_tag
    jamtis::view_tag_t m_view_tag;

    /// less-than operator for sorting
    bool operator<(const SpCoinbaseEnoteV1 &other_enote) const { return m_core < other_enote.m_core; }
    /// comparison operator for equivalence testing
    bool operator==(const SpCoinbaseEnoteV1 &other_enote) const;

    /// generate a dummy v1 coinbase enote (all random; completely unspendable)
    void gen();

    static std::size_t size_bytes()
    {
        return SpCoinbaseEnoteCore::size_bytes() +
            sizeof(jamtis::encrypted_address_tag_t) +
            sizeof(jamtis::view_tag_t);
    }
};
inline const boost::string_ref container_name(const SpCoinbaseEnoteV1&) { return "SpCoinbaseEnoteV1"; }
void append_to_transcript(const SpCoinbaseEnoteV1 &container, SpTranscriptBuilder &transcript_inout);

////
// SpEnoteV1
///
struct SpEnoteV1 final
{
    /// enote core (one-time address, amount commitment)
    SpEnoteCore m_core;

    /// enc(a)
    rct::xmr_amount m_encoded_amount;
    /// addr_tag_enc
    jamtis::encrypted_address_tag_t m_addr_tag_enc;
    /// view_tag
    jamtis::view_tag_t m_view_tag;

    /// less-than operator for sorting
    bool operator<(const SpEnoteV1 &other_enote) const { return m_core < other_enote.m_core; }
    /// comparison operator for equivalence testing
    bool operator==(const SpEnoteV1 &other_enote) const;

    /// generate a dummy v1 enote (all random; completely unspendable)
    void gen();

    static std::size_t size_bytes()
    {
        return SpEnoteCore::size_bytes() +
            sizeof(rct::xmr_amount) +
            sizeof(jamtis::encrypted_address_tag_t) +
            sizeof(jamtis::view_tag_t);
    }
};
inline const boost::string_ref container_name(const SpEnoteV1&) { return "SpEnoteV1"; }
void append_to_transcript(const SpEnoteV1 &container, SpTranscriptBuilder &transcript_inout);

////
// SpEnoteVariant
// - variant of all seraphis enote types
//
// core_ref(): get a copy of the enote's core
// onetime_address_ref(): get the enote's onetime address
// amount_commitment_ref(): get the enote's amount commitment (this is a copy because coinbase enotes need to
//                          compute the commitment)
// addr_tag_enc_ref(): get the enote's encrypted address tag
// view_tag_ref(): get the enote's view tag
// operator==(): check if two enotes are equal
///
using SpEnoteVariant = tools::variant<SpCoinbaseEnoteV1, SpEnoteV1>;
SpEnoteCoreVariant core_ref(const SpEnoteVariant &variant);
const rct::key& onetime_address_ref(const SpEnoteVariant &variant);
rct::key amount_commitment_ref(const SpEnoteVariant &variant);
const jamtis::encrypted_address_tag_t& addr_tag_enc_ref(const SpEnoteVariant &variant);
jamtis::view_tag_t view_tag_ref(const SpEnoteVariant &variant);
bool operator==(const SpEnoteVariant &variant1, const SpEnoteVariant &variant2);

////
// SpEnoteImageV1
///
struct SpEnoteImageV1 final
{
    /// enote image core (masked address, masked amount commitment, key image)
    SpEnoteImageCore m_core;

    /// less-than operator for sorting
    bool operator<(const SpEnoteImageV1 &other_image) const { return m_core < other_image.m_core; }

    static std::size_t size_bytes() { return SpEnoteImageCore::size_bytes(); }
};
inline const boost::string_ref container_name(const SpEnoteImageV1&) { return "SpEnoteImageV1"; }
void append_to_transcript(const SpEnoteImageV1 &container, SpTranscriptBuilder &transcript_inout);

////
// SpMembershipProofV1
// - Grootle
///
struct SpMembershipProofV1 final
{
    /// a grootle proof
    GrootleProof m_grootle_proof;
    /// binned representation of ledger indices of enotes referenced by the proof
    SpBinnedReferenceSetV1 m_binned_reference_set;
    /// ref set size = n^m
    std::size_t m_ref_set_decomp_n;
    std::size_t m_ref_set_decomp_m;

    /// size of the membership proof (does not include the ref set decomp)
    static std::size_t size_bytes(const std::size_t n, const std::size_t m, const std::size_t num_bin_members);
    std::size_t size_bytes() const;
};
inline const boost::string_ref container_name(const SpMembershipProofV1&) { return "SpMembershipProofV1"; }
void append_to_transcript(const SpMembershipProofV1 &container, SpTranscriptBuilder &transcript_inout);

////
// SpImageProofV1
// - ownership and unspentness (legitimacy of key image)
// - Seraphis composition proof
///
struct SpImageProofV1 final
{
    /// a seraphis composition proof
    SpCompositionProof m_composition_proof;

    static std::size_t size_bytes() { return SpCompositionProof::size_bytes(); }
};
inline const boost::string_ref container_name(const SpImageProofV1&) { return "SpImageProofV1"; }
void append_to_transcript(const SpImageProofV1 &container, SpTranscriptBuilder &transcript_inout);

////
// SpBalanceProofV1
// - balance proof: implicit with a remainder blinding factor: [sum(inputs) == sum(outputs) + remainder_blinding_factor*G]
// - range proof: Bulletproofs+ v2
// note: only seraphis inputs are range proofed (legacy inputs are not)
///
struct SpBalanceProofV1 final
{
    /// an aggregate set of BP+ proofs
    BulletproofPlus2 m_bpp2_proof;
    /// the remainder blinding factor
    rct::key m_remainder_blinding_factor;

    static std::size_t size_bytes(const std::size_t num_sp_inputs,
        const std::size_t num_outputs,
        const bool include_commitments = false);
    std::size_t size_bytes(const bool include_commitments = false) const;
    static std::size_t weight(const std::size_t num_sp_inputs,
        const std::size_t num_outputs,
        const bool include_commitments = false);
    std::size_t weight(const bool include_commitments = false) const;
};
inline const boost::string_ref container_name(const SpBalanceProofV1&) { return "SpBalanceProofV1"; }
void append_to_transcript(const SpBalanceProofV1 &container, SpTranscriptBuilder &transcript_inout);

////
// SpTxSupplementV1
// - supplementary info about a tx
//   - enote ephemeral pubkeys: may not line up 1:1 with output enotes, so store in separate field
//   - tx memo
///
struct SpTxSupplementV1 final
{
    /// xKe: enote ephemeral pubkeys for outputs
    std::vector<crypto::x25519_pubkey> m_output_enote_ephemeral_pubkeys;
    /// tx memo
    TxExtra m_tx_extra;

    static std::size_t size_bytes(const std::size_t num_outputs,
        const TxExtra &tx_extra,
        const bool use_shared_ephemeral_key_assumption);
    std::size_t size_bytes() const;
};
inline const boost::string_ref container_name(const SpTxSupplementV1&) { return "SpTxSupplementV1"; }
void append_to_transcript(const SpTxSupplementV1 &container, SpTranscriptBuilder &transcript_inout);

} //namespace sp

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

// Seraphis transaction-builder helper types.


#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "ringct/rctTypes.h"
#include "jamtis_payment_proposal.h"
#include "sp_core_types.h"
#include "tx_component_types.h"
#include "tx_discretized_fee.h"
#include "tx_extra.h"
#include "tx_legacy_builder_types.h"
#include "tx_legacy_component_types.h"

//third party headers

//standard headers

//forward declarations
namespace sp
{
namespace jamtis
{
    struct JamtisPaymentProposalV1;
    struct JamtisPaymentProposalSelfSendV1;
}
}

namespace sp
{

////
// SpInputProposalV1
///
struct SpInputProposalV1 final
{
    /// core of the proposal
    SpInputProposal m_core;

    /// less-than operator for sorting
    bool operator<(const SpInputProposalV1 &other_proposal) const { return m_core < other_proposal.m_core; }

    /**
    * brief: get_enote_image_v1 - get this input's enote image in the squashed enote model
    * outparam: image_out -
    */
    void get_enote_image_v1(SpEnoteImageV1 &image_out) const { m_core.get_enote_image_core(image_out.m_core); }

    /**
    * brief: get_squash_prefix - get this input's enote's squash prefix
    * outparam: squash_prefix_out - H_n(Ko, C)
    */
    void get_squash_prefix(rct::key &squash_prefix_out) const { m_core.get_squash_prefix(squash_prefix_out); }

    /// get the amount of this proposal
    rct::xmr_amount amount() const { return m_core.m_amount; }

    /// generate a v1 input (does not support info recovery)
    void gen(const crypto::secret_key &sp_spend_privkey, const rct::xmr_amount amount)
    {
        m_core.gen(sp_spend_privkey, amount);
    }
};

////
// SpOutputProposalV1
///
struct SpOutputProposalV1 final
{
    /// core of the proposal
    SpOutputProposal m_core;

    /// xK_e: enote ephemeral pubkey
    crypto::x25519_pubkey m_enote_ephemeral_pubkey;
    /// enc_a
    rct::xmr_amount m_encoded_amount;
    /// addr_tag_enc
    jamtis::encrypted_address_tag_t m_addr_tag_enc;
    /// view_tag
    jamtis::view_tag_t m_view_tag;

    /// memo elements to add to the tx memo
    TxExtra m_partial_memo;

    /// less-than operator for sorting
    bool operator<(const SpOutputProposalV1 &other_proposal) const { return m_core < other_proposal.m_core; }

    /// convert this destination into a v1 enote
    void get_enote_v1(SpEnoteV1 &enote_out) const;

    /// get the amount of this proposal
    rct::xmr_amount amount() const { return m_core.m_amount; }

    /**
    * brief: gen - generate a V1 Destination (random)
    * param: amount -
    * param: num_random_memo_elements -
    */
    void gen(const rct::xmr_amount amount, const std::size_t num_random_memo_elements);
};

////
// SpMembershipProofPrepV1
// - data for producing a membership proof
///
struct SpMembershipProofPrepV1 final
{
    /// ref set size = n^m
    std::size_t m_ref_set_decomp_n;
    std::size_t m_ref_set_decomp_m;
    /// binned representation of ledger indices of enotes referenced by the proof
    /// - only enotes in the ledger can have a membership proof
    SpBinnedReferenceSetV1 m_binned_reference_set;
    /// the referenced enotes (squashed representation)
    std::vector<rct::key> m_referenced_enotes_squashed;
    /// the real enote being referenced (plain enote representation)
    SpEnote m_real_reference_enote;
    /// image masks for the real reference
    crypto::secret_key m_address_mask;
    crypto::secret_key m_commitment_mask;
};

////
// SpAlignableMembershipProofV1 - Alignable Membership Proof V1
// - the masked address can be used to match this membership proof with its input image
//   - note: matching can fail if a masked address is reused in a tx, but that is almost definitely an implementation error!
///
struct SpAlignableMembershipProofV1 final
{
    /// masked address used in the membership proof (for matching with actual input image)
    rct::key m_masked_address;
    /// the membership proof
    SpMembershipProofV1 m_membership_proof;

    /// overloaded operator for aligning
    bool operator==(const SpAlignableMembershipProofV1 &other) const { return m_masked_address == other.m_masked_address; }
    bool operator==(const rct::key &other_masked_address) const { return m_masked_address == other_masked_address; }
};

////
// SpTxProposalV1: the proposed set of inputs and outputs, with tx fee and miscellaneous memos
///
struct SpTxProposalV1 final
{
    /// outputs (SORTED)
    std::vector<jamtis::JamtisPaymentProposalV1> m_normal_payment_proposals;
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> m_selfsend_payment_proposals;
    /// tx fee
    DiscretizedFee m_tx_fee;
    /// legacy input proposals (SORTED)
    std::vector<LegacyInputProposalV1> m_legacy_input_proposals;
    /// seraphis input proposals (SORTED)
    std::vector<SpInputProposalV1> m_sp_input_proposals;
    /// partial memo
    TxExtra m_partial_memo;

    /// convert the tx proposal's payment proposals into output proposals
    void get_output_proposals_v1(const crypto::secret_key &k_view_balance,
        std::vector<SpOutputProposalV1> &output_proposals_out) const;

    /// get the message to be signed by input spend proofs
    void get_proposal_prefix(const std::string &version_string,
        const crypto::secret_key &k_view_balance,
        rct::key &proposal_prefix_out) const;
};

////
// SpPartialInputV1
// - enote spent
// - cached amount and amount blinding factor, image masks (for balance and membership proofs)
// - spend proof for input (and proof the input's key image is properly constructed)
// - proposal prefix (spend proof msg) [for consistency checks when handling this object]
///
struct SpPartialInputV1 final
{
    /// input's image
    SpEnoteImageV1 m_input_image;
    /// input image's proof (demonstrates ownership of the underlying enote, and that the key image is correct)
    SpImageProofV1 m_image_proof;
    /// image masks
    crypto::secret_key m_address_mask;
    crypto::secret_key m_commitment_mask;

    /// tx proposal prefix (represents the inputs/outputs/fee/memo; signed by this partial input's image proof)
    rct::key m_proposal_prefix;

    /// the input enote's core; used for making a membership proof
    SpEnote m_input_enote_core;
    /// input amount
    rct::xmr_amount m_input_amount;
    /// input amount commitment's blinding factor; used for making the balance proof
    crypto::secret_key m_input_amount_blinding_factor;

    /// less-than operator for sorting
    bool operator<(const SpPartialInputV1 &other_input) const { return m_input_image < other_input.m_input_image; }
};

////
// SpPartialTxV1: everything needed for a tx except input membership proofs
///
struct SpPartialTxV1 final
{
    /// legacy tx input images  (spent legacy enotes) (SORTED)
    std::vector<LegacyEnoteImageV2> m_legacy_input_images;
    /// seraphis tx input images  (spent seraphis enotes) (SORTED)
    std::vector<SpEnoteImageV1> m_sp_input_images;
    /// tx outputs (new enotes) (SORTED)
    std::vector<SpEnoteV1> m_outputs;
    /// balance proof (balance proof and range proofs)
    SpBalanceProofV1 m_balance_proof;
    /// legacy ring signatures: membership/ownership/unspentness for each legacy input (ALIGNED TO LEGACY INPUTS)
    std::vector<LegacyRingSignatureV3> m_legacy_ring_signatures;
    /// composition proofs: ownership/unspentness for each seraphis input (ALIGNED TO SERAPHIS INPUTS)
    std::vector<SpImageProofV1> m_sp_image_proofs;
    /// supplemental data for tx
    SpTxSupplementV1 m_tx_supplement;
    /// tx fee (discretized representation)
    DiscretizedFee m_tx_fee;

    /// ring members for each legacy input; for validating ring signatures stored here (ALIGNED TO LEGACY INPUTS)
    std::vector<rct::ctkeyV> m_legacy_ring_signature_rings;

    /// seraphis input enotes; for creating seraphis input membership proofs (ALIGNED TO SERAPHIS INPUTS)
    std::vector<SpEnote> m_sp_input_enotes;
    /// seraphis image masks; for creating seraphis input membership proofs (ALIGNED TO SERAPHIS INPUTS)
    std::vector<crypto::secret_key> m_sp_address_masks;
    std::vector<crypto::secret_key> m_sp_commitment_masks;
};

} //namespace sp

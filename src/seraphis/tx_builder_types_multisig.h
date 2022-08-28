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

// Seraphis transaction-builder helper types (multisig).


#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "jamtis_payment_proposal.h"
#include "multisig/multisig_signer_set_filter.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "sp_composition_proof.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"
#include "tx_extra.h"

//third party headers

//standard headers
#include <unordered_map>

//forward declarations


namespace sp
{

////
// SpMultisigPublicInputProposalV1
// - propose a tx input to be signed with multisig (for sending to other multisig participants)
///
struct SpMultisigPublicInputProposalV1 final
{
    /// enote to spend
    SpEnoteV1 m_enote;
    /// the enote's ephemeral pubkey
    crypto::x25519_pubkey m_enote_ephemeral_pubkey;
    /// the enote's input context
    rct::key m_input_context;

    /// t_k
    crypto::secret_key m_address_mask;
    /// t_c
    crypto::secret_key m_commitment_mask;

    /**
    * brief: get_squash_prefix - get this input's enote's squash prefix
    * outparam: squash_prefix_out - H_n(Ko, C)
    */
    void get_squash_prefix(crypto::secret_key &squash_prefix_out) const;

    /**
    * brief: get_input_proposal_v1 - convert this input to a plain input proposal (throws on failure to convert)
    * param: wallet_spend_pubkey -
    * param: k_view_balance -
    * outparam: input_proposal_out -
    */
    void get_input_proposal_v1(const rct::key &wallet_spend_pubkey,
        const crypto::secret_key &k_view_balance,
        SpInputProposalV1 &input_proposal_out) const;
};

////
// SpMultisigTxProposalV1
// - propose to fund a set of outputs with multisig inputs
// - total input amount can be less than total output amount (additional inputs should be provided from elsewhere)
///
struct SpMultisigTxProposalV1 final
{
    /// normal tx outputs
    std::vector<jamtis::JamtisPaymentProposalV1> m_normal_payment_proposals;
    /// self-send tx outputs
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> m_selfsend_payment_proposals;
    /// miscellaneous memo elements to add to the tx memo
    TxExtra m_partial_memo;
    /// proposed transaction fee
    DiscretizedFee m_tx_fee;
    /// tx inputs to sign with multisig
    std::vector<SpMultisigPublicInputProposalV1> m_input_proposals;
    /// composition proof proposals for each input proposal
    std::vector<SpCompositionProofMultisigProposal> m_input_proof_proposals;
    /// all multisig signers who should participate in signing this proposal
    /// - the set may be larger than 'threshold', in which case every permutation of 'threshold' signers will attempt to sign
    multisig::signer_set_filter m_aggregate_signer_set_filter;

    /// encoding of intended tx version
    std::string m_version_string;

    /// convert to plain tx proposal
    void get_v1_tx_proposal_v1(const rct::key &wallet_spend_pubkey,
        const crypto::secret_key &k_view_balance,
        SpTxProposalV1 &tx_proposal_out) const;

    /// get the tx proposal prefix that will be signed by input composition proofs
    void get_proposal_prefix_v1(const rct::key &wallet_spend_pubkey,
        const crypto::secret_key &k_view_balance,
        rct::key &proposal_prefix_out) const;
};

////
// SpMultisigInputInitV1
// - initialize seraphis composition proofs for a set of enote images
// - each enote image has proof nonces for every set of multisig signers that includes the signer
//   - the vectors of proof nonces map 1:1 with the signer sets that include the local signer that can be extracted
//     from the aggregate filter
///
struct SpMultisigInputInitSetV1 final
{
    /// id of signer who made this input initializer set
    crypto::public_key m_signer_id;
    /// proposal prefix (represents the set of destinations and memos; will be signed by the image proofs)
    rct::key m_proposal_prefix;
    /// all multisig signers who should participate in attempting to make these composition proofs
    multisig::signer_set_filter m_aggregate_signer_set_filter;

    // map [masked address : {alpha_{ki,1,e}*U, alpha_{ki,2,e}*U}]
    // - key: masked addresses for enote images to sign
    // - value: signature nonce pubkeys for each signer set that includes the specified signer id (i.e. each tx attempt)
    //   - WARNING: ordering is dependent on the signer set filter permutation generator
    std::unordered_map<rct::key, std::vector<SpMultisigPubNonces>> m_input_inits;

    /// get nonces at a [masked address : nonce index] location (return false if the location doesn't exist)
    bool try_get_nonces(const rct::key &masked_address,
        const std::size_t nonces_index,
        SpMultisigPubNonces &nonces_out) const;
};

////
// SpMultisigInputPartialSigSetV1
// - set of partially signed inputs; combine partial signatures to complete the image proof for a partial input
///
struct SpMultisigInputPartialSigSetV1 final
{
    /// id of signer who made these partial signatures
    crypto::public_key m_signer_id;
    /// proposal prefix (represents the set of destinations and memos; signed by these composition proofs)
    rct::key m_proposal_prefix;
    /// set of multisig signers these partial signatures correspond to
    multisig::signer_set_filter m_signer_set_filter;

    // partial composition proof signatures for the masked addresses in a set of enote images
    std::vector<SpCompositionProofMultisigPartial> m_partial_signatures;
};

} //namespace sp

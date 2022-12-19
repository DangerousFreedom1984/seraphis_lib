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

// A 'payment proposal' is a proposal to make an enote sending funds to a Jamtis address.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "jamtis_destination.h"
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"
#include "tx_extra.h"

//third party headers

//standard headers

//forward declarations
namespace sp
{
    struct SpCoinbaseOutputProposalV1;
    struct SpOutputProposalV1;
}

namespace sp
{
namespace jamtis
{

////
// JamtisPaymentProposalV1
// - for creating an output proposal to send an amount to someone
///
struct JamtisPaymentProposalV1 final
{
    /// user address
    JamtisDestinationV1 m_destination;
    /// b
    rct::xmr_amount m_amount;

    /// enote ephemeral privkey: xr
    crypto::x25519_secret_key m_enote_ephemeral_privkey;

    /// memo elements to add to the tx memo
    TxExtra m_partial_memo;
};

////
// JamtisPaymentProposalSelfSendV1
// - for creating an output proposal to send an amount to the tx author
///
struct JamtisPaymentProposalSelfSendV1 final
{
    /// user address
    JamtisDestinationV1 m_destination;
    /// b
    rct::xmr_amount m_amount;

    /// self-send type
    JamtisSelfSendType m_type;
    /// enote ephemeral privkey: xr
    crypto::x25519_secret_key m_enote_ephemeral_privkey;

    /// memo elements to add to the tx memo
    TxExtra m_partial_memo;
};

/**
* brief: get_enote_ephemeral_pubkey - get the proposal's enote ephemeral pubkey xK_e
* param: proposal -
* outparam: enote_ephemeral_pubkey_out -
*/
void get_enote_ephemeral_pubkey(const JamtisPaymentProposalV1 &proposal,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out);
/**
* brief: get_enote_ephemeral_pubkey - get the proposal's enote ephemeral pubkey xK_e
* outparam: enote_ephemeral_pubkey_out -
*/
void get_enote_ephemeral_pubkey(const JamtisPaymentProposalSelfSendV1 &proposal,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out);
/**
* brief: get_coinbase_output_proposal_v1 - convert the jamtis proposal to a coinbase output proposal
* param: proposal -
* param: block_height - height of the coinbase tx's block
* outparam: output_proposal_out -
*/
void get_coinbase_output_proposal_v1(const JamtisPaymentProposalV1 &proposal,
    const std::uint64_t block_height,
    SpCoinbaseOutputProposalV1 &output_proposal_out);
/**
* brief: get_output_proposal_v1 - convert the jamtis proposal to an output proposal
* param: proposal -
* param: input_context -
* outparam: output_proposal_out -
*/
void get_output_proposal_v1(const JamtisPaymentProposalV1 &proposal,
    const rct::key &input_context,
    SpOutputProposalV1 &output_proposal_out);
/**
* brief: get_output_proposal_v1 - convert the jamtis selfsend proposal to a concrete output proposal
* param: proposal -
* param: k_view_balance -
* param: input_context -
* outparam: output_proposal_out -
*/
void get_output_proposal_v1(const JamtisPaymentProposalSelfSendV1 &proposal,
    const crypto::secret_key &k_view_balance,
    const rct::key &input_context,
    SpOutputProposalV1 &output_proposal_out);
/**
* brief: check_jamtis_payment_proposal_selfsend_semantics_v1 - validate semantics of a self-send payment proposal
* param: output_proposal -
* param: input_context -
* param: spend_pubkey -
* param: k_view_balance -
* outparam: type_out -
* return: true if it's a self-send proposal
*/
void check_jamtis_payment_proposal_selfsend_semantics_v1(const JamtisPaymentProposalSelfSendV1 &selfsend_payment_proposal,
    const rct::key &input_context,
    const rct::key &spend_pubkey,
    const crypto::secret_key &k_view_balance);
/**
* brief: gen_jamtis_payment_proposal_v1 - generate a random proposal
* param: amount -
* param: num_random_memo_elements -
* return: a random proposal
*/
JamtisPaymentProposalV1 gen_jamtis_payment_proposal_v1(const rct::xmr_amount amount,
    const std::size_t num_random_memo_elements);
/**
* brief: gen_jamtis_selfsend_payment_proposal_v1 - generate a random selfsend proposal (with specified parameters)
* param: amount -
* param: type -
* param: num_random_memo_elements
* return: a random proposal
*/
JamtisPaymentProposalSelfSendV1 gen_jamtis_selfsend_payment_proposal_v1(const rct::xmr_amount amount,
    const JamtisSelfSendType type,
    const std::size_t num_random_memo_elements);

} //namespace jamtis
} //namespace sp

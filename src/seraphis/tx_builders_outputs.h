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

// Seraphis tx-builder/component-builder implementations

#pragma once

//local headers
#include "crypto/crypto.h"
#include "jamtis_destination.h"
#include "ringct/rctTypes.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <string>
#include <vector>

//forward declarations


namespace sp
{

/**
* brief: check_v1_output_proposal_set_semantics_v1 - check semantics of a set of output proposals
*   - if 2 proposals, should be 1 unique enote ephemeral pubkey
*   - if >2 proposals, should be 1 unique enote ephemeral pubkey per output
*   - proposals should be sorted
*   - proposals should have unique onetime addresses
* param - output_proposals -
*/
void check_v1_output_proposal_set_semantics_v1(const std::vector<SpOutputProposalV1> &output_proposals);
/**
* brief: check_v1_tx_supplement_semantics_v1 - check semantics of a tx supplement
*   - if num_outputs == 2, should be 1 enote ephemeral pubkey
*   - if num_outputs > 2, should be 'num_outputs' enote ephemeral pubkeys
*   - all enote ephemeral pubkeys should be unique
* param - tx_supplement -
* param - num_outputs -
*/
void check_v1_tx_supplement_semantics_v1(const SpTxSupplementV1 &tx_supplement, const std::size_t num_outputs);
/**
* brief: make_v1_outputs_v1 - make v1 tx outputs
* param: destinations -
* outparam: outputs_out -
* outparam: output_amounts_out -
* outparam: output_amount_commitment_blinding_factors_out -
* outparam: output_enote_ephemeral_pubkeys_out -
*/
void make_v1_outputs_v1(const std::vector<SpOutputProposalV1> &output_proposals,
    std::vector<SpEnoteV1> &outputs_out,
    std::vector<rct::xmr_amount> &output_amounts_out,
    std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors_out,
    std::vector<rct::key> &output_enote_ephemeral_pubkeys_out);
/**
* brief: finalize_v1_output_proposal_set_v1 - finalize a set of output proposals (new proposals are appended)
*   - add a change output if necessary
*   - add a dummy output if appropriate
* param: total_input_amount -
* param: transaction_fee -
* param: change_destination -
* param: wallet_spend_pubkey -
* param: k_view_balance -
* inoutparam: output_proposals_inout -
*/
void finalize_v1_output_proposal_set_v1(const boost::multiprecision::uint128_t &total_input_amount,
    const rct::xmr_amount transaction_fee,
    const jamtis::JamtisDestinationV1 &change_destination,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    std::vector<SpOutputProposalV1> &output_proposals_inout);
/**
* brief: make_v1_tx_proposal_v1 - make v1 tx proposal (set of outputs that can be incorporated in a full tx)
* param: output_proposals -
* param: additional_memo_elements -
* outparam: proposal_out --
*/
void make_v1_tx_proposal_v1(std::vector<SpOutputProposalV1> output_proposals,
    std::vector<ExtraFieldElement> additional_memo_elements,
    SpTxProposalV1 &proposal_out);
/**
* brief: gen_mock_sp_output_proposals_v1 - create random output proposals
* param: out_amounts -
* param: num_random_memo_elements -
* return: set of generated output proposals
*/
std::vector<SpOutputProposalV1> gen_mock_sp_output_proposals_v1(const std::vector<rct::xmr_amount> &out_amounts,
    const std::size_t num_random_memo_elements);

} //namespace sp

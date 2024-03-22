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

#pragma once

//local headers
#include "seraphis_mocks/mock_ledger_context.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_core/jamtis_payment_proposal.h"
#include "seraphis_core/tx_extra.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_main/scan_machine_types.h"
#include "seraphis_main/tx_builder_types.h"
#include "seraphis_main/tx_fee_calculator.h"
#include "seraphis_main/tx_input_selection.h"
#include "seraphis_main/txtype_squashed_v1.h"

#include "seraphis_wallet/jamtis_keys.h"
//third party headers

//standard headers
#include <tuple>
#include <vector>

//forward declarations


namespace sp
{

/// make a payment proposal
void convert_outlay_to_payment_proposal(const rct::xmr_amount outlay_amount,
    const TxExtra &partial_memo_for_destination,
    const jamtis::JamtisDestinationV1 &destination,
    const JamtisAddressVersion address_version,
    const JamtisAddressNetwork address_network,
    jamtis::JamtisPaymentProposalV1 &payment_proposal_out);
/// send funds as coinbase enotes
void send_sp_coinbase_amounts_to_user(const std::vector<rct::xmr_amount> &coinbase_amounts,
    const jamtis::JamtisDestinationV1 &user_address,
    const JamtisAddressVersion address_version,
    const JamtisAddressNetwork address_network,
    mocks::MockLedgerContext &ledger_context_inout);
/// create a seraphis transaction
void construct_tx_for_mock_ledger_v1(const jamtis::LegacyKeys &local_user_legacy_keys,
    const jamtis::JamtisKeys &local_user_sp_keys,
    const InputSelectorV1 &local_user_input_selector,
    const FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const std::vector<std::tuple<rct::xmr_amount, TxExtra, jamtis::JamtisDestinationV1, JamtisAddressVersion, JamtisAddressNetwork>> &outlays,
    const std::size_t legacy_ring_size,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    const mocks::MockLedgerContext &ledger_context,
    SpTxSquashedV1 &tx_out,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> &selfsend_payments_out,
    std::vector<jamtis::JamtisPaymentProposalV1> &normal_payments_out);
/// create transactions and submit them to a mock ledger
void refresh_user_enote_store(const jamtis::JamtisKeys &user_keys,
    const scanning::ScanMachineConfig &refresh_config,
    const mocks::MockLedgerContext &ledger_context,
    SpEnoteStore &user_enote_store_inout);

} //namespace sp

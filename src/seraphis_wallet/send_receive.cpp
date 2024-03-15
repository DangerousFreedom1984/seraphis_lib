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

//paired header
#include "send_receive.h"

//local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "seraphis_mocks/enote_finding_context_mocks.h"
#include "misc_log_ex.h"
#include "seraphis_mocks/mock_ledger_context.h"
#include "seraphis_mocks/mock_tx_builders_inputs.h"
#include "seraphis_mocks/mock_tx_builders_legacy_inputs.h"
#include "ringct/rctTypes.h"
#include "seraphis_mocks/scan_chunk_consumer_mocks.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_impl/scan_context_simple.h"
#include "seraphis_impl/scan_process_basic.h"
#include "seraphis_impl/tx_builder_utils.h"
#include "seraphis_main/contextual_enote_record_utils.h"
#include "seraphis_main/scan_machine_types.h"
#include "seraphis_main/tx_builder_types.h"
#include "seraphis_main/tx_builders_mixed.h"
#include "seraphis_main/txtype_coinbase_v1.h"
#include "seraphis_main/txtype_squashed_v1.h"
#include "seraphis_mocks/mock_ledger_context.h"
#include "seraphis_mocks/tx_validation_context_mock.h"

#include "seraphis_wallet/jamtis_keys.h"

//third party headers

//standard headers
#include <tuple>
#include <unordered_map>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_mocks"

using namespace sp;

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void convert_outlay_to_payment_proposal(const rct::xmr_amount outlay_amount,
    const jamtis::JamtisDestinationV1 &destination,
    const TxExtra &partial_memo_for_destination,
    jamtis::JamtisPaymentProposalV1 &payment_proposal_out)
{
    payment_proposal_out = jamtis::JamtisPaymentProposalV1{
            .destination             = destination,
            .amount                  = outlay_amount,
            .enote_ephemeral_privkey = crypto::x25519_secret_key_gen(),
            .partial_memo            = partial_memo_for_destination
        };
}
//-------------------------------------------------------------------------------------------------------------------
void send_sp_coinbase_amounts_to_user(const std::vector<rct::xmr_amount> &coinbase_amounts,
    const jamtis::JamtisDestinationV1 &user_address,
    mocks::MockLedgerContext &ledger_context_inout)
{
    // 1. prepare payment proposals
    std::vector<jamtis::JamtisPaymentProposalV1> payment_proposals;
    payment_proposals.reserve(coinbase_amounts.size());
    rct::xmr_amount block_reward{0};

    for (const rct::xmr_amount coinbase_amount : coinbase_amounts)
    {
        // a. make payment proposal
        convert_outlay_to_payment_proposal(coinbase_amount,
        user_address,
        TxExtra{},
        tools::add_element(payment_proposals));

        // b. accumulate the block reward
        block_reward += coinbase_amount;
    }

    // 2. make a coinbase tx
    SpTxCoinbaseV1 coinbase_tx;
    make_seraphis_tx_coinbase_v1(SpTxCoinbaseV1::SemanticRulesVersion::MOCK,
        ledger_context_inout.chain_height() + 1,
        block_reward,
        std::move(payment_proposals),
        {},
        coinbase_tx);

    // 3. validate the coinbase tx
    const mocks::TxValidationContextMock tx_validation_context{ledger_context_inout};
    CHECK_AND_ASSERT_THROW_MES(validate_tx(coinbase_tx, tx_validation_context),
        "send sp coinbase amounts to user (mock): failed to validate coinbase tx.");

    // 4. commit coinbase tx as new block
    ledger_context_inout.commit_unconfirmed_txs_v1(coinbase_tx);
}
//-------------------------------------------------------------------------------------------------------------------
void construct_tx_for_mock_ledger_v1(const jamtis::LegacyKeys &local_user_legacy_keys,
    const jamtis::JamtisKeys &local_user_sp_keys,
    const InputSelectorV1 &local_user_input_selector,
    const FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const std::vector<std::tuple<rct::xmr_amount, jamtis::JamtisDestinationV1, TxExtra>> &outlays,
    const std::size_t legacy_ring_size,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const SpBinnedReferenceSetConfigV1 &bin_config,
    const mocks::MockLedgerContext &ledger_context,
    SpTxSquashedV1 &tx_out)
{
    /// build transaction

    // 1. prepare dummy and change addresses
    jamtis::JamtisDestinationV1 change_address;
    jamtis::JamtisDestinationV1 dummy_address;
    jamtis::make_destination_random(local_user_sp_keys, change_address);
    jamtis::make_destination_random(local_user_sp_keys, dummy_address);

    // 2. convert outlays to normal payment proposals
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals;
    normal_payment_proposals.reserve(outlays.size());

    for (const auto &outlay : outlays)
    {
        convert_outlay_to_payment_proposal(std::get<rct::xmr_amount>(outlay),
            std::get<jamtis::JamtisDestinationV1>(outlay),
            std::get<TxExtra>(outlay),
            tools::add_element(normal_payment_proposals));
    }

    // 3. prepare inputs and finalize outputs
    std::vector<LegacyContextualEnoteRecordV1> legacy_contextual_inputs;
    std::vector<SpContextualEnoteRecordV1> sp_contextual_inputs;
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals;  //note: no user-defined selfsends
    DiscretizedFee discretized_transaction_fee;
    CHECK_AND_ASSERT_THROW_MES(try_prepare_inputs_and_outputs_for_transfer_v1(change_address,
            dummy_address,
            local_user_input_selector,
            tx_fee_calculator,
            fee_per_tx_weight,
            max_inputs,
            std::move(normal_payment_proposals),
            std::move(selfsend_payment_proposals),
            local_user_sp_keys.k_vb,
            legacy_contextual_inputs,
            sp_contextual_inputs,
            normal_payment_proposals,
            selfsend_payment_proposals,
            discretized_transaction_fee),
        "construct tx for mock ledger (v1): preparing inputs and outputs failed.");

    // 4. tx proposal
    SpTxProposalV1 tx_proposal;
    make_v1_tx_proposal_v1(legacy_contextual_inputs,
        sp_contextual_inputs,
        std::move(normal_payment_proposals),
        std::move(selfsend_payment_proposals),
        discretized_transaction_fee,
        TxExtra{},
        tx_proposal);

    // 5. tx proposal prefix
    const tx_version_t tx_version{tx_version_from(SpTxSquashedV1::SemanticRulesVersion::MOCK)};

    rct::key tx_proposal_prefix;
    get_tx_proposal_prefix_v1(tx_proposal, tx_version, local_user_sp_keys.k_vb, tx_proposal_prefix);

    // 6. get ledger mappings for the input membership proofs
    // note: do this after making the tx proposal to demo that inputs don't have to be on-chain when proposing a tx
    std::unordered_map<crypto::key_image, std::uint64_t> legacy_input_ledger_mappings;
    std::unordered_map<crypto::key_image, std::uint64_t> sp_input_ledger_mappings;
    try_get_membership_proof_real_reference_mappings(legacy_contextual_inputs, legacy_input_ledger_mappings);
    try_get_membership_proof_real_reference_mappings(sp_contextual_inputs, sp_input_ledger_mappings);

    // 7. prepare for legacy ring signatures
    std::vector<LegacyRingSignaturePrepV1> legacy_ring_signature_preps;
    make_mock_legacy_ring_signature_preps_for_inputs_v1(tx_proposal_prefix,
        legacy_input_ledger_mappings,
        tx_proposal.legacy_input_proposals,
        legacy_ring_size,
        ledger_context,
        legacy_ring_signature_preps);

    // 8. prepare for membership proofs
    std::vector<SpMembershipProofPrepV1> sp_membership_proof_preps;
    make_mock_sp_membership_proof_preps_for_inputs_v1(sp_input_ledger_mappings,
        tx_proposal.sp_input_proposals,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context,
        sp_membership_proof_preps);

    // 9. complete tx
    make_seraphis_tx_squashed_v1(SpTxSquashedV1::SemanticRulesVersion::MOCK,
        tx_proposal,
        std::move(legacy_ring_signature_preps),
        std::move(sp_membership_proof_preps),
        local_user_legacy_keys.k_s,
        local_user_sp_keys.k_m,
        local_user_sp_keys.k_vb,
        hw::get_device("default"),
        tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
void refresh_user_enote_store(const jamtis::JamtisKeys &user_keys,
    const scanning::ScanMachineConfig &refresh_config,
    const mocks::MockLedgerContext &ledger_context,
    SpEnoteStore &user_enote_store_inout)
{
    const mocks::EnoteFindingContextUnconfirmedMockSp enote_finding_context_unconfirmed{ledger_context, user_keys.xk_fr};
    const mocks::EnoteFindingContextLedgerMockSp enote_finding_context_ledger{ledger_context, user_keys.xk_fr};
    scanning::ScanContextNonLedgerSimple scan_context_unconfirmed{enote_finding_context_unconfirmed};
    scanning::ScanContextLedgerSimple scan_context_ledger{enote_finding_context_ledger};
    mocks::ChunkConsumerMockSp chunk_consumer{user_keys.K_1_base, user_keys.k_vb, user_enote_store_inout};

    sp::refresh_enote_store(refresh_config,
        scan_context_unconfirmed,
        scan_context_ledger,
        chunk_consumer);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp

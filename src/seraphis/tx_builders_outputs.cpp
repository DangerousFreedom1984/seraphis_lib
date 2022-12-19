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
#include "tx_builders_outputs.h"

//local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "cryptonote_config.h"
#include "jamtis_core_utils.h"
#include "jamtis_destination.h"
#include "jamtis_payment_proposal.h"
#include "jamtis_support_types.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "tx_builder_types.h"
#include "tx_component_types.h"
#include "tx_extra.h"

//third party headers
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <algorithm>
#include <string>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
// check that all enote ephemeral pubkeys in an output proposal set are unique
//-------------------------------------------------------------------------------------------------------------------
static bool ephemeral_pubkeys_are_unique(const std::vector<SpCoinbaseOutputProposalV1> &output_proposals)
{
    std::unordered_set<crypto::x25519_pubkey> enote_ephemeral_pubkeys;

    for (const SpCoinbaseOutputProposalV1 &output_proposal : output_proposals)
        enote_ephemeral_pubkeys.insert(output_proposal.m_enote_ephemeral_pubkey);

    return enote_ephemeral_pubkeys.size() == output_proposals.size();
}
//-------------------------------------------------------------------------------------------------------------------
// check that all enote ephemeral pubkeys in an output proposal set are unique
//-------------------------------------------------------------------------------------------------------------------
static bool ephemeral_pubkeys_are_unique(const std::vector<SpOutputProposalV1> &output_proposals)
{
    std::unordered_set<crypto::x25519_pubkey> enote_ephemeral_pubkeys;

    for (const SpOutputProposalV1 &output_proposal : output_proposals)
        enote_ephemeral_pubkeys.insert(output_proposal.m_enote_ephemeral_pubkey);

    return enote_ephemeral_pubkeys.size() == output_proposals.size();
}
//-------------------------------------------------------------------------------------------------------------------
// check that all enote ephemeral pubkeys in an output proposal set are unique
//-------------------------------------------------------------------------------------------------------------------
static bool ephemeral_pubkeys_are_unique(const std::vector<jamtis::JamtisPaymentProposalV1> &normal_payment_proposals,
    const std::vector<jamtis::JamtisPaymentProposalSelfSendV1> &selfsend_payment_proposals)
{
    // record all as 8*K_e to remove torsion elements if they exist
    std::unordered_set<crypto::x25519_pubkey> enote_ephemeral_pubkeys;
    crypto::x25519_pubkey temp_enote_ephemeral_pubkey;

    for (const jamtis::JamtisPaymentProposalV1 &normal_proposal : normal_payment_proposals)
    {
        normal_proposal.get_enote_ephemeral_pubkey(temp_enote_ephemeral_pubkey);
        enote_ephemeral_pubkeys.insert(temp_enote_ephemeral_pubkey);
    }

    for (const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_proposal : selfsend_payment_proposals)
    {
        selfsend_proposal.get_enote_ephemeral_pubkey(temp_enote_ephemeral_pubkey);
        enote_ephemeral_pubkeys.insert(temp_enote_ephemeral_pubkey);
    }

    return enote_ephemeral_pubkeys.size() == normal_payment_proposals.size() + selfsend_payment_proposals.size();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_additional_output_normal_dummy_v1(jamtis::JamtisPaymentProposalV1 &dummy_proposal_out)
{
    // make random payment proposal for a 'normal' dummy output
    dummy_proposal_out.m_destination = jamtis::gen_jamtis_destination_v1();
    dummy_proposal_out.m_amount = 0;
    dummy_proposal_out.m_enote_ephemeral_privkey = crypto::x25519_secret_key_gen();
    dummy_proposal_out.m_partial_memo = TxExtra{};
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_additional_output_special_dummy_v1(const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    jamtis::JamtisPaymentProposalV1 &dummy_proposal_out)
{
    // make random payment proposal for a 'special' dummy output
    dummy_proposal_out.m_destination = jamtis::gen_jamtis_destination_v1();
    crypto::x25519_invmul_key({crypto::x25519_eight()},
        enote_ephemeral_pubkey,
        dummy_proposal_out.m_destination.m_addr_K3);  //(1/8) * xK_e_other
    dummy_proposal_out.m_amount = 0;
    dummy_proposal_out.m_enote_ephemeral_privkey = crypto::x25519_eight();  //r = 8 (can't do r = 1 for x25519)
    dummy_proposal_out.m_partial_memo = TxExtra{};
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_additional_output_normal_self_send_v1(const jamtis::JamtisSelfSendType self_send_type,
    const jamtis::JamtisDestinationV1 &destination,
    const rct::xmr_amount amount,
    jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_proposal_out)
{
    // build payment proposal for a 'normal' self-send
    selfsend_proposal_out.m_destination = destination;
    selfsend_proposal_out.m_amount = amount;
    selfsend_proposal_out.m_type = self_send_type;
    selfsend_proposal_out.m_enote_ephemeral_privkey = crypto::x25519_secret_key_gen();
    selfsend_proposal_out.m_partial_memo = TxExtra{};
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_additional_output_special_self_send_v1(const jamtis::JamtisSelfSendType self_send_type,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const jamtis::JamtisDestinationV1 &destination,
    const crypto::secret_key &k_view_balance,
    const rct::xmr_amount amount,
    jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_proposal_out)
{
    // build payment proposal for a 'special' self-send that uses a shared enote ephemeral pubkey
    crypto::x25519_secret_key findreceived_xkey;
    jamtis::make_jamtis_findreceived_key(k_view_balance, findreceived_xkey);

    crypto::x25519_pubkey special_addr_K2;
    crypto::x25519_scmul_key(findreceived_xkey, enote_ephemeral_pubkey, special_addr_K2);  //xk_fr * xK_e_other

    selfsend_proposal_out.m_destination = destination;
    crypto::x25519_invmul_key({crypto::x25519_eight()},
        special_addr_K2,
        selfsend_proposal_out.m_destination.m_addr_K2);  //(1/8) * xk_fr * xK_e_other
    crypto::x25519_invmul_key({crypto::x25519_eight()},
        enote_ephemeral_pubkey,
        selfsend_proposal_out.m_destination.m_addr_K3);  //(1/8) * xK_e_other
    selfsend_proposal_out.m_amount = amount;
    selfsend_proposal_out.m_type = self_send_type;
    selfsend_proposal_out.m_enote_ephemeral_privkey = crypto::x25519_eight();  //r = 8 (can't do r = 1 for x25519)
    selfsend_proposal_out.m_partial_memo = TxExtra{};
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_additional_output_dummy_v1(const OutputProposalSetExtraTypesV1 additional_output_type,
    const crypto::x25519_pubkey &first_enote_ephemeral_pubkey,
    jamtis::JamtisPaymentProposalV1 &normal_proposal_out)
{
    // choose which output type to make, and make it
    if (additional_output_type == OutputProposalSetExtraTypesV1::NORMAL_DUMMY)
    {
        // normal dummy
        // - 0 amount
        make_additional_output_normal_dummy_v1(normal_proposal_out);
    }
    else if (additional_output_type == OutputProposalSetExtraTypesV1::SPECIAL_DUMMY)
    {
        // special dummy
        // - 0 amount
        // - shared enote ephemeral pubkey
        make_additional_output_special_dummy_v1(first_enote_ephemeral_pubkey, normal_proposal_out);
    }
    else
    {
        CHECK_AND_ASSERT_THROW_MES(false, "Unknown output proposal set extra type (dummy).");
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_additional_output_selfsend_v1(const OutputProposalSetExtraTypesV1 additional_output_type,
    const crypto::x25519_pubkey &first_enote_ephemeral_pubkey,
    const jamtis::JamtisDestinationV1 &change_destination,
    const jamtis::JamtisDestinationV1 &dummy_destination,
    const crypto::secret_key &k_view_balance,
    const rct::xmr_amount change_amount,
    jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_proposal_out)
{
    // choose which output type to make, and make it
    if (additional_output_type == OutputProposalSetExtraTypesV1::NORMAL_SELF_SEND_DUMMY)
    {
        // normal self-send dummy
        // - 0 amount
        make_additional_output_normal_self_send_v1(jamtis::JamtisSelfSendType::DUMMY,
            dummy_destination,
            0,
            selfsend_proposal_out);
    }
    else if (additional_output_type == OutputProposalSetExtraTypesV1::NORMAL_CHANGE)
    {
        // normal change
        // - 'change' amount
        make_additional_output_normal_self_send_v1(jamtis::JamtisSelfSendType::CHANGE,
            change_destination,
            change_amount,
            selfsend_proposal_out);
    }
    else if (additional_output_type == OutputProposalSetExtraTypesV1::SPECIAL_SELF_SEND_DUMMY)
    {
        // special self-send dummy
        // - 0 amount
        // - shared enote ephemeral pubkey
        make_additional_output_special_self_send_v1(jamtis::JamtisSelfSendType::DUMMY,
            first_enote_ephemeral_pubkey,
            dummy_destination,
            k_view_balance,
            0,
            selfsend_proposal_out);
        
    }
    else if (additional_output_type == OutputProposalSetExtraTypesV1::SPECIAL_CHANGE)
    {
        // special change
        // - 'change' amount
        // - shared enote ephemeral pubkey
        make_additional_output_special_self_send_v1(jamtis::JamtisSelfSendType::CHANGE,
            first_enote_ephemeral_pubkey,
            change_destination,
            k_view_balance,
            change_amount,
            selfsend_proposal_out);
    }
    else
    {
        CHECK_AND_ASSERT_THROW_MES(false, "Unknown output proposal set extra type (self-send).");
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void check_v1_coinbase_output_proposal_semantics_v1(const SpCoinbaseOutputProposalV1 &output_proposal)
{
    std::vector<ExtraFieldElement> additional_memo_elements;
    CHECK_AND_ASSERT_THROW_MES(try_get_extra_field_elements(output_proposal.m_partial_memo,
            additional_memo_elements),
        "coinbase output proposal semantics (v1): invalid partial memo.");
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_output_proposal_semantics_v1(const SpOutputProposalV1 &output_proposal)
{
    std::vector<ExtraFieldElement> additional_memo_elements;
    CHECK_AND_ASSERT_THROW_MES(try_get_extra_field_elements(output_proposal.m_partial_memo,
            additional_memo_elements),
        "output proposal semantics (v1): invalid partial memo.");
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_coinbase_output_proposal_set_semantics_v1(const std::vector<SpCoinbaseOutputProposalV1> &output_proposals)
{
    // individual output proposals should be internally valid
    for (const SpCoinbaseOutputProposalV1 &output_proposal : output_proposals)
        check_v1_coinbase_output_proposal_semantics_v1(output_proposal);

    // all enote ephemeral pubkeys should be unique
    CHECK_AND_ASSERT_THROW_MES(ephemeral_pubkeys_are_unique(output_proposals),
        "Semantics check coinbase output proposals v1: enote ephemeral pubkeys aren't all unique.");

    // proposals should be sorted and unique
    CHECK_AND_ASSERT_THROW_MES(tools::is_sorted_and_unique(output_proposals, compare_Ko),
        "Semantics check output proposals v1: output onetime addresses are not sorted and unique.");

    // proposal onetime addresses should be canonical (sanity check so our tx outputs don't have duplicate key images)
    for (const SpCoinbaseOutputProposalV1 &output_proposal : output_proposals)
    {
        CHECK_AND_ASSERT_THROW_MES(output_proposal.m_enote.m_core.onetime_address_is_canonical(),
            "Semantics check output proposals v1: an output onetime address is not in the prime subgroup.");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_output_proposal_set_semantics_v1(const std::vector<SpOutputProposalV1> &output_proposals)
{
    CHECK_AND_ASSERT_THROW_MES(output_proposals.size() >= 1, "Semantics check output proposals v1: insufficient outputs.");

    // individual output proposals should be internally valid
    for (const SpOutputProposalV1 &output_proposal : output_proposals)
        check_v1_output_proposal_semantics_v1(output_proposal);

    // if 2 proposals, must be a shared enote ephemeral pubkey
    if (output_proposals.size() == 2)
    {
        CHECK_AND_ASSERT_THROW_MES(output_proposals[0].m_enote_ephemeral_pubkey == 
                output_proposals[1].m_enote_ephemeral_pubkey,
            "Semantics check output proposals v1: there are 2 outputs but they don't share an enote ephemeral pubkey.");
    }

    // if >2 proposals, all enote ephemeral pubkeys should be unique
    if (output_proposals.size() > 2)
    {
        CHECK_AND_ASSERT_THROW_MES(ephemeral_pubkeys_are_unique(output_proposals),
            "Semantics check output proposals v1: there are >2 outputs but their enote ephemeral pubkeys aren't all "
            "unique.");
    }

    // proposals should be sorted and unique
    CHECK_AND_ASSERT_THROW_MES(tools::is_sorted_and_unique(output_proposals, compare_Ko),
        "Semantics check output proposals v1: output onetime addresses are not sorted and unique.");

    // proposal onetime addresses should be canonical (sanity check so our tx outputs don't have duplicate key images)
    for (const SpOutputProposalV1 &output_proposal : output_proposals)
    {
        CHECK_AND_ASSERT_THROW_MES(output_proposal.m_core.onetime_address_is_canonical(),
            "Semantics check output proposals v1: an output onetime address is not in the prime subgroup.");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_tx_supplement_semantics_v1(const SpTxSupplementV1 &tx_supplement,
    const std::size_t num_outputs,
    const bool ephemeral_pubkey_optimization)
{
    // there may be either 1 or 3+ enote pubkeys
    if (num_outputs <= 2 && ephemeral_pubkey_optimization)
    {
        CHECK_AND_ASSERT_THROW_MES(tx_supplement.m_output_enote_ephemeral_pubkeys.size() == 1,
            "Semantics check tx supplement v1: there must be 1 enote pubkey if there are 2 outputs and the ephemeral "
            "pubkey optimization is being used.");
    }
    else
    {
        CHECK_AND_ASSERT_THROW_MES(tx_supplement.m_output_enote_ephemeral_pubkeys.size() == num_outputs,
            "Semantics check tx supplement v1: there must be one enote pubkey for each output when there is no ephemeral "
            "pubkey optimization.");
    }

    // all enote pubkeys should be unique
    CHECK_AND_ASSERT_THROW_MES(keys_are_unique(tx_supplement.m_output_enote_ephemeral_pubkeys),
        "Semantics check tx supplement v1: enote pubkeys must be unique.");

    // enote ephemeral pubkeys should not be zero
    // note: these are easy checks to do, but in no way guarantee the enote ephemeral pubkeys are valid/usable
    for (const crypto::x25519_pubkey &enote_ephemeral_pubkey : tx_supplement.m_output_enote_ephemeral_pubkeys)
    {
        CHECK_AND_ASSERT_THROW_MES(!(enote_ephemeral_pubkey == crypto::x25519_pubkey{}),
            "Semantics check tx supplement v1: an enote ephemeral pubkey is zero.");
    }

    // the tx extra must be well-formed
    std::vector<ExtraFieldElement> extra_field_elements;

    CHECK_AND_ASSERT_THROW_MES(try_get_extra_field_elements(tx_supplement.m_tx_extra, extra_field_elements),
        "Semantics check tx supplement v1: could not extract extra field elements.");

    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(extra_field_elements.begin(), extra_field_elements.end()),
        "Semantics check tx supplement v1: extra field elements are not sorted.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_coinbase_outputs_v1(const std::vector<SpCoinbaseOutputProposalV1> &output_proposals,
    std::vector<SpCoinbaseEnoteV1> &outputs_out,
    std::vector<crypto::x25519_pubkey> &output_enote_ephemeral_pubkeys_out)
{
    // output proposal set should be valid
    check_v1_coinbase_output_proposal_set_semantics_v1(output_proposals);

    // extract tx output information from output proposals
    outputs_out.clear();
    outputs_out.reserve(output_proposals.size());
    output_enote_ephemeral_pubkeys_out.clear();
    output_enote_ephemeral_pubkeys_out.reserve(output_proposals.size());

    for (const SpCoinbaseOutputProposalV1 &output_proposal : output_proposals)
    {
        // convert to enote
        outputs_out.emplace_back(output_proposal.m_enote);

        // copy non-duplicate enote pubkeys to tx supplement (note: the semantics checker should prevent duplicates)
        if (std::find(output_enote_ephemeral_pubkeys_out.begin(),
                output_enote_ephemeral_pubkeys_out.end(),
                output_proposal.m_enote_ephemeral_pubkey) == output_enote_ephemeral_pubkeys_out.end())
            output_enote_ephemeral_pubkeys_out.emplace_back(output_proposal.m_enote_ephemeral_pubkey);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_outputs_v1(const std::vector<SpOutputProposalV1> &output_proposals,
    std::vector<SpEnoteV1> &outputs_out,
    std::vector<rct::xmr_amount> &output_amounts_out,
    std::vector<crypto::secret_key> &output_amount_commitment_blinding_factors_out,
    std::vector<crypto::x25519_pubkey> &output_enote_ephemeral_pubkeys_out)
{
    // output proposal set should be valid
    check_v1_output_proposal_set_semantics_v1(output_proposals);

    // extract tx output information from output proposals
    outputs_out.clear();
    outputs_out.reserve(output_proposals.size());
    output_amounts_out.clear();
    output_amounts_out.reserve(output_proposals.size());
    output_amount_commitment_blinding_factors_out.clear();
    output_amount_commitment_blinding_factors_out.reserve(output_proposals.size());
    output_enote_ephemeral_pubkeys_out.clear();
    output_enote_ephemeral_pubkeys_out.reserve(output_proposals.size());

    for (const SpOutputProposalV1 &output_proposal : output_proposals)
    {
        // sanity check
        // note: a blinding factor of 0 is allowed (but not recommended)
        CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(output_proposal.m_core.m_amount_blinding_factor)) == 0,
            "making v1 outputs: invalid amount blinding factor (non-canonical).");

        // convert to enote
        output_proposal.get_enote_v1(tools::add_element(outputs_out));

        // prepare for range proofs
        output_amounts_out.emplace_back(output_proposal.amount());
        output_amount_commitment_blinding_factors_out.emplace_back(output_proposal.m_core.m_amount_blinding_factor);

        // copy non-duplicate enote pubkeys to tx supplement
        if (std::find(output_enote_ephemeral_pubkeys_out.begin(),
                output_enote_ephemeral_pubkeys_out.end(),
                output_proposal.m_enote_ephemeral_pubkey) == output_enote_ephemeral_pubkeys_out.end())
            output_enote_ephemeral_pubkeys_out.emplace_back(output_proposal.m_enote_ephemeral_pubkey);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void finalize_tx_extra_v1(const TxExtra &partial_memo,
    const std::vector<SpCoinbaseOutputProposalV1> &output_proposals,
    TxExtra &tx_extra_out)
{
    // collect all memo elements
    std::vector<ExtraFieldElement> collected_memo_elements;
    accumulate_extra_field_elements(partial_memo, collected_memo_elements);

    for (const SpCoinbaseOutputProposalV1 &output_proposal : output_proposals)
        accumulate_extra_field_elements(output_proposal.m_partial_memo, collected_memo_elements);

    // finalize the extra field
    make_tx_extra(std::move(collected_memo_elements), tx_extra_out);
}
//-------------------------------------------------------------------------------------------------------------------
void finalize_tx_extra_v1(const TxExtra &partial_memo,
    const std::vector<SpOutputProposalV1> &output_proposals,
    TxExtra &tx_extra_out)
{
    // collect all memo elements
    std::vector<ExtraFieldElement> collected_memo_elements;
    accumulate_extra_field_elements(partial_memo, collected_memo_elements);

    for (const SpOutputProposalV1 &output_proposal : output_proposals)
        accumulate_extra_field_elements(output_proposal.m_partial_memo, collected_memo_elements);

    // finalize the extra field
    make_tx_extra(std::move(collected_memo_elements), tx_extra_out);
}
//-------------------------------------------------------------------------------------------------------------------
void get_additional_output_types_for_output_set_v1(const std::size_t num_outputs,
    const std::vector<jamtis::JamtisSelfSendType> &self_send_output_types,
    const bool output_ephemeral_pubkeys_are_unique,
    const rct::xmr_amount change_amount,
    std::vector<OutputProposalSetExtraTypesV1> &additional_outputs_out)
{
    // txs should have at least 1 non-change output
    CHECK_AND_ASSERT_THROW_MES(num_outputs > 0, "Finalize output proposals: 0 outputs specified. If you want to send "
        "money to yourself, use a self-spend enote type instead of forcing it via a change enote type.");

    // sanity check
    CHECK_AND_ASSERT_THROW_MES(self_send_output_types.size() <= num_outputs,
        "Finalize output proposals: there are more self send outputs than outputs (bug).");

    // add the extra output needed
    additional_outputs_out.clear();

    if (num_outputs == 1)
    {
        if (change_amount == 0)
        {
            if (self_send_output_types.size() == 1)
            {
                // txs need at least 2 outputs; we already have a self-send, so make a random special dummy output

                // add a special dummy output
                // - 0 amount
                // - make sure the final proposal set will have 1 unique enote ephemeral pubkey
                additional_outputs_out.emplace_back(OutputProposalSetExtraTypesV1::SPECIAL_DUMMY);
            }
            else //(no self-send)
            {
                // txs need at least 2 outputs, with at least 1 self-send enote type

                // add a special self-send dummy output
                // - 0 amount
                // - make sure the final proposal set will have 1 unique enote ephemeral pubkey
                additional_outputs_out.emplace_back(OutputProposalSetExtraTypesV1::SPECIAL_SELF_SEND_DUMMY);
            }
        }
        else if (/*change_amount > 0 &&*/
            self_send_output_types.size() == 1 &&
            self_send_output_types[0] == jamtis::JamtisSelfSendType::CHANGE)
        {
            // 2-out txs may not have 2 self-send type enotes of the same type from the same wallet, so since
            //   we already have a change output (for some dubious reason) we can't have a special change here
            // reason: the outputs in a 2-out tx with 2 same-type self-sends would have the same sender-receiver shared
            //         secret, which could cause problems (e.g. the outputs would have the same view tags, and could even
            //         have the same onetime address if the destinations of the two outputs are the same)

            // two change outputs doesn't make sense, so just ban it
            CHECK_AND_ASSERT_THROW_MES(false, "Finalize output proposals: there is 1 change-type output already "
                "specified, but the change amount is non-zero and a tx with just two change outputs is not allowed "
                "for privacy reasons. If you want to make a tx with just two change outputs, avoid calling this function "
                "(not recommended).");
        }
        else //(change_amount > 0 && single output is not a self-send change)
        {
            // if there is 1 non-change output and non-zero change, then make a special change enote that shares
            //   the other output's enote ephemeral pubkey

            // add a special change output
            // - 'change' amount
            // - make sure the final proposal set will have 1 unique enote ephemeral pubkey
            additional_outputs_out.emplace_back(OutputProposalSetExtraTypesV1::SPECIAL_CHANGE);
        }
    }
    else if (num_outputs == 2 && output_ephemeral_pubkeys_are_unique)
    {
        if (change_amount == 0)
        {
            // 2-out txs need 1 shared enote ephemeral pubkey; add a dummy output here since the outputs have different
            //   enote ephemeral pubkeys

            if (self_send_output_types.size() > 0)
            {
                // if we have at least 1 self-send already, we can just make a normal dummy output

                // add a normal dummy output
                // - 0 amount
                additional_outputs_out.emplace_back(OutputProposalSetExtraTypesV1::NORMAL_DUMMY);
            }
            else //(no self-sends)
            {
                // if there are no self-sends, then we need to add a dummy self-send

                // add a normal self-send dummy output
                // - 0 amount
                additional_outputs_out.emplace_back(OutputProposalSetExtraTypesV1::NORMAL_SELF_SEND_DUMMY);
            }
        }
        else //(change_amount > 0)
        {
            // 2 separate outputs + 1 change output = a simple 3-out tx

            // add a normal change output
            // - 'change' amount
            additional_outputs_out.emplace_back(OutputProposalSetExtraTypesV1::NORMAL_CHANGE);
        }
    }
    else if (num_outputs == 2 && !output_ephemeral_pubkeys_are_unique)
    {
        if (change_amount == 0)
        {
            if (self_send_output_types.size() == 2 &&
                self_send_output_types[0] == self_send_output_types[1])
            {
                CHECK_AND_ASSERT_THROW_MES(false, "Finalize output proposals: there are 2 self-send outputs with the "
                    "same type that share an enote ephemeral pubkey, but this can reduce user privacy. If you want to "
                    "send money to yourself, make independent self-spend types, or avoid calling this function (not "
                    "recommended).");
            }
            else if (self_send_output_types.size() > 0)
            {
                // do nothing: the proposal set is already 'final'
            }
            else //(no self-sends)
            {
                CHECK_AND_ASSERT_THROW_MES(false, "Finalize output proposals: there are 2 normal outputs that share "
                    "an enote ephemeral pubkey, but every normally-constructed tx needs at least one self-send output "
                    "(since the 2 outputs share an enote ephemeral pubkey, we can't add a dummy self-send). If you want "
                    "to make a 2-output tx with no self-sends, then avoid calling this function (not recommended without "
                    "good reason).");
            }
        }
        else //(change_amount > 0)
        {
            CHECK_AND_ASSERT_THROW_MES(false, "Finalize output proposals: there are 2 outputs that share "
                "an enote ephemeral pubkey, but a non-zero change amount. In >2-out txs, all enote ephemeral pubkeys "
                "should be unique, so adding a change output isn't feasible here. You need to make independent output "
                "proposals, or avoid calling this function (not recommended).");
        }
    }
    else //(output_proposals.size() > 2)
    {
        CHECK_AND_ASSERT_THROW_MES(output_ephemeral_pubkeys_are_unique,
            "Finalize output proposals: there are >2 outputs but their enote ephemeral pubkeys aren't all unique.");

        if (change_amount == 0)
        {
            if (self_send_output_types.size() > 0)
            {
                // do nothing: the proposal set is already 'final'
            }
            else //(no self-sends)
            {
                // every tx made by this function needs a self-send output, so make a dummy self-send here

                // add a normal self-send dummy output
                // - 0 amount
                additional_outputs_out.emplace_back(OutputProposalSetExtraTypesV1::NORMAL_SELF_SEND_DUMMY);
            }
        }
        else //(change_amount > 0)
        {
            // >2 separate outputs + 1 change output = a simple tx with 3+ outputs

            // add a normal change output
            // - 'change' amount
            additional_outputs_out.emplace_back(OutputProposalSetExtraTypesV1::NORMAL_CHANGE);
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void finalize_v1_output_proposal_set_v1(const boost::multiprecision::uint128_t &total_input_amount,
    const rct::xmr_amount transaction_fee,
    const jamtis::JamtisDestinationV1 &change_destination,
    const jamtis::JamtisDestinationV1 &dummy_destination,
    const crypto::secret_key &k_view_balance,
    std::vector<jamtis::JamtisPaymentProposalV1> &normal_payment_proposals_inout,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> &selfsend_payment_proposals_inout)
{
    // 1. get change amount
    boost::multiprecision::uint128_t output_sum{transaction_fee};

    for (const jamtis::JamtisPaymentProposalV1 &normal_proposal : normal_payment_proposals_inout)
        output_sum += normal_proposal.m_amount;

    for (const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_proposal : selfsend_payment_proposals_inout)
        output_sum += selfsend_proposal.m_amount;

    CHECK_AND_ASSERT_THROW_MES(total_input_amount >= output_sum,
        "Finalize output proposals: input amount is too small.");
    CHECK_AND_ASSERT_THROW_MES(total_input_amount - output_sum <= static_cast<rct::xmr_amount>(-1),
        "Finalize output proposals: change amount exceeds maximum value allowed.");

    const rct::xmr_amount change_amount{total_input_amount - output_sum};

    // 2. collect self-send output types
    std::vector<jamtis::JamtisSelfSendType> self_send_output_types;
    self_send_output_types.reserve(selfsend_payment_proposals_inout.size());

    for (const jamtis::JamtisPaymentProposalSelfSendV1 &selfsend_proposal : selfsend_payment_proposals_inout)
        self_send_output_types.emplace_back(selfsend_proposal.m_type);

    // 3. set the shared enote ephemeral pubkey here: it will always be the first one when it is needed
    crypto::x25519_pubkey first_enote_ephemeral_pubkey{};

    if (normal_payment_proposals_inout.size() > 0)
        normal_payment_proposals_inout[0].get_enote_ephemeral_pubkey(first_enote_ephemeral_pubkey);
    else if (selfsend_payment_proposals_inout.size() > 0)
        selfsend_payment_proposals_inout[0].get_enote_ephemeral_pubkey(first_enote_ephemeral_pubkey);

    // 4. get output types to add
    std::vector<OutputProposalSetExtraTypesV1> additional_outputs;

    get_additional_output_types_for_output_set_v1(
        normal_payment_proposals_inout.size() + selfsend_payment_proposals_inout.size(),
        self_send_output_types,
        ephemeral_pubkeys_are_unique(normal_payment_proposals_inout, selfsend_payment_proposals_inout),
        change_amount,
        additional_outputs);

    // 5. add the new outputs
    for (const OutputProposalSetExtraTypesV1 additional_output_type : additional_outputs)
    {
        if (additional_output_type == OutputProposalSetExtraTypesV1::NORMAL_DUMMY ||
            additional_output_type == OutputProposalSetExtraTypesV1::SPECIAL_DUMMY)
        {
            make_additional_output_dummy_v1(additional_output_type,
                first_enote_ephemeral_pubkey,
                tools::add_element(normal_payment_proposals_inout));
        }
        else
        {
            make_additional_output_selfsend_v1(additional_output_type,
                first_enote_ephemeral_pubkey,
                change_destination,
                dummy_destination,
                k_view_balance,
                change_amount,
                tools::add_element(selfsend_payment_proposals_inout));
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp

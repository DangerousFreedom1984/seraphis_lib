// Copyright (c) 2023, The Monero Project
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

#include <gtest/gtest.h>

#include <boost/optional/optional.hpp>
#include <boost/range/adaptor/indexed.hpp>
#include <vector>

#include "common/container_helpers.h"
#include "crypto/hash.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "ringct/rctTypes.h"
#include "seraphis_main/tx_builder_types.h"
#include "seraphis_main/tx_builder_types_legacy.h"
#include "seraphis_main/tx_builders_inputs.h"
#include "seraphis_main/tx_builders_legacy_inputs.h"
#include "seraphis_main/tx_builders_mixed.h"
#include "seraphis_main/tx_builders_outputs.h"
#include "seraphis_main/tx_component_types.h"
#include "seraphis_main/tx_component_types_legacy.h"
#include "seraphis_main/txtype_base.h"
#include "seraphis_main/txtype_squashed_v1.h"
#include "seraphis_mocks/seraphis_mocks.h"
#include "seraphis_wallet/tx_classes.h"

using namespace sp;
using namespace sp::mocks;

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static cryptonote::transaction make_miner_transaction(cryptonote::account_public_address const &to)
{
    cryptonote::transaction tx{};
    if (!cryptonote::construct_miner_tx(0, 0, 5000, 500, 500, to, tx))
        throw std::runtime_error{"transaction construction error"};

    crypto::hash id{0};
    if (!cryptonote::get_transaction_hash(tx, id))
        throw std::runtime_error{"could not get transaction hash"};

    return tx;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static cryptonote::transaction make_transaction(cryptonote::account_keys const &from,
    std::vector<cryptonote::transaction> const &sources,
    std::vector<cryptonote::account_public_address> const &destinations,
    bool rct,
    bool bulletproof)
{
    std::uint64_t source_amount = 0;
    std::vector<cryptonote::tx_source_entry> actual_sources;
    for (auto const &source : sources)
    {
        std::vector<cryptonote::tx_extra_field> extra_fields;
        if (!cryptonote::parse_tx_extra(source.extra, extra_fields))
            throw std::runtime_error{"invalid transaction"};

        cryptonote::tx_extra_pub_key key_field{};
        if (!cryptonote::find_tx_extra_field_by_type(extra_fields, key_field))
            throw std::runtime_error{"invalid transaction"};

        for (auto const input : boost::adaptors::index(source.vout))
        {
            source_amount += input.value().amount;
            auto const &key = boost::get<cryptonote::txout_to_key>(input.value().target);

            actual_sources.push_back(
                {{}, 0, key_field.pub_key, {}, std::size_t(input.index()), input.value().amount, rct, rct::identity()});

            for (unsigned ring = 0; ring < 10; ++ring)
                actual_sources.back().push_output(input.index(), key.key, input.value().amount);
        }
    }

    std::vector<cryptonote::tx_destination_entry> to;
    for (auto const &destination : destinations)
        to.push_back({(source_amount / destinations.size()), destination, false});

    cryptonote::transaction tx{};

    crypto::secret_key tx_key{};
    std::vector<crypto::secret_key> extra_keys{};

    std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
    subaddresses[from.m_account_address.m_spend_public_key] = {0, 0};

    if (!cryptonote::construct_tx_and_get_tx_key(from,
            subaddresses,
            actual_sources,
            to,
            boost::none,
            {},
            tx,
            0,
            tx_key,
            extra_keys,
            rct,
            {bulletproof ? rct::RangeProofBulletproof : rct::RangeProofBorromean, bulletproof ? 2 : 0}))
        throw std::runtime_error{"transaction construction error"};

    return tx;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_sp_txtype_squashed_v1(
    std::vector<SpTxSquashedV1> &txs)
{
    // demo making SpTxTypeSquasedV1 with raw tx builder API
    const std::size_t legacy_ring_size = 2;
    const std::size_t ref_set_decomp_n = 2;
    const std::size_t ref_set_decomp_m = 2;
    SpBinnedReferenceSetConfigV1 bin_config{.bin_radius = 1, .num_bin_members = 2};
    const std::size_t num_random_memo_elements = 3;

   
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version = SpTxSquashedV1::SemanticRulesVersion::MOCK;
    const std::size_t num_txs{3};
    const std::size_t num_ins_outs{11};

    // fake ledger context for this test
    MockLedgerContext ledger_context{0, 10000};

    // prepare input/output amounts
    std::vector<rct::xmr_amount> in_legacy_amounts;
    std::vector<rct::xmr_amount> in_sp_amounts;
    std::vector<rct::xmr_amount> out_amounts;

    for (int i{0}; i < num_ins_outs; ++i)
    {
        in_legacy_amounts.push_back(1);  // initial tx_fee = num_ins_outs
        in_sp_amounts.push_back(3);
        out_amounts.push_back(3);
    }

    // set fee
    const DiscretizedFee discretized_transaction_fee{num_ins_outs};
    rct::xmr_amount real_transaction_fee;
    EXPECT_TRUE(try_get_fee_value(discretized_transaction_fee, real_transaction_fee));

    // add an input to cover any extra fee added during discretization
    const rct::xmr_amount extra_fee_amount{real_transaction_fee - num_ins_outs};

    if (extra_fee_amount > 0)
        in_sp_amounts.push_back(extra_fee_amount);

    // make txs
    SpTxSquashedV1 tx_out;
    std::vector<const SpTxSquashedV1 *> tx_ptrs;
    txs.reserve(num_txs);
    tx_ptrs.reserve(num_txs);

    for (std::size_t tx_index{0}; tx_index < num_txs; ++tx_index)
    {
        /// build a tx from base components

        rct::xmr_amount raw_transaction_fee;
        CHECK_AND_ASSERT_THROW_MES(try_get_fee_value(discretized_transaction_fee, raw_transaction_fee),
            "SpTxSquashedV1 (unit test): tried to raw make tx with invalid discretized fee.");

        CHECK_AND_ASSERT_THROW_MES(in_legacy_amounts.size() + in_sp_amounts.size() > 0,
            "SpTxSquashedV1 (unit test): tried to raw make tx without any inputs.");
        CHECK_AND_ASSERT_THROW_MES(out_amounts.size() > 0, "SpTxSquashedV1: tried to raw make tx without any outputs.");

        std::vector<rct::xmr_amount> all_in_amounts{in_legacy_amounts};
        all_in_amounts.insert(all_in_amounts.end(), in_sp_amounts.begin(), in_sp_amounts.end());
        CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts(all_in_amounts, out_amounts, raw_transaction_fee),
            "SpTxSquashedV1 (unit test): tried to raw make tx with unbalanced amounts.");

        // make wallet core privkeys (spend keys for legacy and seraphis, view key for seraphis)
        const crypto::secret_key legacy_spend_privkey{rct::rct2sk(rct::skGen())};
        const crypto::secret_key sp_spend_privkey{rct::rct2sk(rct::skGen())};
        const crypto::secret_key k_view_balance{rct::rct2sk(rct::skGen())};

        // make mock legacy input proposals
        std::vector<LegacyInputProposalV1> legacy_input_proposals{
            gen_mock_legacy_input_proposals_v1(legacy_spend_privkey, in_legacy_amounts)};

        // make mock seraphis input proposals
        std::vector<SpInputProposalV1> sp_input_proposals{
            gen_mock_sp_input_proposals_v1(sp_spend_privkey, k_view_balance, in_sp_amounts)};

        // make mock output proposals
        std::vector<SpOutputProposalV1> output_proposals{
            gen_mock_sp_output_proposals_v1(out_amounts, num_random_memo_elements)};

        // for 2-out txs, can only have one unique enote ephemeral pubkey
        if (output_proposals.size() == 2)
            output_proposals[1].enote_ephemeral_pubkey = output_proposals[0].enote_ephemeral_pubkey;

        // pre-sort inputs and outputs (doing this here makes everything else easier)
        std::sort(legacy_input_proposals.begin(),
            legacy_input_proposals.end(),
            tools::compare_func<LegacyInputProposalV1>(compare_KI));
        std::sort(
            sp_input_proposals.begin(), sp_input_proposals.end(), tools::compare_func<SpInputProposalV1>(compare_KI));
        std::sort(
            output_proposals.begin(), output_proposals.end(), tools::compare_func<SpOutputProposalV1>(compare_Ko));

        // make mock memo elements
        std::vector<ExtraFieldElement> additional_memo_elements;
        additional_memo_elements.resize(num_random_memo_elements);
        for (ExtraFieldElement &element : additional_memo_elements) element = gen_extra_field_element();

        // versioning for proofs
        const tx_version_t tx_version{tx_version_from(semantic_rules_version)};

        // tx components
        std::vector<LegacyEnoteImageV2> legacy_input_images;
        std::vector<SpEnoteImageV1> sp_input_images;
        std::vector<SpEnoteV1> outputs;
        SpBalanceProofV1 balance_proof;
        std::vector<LegacyRingSignatureV4> tx_legacy_ring_signatures;
        std::vector<SpImageProofV1> tx_sp_image_proofs;
        std::vector<SpAlignableMembershipProofV1> tx_sp_alignable_membership_proofs;
        std::vector<SpMembershipProofV1> tx_sp_membership_proofs;
        SpTxSupplementV1 tx_supplement;

        // info shuttles for making components
        std::vector<rct::xmr_amount> output_amounts;
        std::vector<crypto::secret_key> output_amount_commitment_blinding_factors;
        rct::key tx_proposal_prefix;
        std::vector<rct::xmr_amount> input_legacy_amounts;
        std::vector<rct::xmr_amount> input_sp_amounts;
        std::vector<crypto::secret_key> legacy_input_image_amount_commitment_blinding_factors;
        std::vector<crypto::secret_key> sp_input_image_amount_commitment_blinding_factors;

        legacy_input_images.reserve(legacy_input_proposals.size());
        sp_input_images.reserve(sp_input_proposals.size());

        // make everything
        make_v1_outputs_v1(output_proposals,
            outputs,
            output_amounts,
            output_amount_commitment_blinding_factors,
            tx_supplement.output_enote_ephemeral_pubkeys);
        for (const SpOutputProposalV1 &output_proposal : output_proposals)
            accumulate_extra_field_elements(output_proposal.partial_memo, additional_memo_elements);
        make_tx_extra(std::move(additional_memo_elements), tx_supplement.tx_extra);
        for (const LegacyInputProposalV1 &legacy_input_proposal : legacy_input_proposals)
        {
            legacy_input_images.emplace_back();
            get_enote_image_v2(legacy_input_proposal, legacy_input_images.back());
        }
        for (const SpInputProposalV1 &sp_input_proposal : sp_input_proposals)
        {
            sp_input_images.emplace_back();
            get_enote_image_v1(sp_input_proposal, sp_input_images.back());
        }
        make_tx_proposal_prefix_v1(tx_version,
            legacy_input_images,
            sp_input_images,
            outputs,
            discretized_transaction_fee,
            tx_supplement,
            tx_proposal_prefix);
        std::vector<LegacyRingSignaturePrepV1> legacy_ring_signature_preps{gen_mock_legacy_ring_signature_preps_v1(
            tx_proposal_prefix, legacy_input_proposals, legacy_ring_size, ledger_context)};
        make_v3_legacy_ring_signatures_v1(std::move(legacy_ring_signature_preps),
            legacy_spend_privkey,
            hw::get_device("default"),
            tx_legacy_ring_signatures);
        make_v1_image_proofs_v1(
            sp_input_proposals, tx_proposal_prefix, sp_spend_privkey, k_view_balance, tx_sp_image_proofs);
        get_legacy_input_commitment_factors_v1(
            legacy_input_proposals, input_legacy_amounts, legacy_input_image_amount_commitment_blinding_factors);
        get_input_commitment_factors_v1(
            sp_input_proposals, input_sp_amounts, sp_input_image_amount_commitment_blinding_factors);
        make_v1_balance_proof_v1(input_legacy_amounts,
            input_sp_amounts,  // note: must range proof seraphis input image commitments in squashed enote model
            output_amounts,
            raw_transaction_fee,
            legacy_input_image_amount_commitment_blinding_factors,
            sp_input_image_amount_commitment_blinding_factors,
            output_amount_commitment_blinding_factors,
            balance_proof);
        std::vector<SpMembershipProofPrepV1> sp_membership_proof_preps{gen_mock_sp_membership_proof_preps_v1(
            sp_input_proposals, ref_set_decomp_n, ref_set_decomp_m, bin_config, ledger_context)};
        make_v1_alignable_membership_proofs_v1(std::move(sp_membership_proof_preps),
            tx_sp_alignable_membership_proofs);  // alignable membership proofs could theoretically be user inputs as
                                                 // well
        align_v1_membership_proofs_v1(
            sp_input_images, std::move(tx_sp_alignable_membership_proofs), tx_sp_membership_proofs);

        make_seraphis_tx_squashed_v1(semantic_rules_version,
            std::move(legacy_input_images),
            std::move(sp_input_images),
            std::move(outputs),
            std::move(balance_proof),
            std::move(tx_legacy_ring_signatures),
            std::move(tx_sp_image_proofs),
            std::move(tx_sp_membership_proofs),
            std::move(tx_supplement),
            discretized_transaction_fee,
            tx_out);

        txs.push_back(tx_out);
        tx_ptrs.push_back(&(txs.back()));
        const TxValidationContextMock tx_validation_context{ledger_context};

        EXPECT_TRUE(validate_txs(tx_ptrs, tx_validation_context));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------

TEST(seraphis_transaction_class, legacy_txs)
{
    cryptonote::account_base acct;
    acct.generate();
    const auto miner_tx = make_miner_transaction(acct.get_keys().m_account_address);

    crypto::hash tx_id_miner{};
    cryptonote::get_transaction_hash(miner_tx, tx_id_miner);

    crypto::hash tx_id_miner_generic = get_tx_id(miner_tx);

    ASSERT_EQ(tx_id_miner_generic, tx_id_miner);

    cryptonote::account_base acct1;
    acct1.generate();

    cryptonote::account_base acct2;
    acct2.generate();

    const auto miner_tx1 = make_miner_transaction(acct1.get_keys().m_account_address);
    const auto tx = make_transaction(acct1.get_keys(), {miner_tx1}, {acct2.get_keys().m_account_address}, false, false);

    crypto::hash tx_id_normal{};
    cryptonote::get_transaction_hash(tx, tx_id_normal);

    crypto::hash tx_id_generic = get_tx_id(tx);

    ASSERT_EQ(tx_id_generic, tx_id_normal);
}

TEST(seraphis_transaction_class, sp_txs)
{

    std::vector<SpTxSquashedV1> txs;
    make_sp_txtype_squashed_v1(txs);

    // Verify if they are equal
    for (const SpTxSquashedV1 &tx : txs)
    {
        rct::key sp_tx_id;
        get_sp_tx_squashed_v1_txid(tx, sp_tx_id);
        EXPECT_TRUE(get_tx_id(tx) == rct::rct2hash(sp_tx_id));
    }
}

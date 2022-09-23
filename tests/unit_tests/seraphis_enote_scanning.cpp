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

#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/subaddress_index.h"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/jamtis_address_tag_utils.h"
#include "seraphis/jamtis_address_utils.h"
#include "seraphis/jamtis_core_utils.h"
#include "seraphis/jamtis_destination.h"
#include "seraphis/jamtis_enote_utils.h"
#include "seraphis/jamtis_payment_proposal.h"
#include "seraphis/jamtis_support_types.h"
#include "seraphis/legacy_core_utils.h"
#include "seraphis/legacy_enote_types.h"
#include "seraphis/legacy_enote_utils.h"
#include "seraphis/mock_ledger_context.h"
#include "seraphis/sp_composition_proof.h"
#include "seraphis/sp_core_enote_utils.h"
#include "seraphis/sp_core_types.h"
#include "seraphis/sp_crypto_utils.h"
#include "seraphis/tx_base.h"
#include "seraphis/tx_binned_reference_set.h"
#include "seraphis/tx_builder_types.h"
#include "seraphis/tx_builders_inputs.h"
#include "seraphis/tx_builders_mixed.h"
#include "seraphis/tx_builders_outputs.h"
#include "seraphis/tx_component_types.h"
#include "seraphis/tx_discretized_fee.h"
#include "seraphis/tx_enote_finding_context_mocks.h"
#include "seraphis/tx_enote_record_types.h"
#include "seraphis/tx_enote_record_utils.h"
#include "seraphis/tx_enote_scanning.h"
#include "seraphis/tx_enote_scanning_context_simple.h"
#include "seraphis/tx_enote_store_mocks.h"
#include "seraphis/tx_enote_store_updater_mocks.h"
#include "seraphis/tx_extra.h"
#include "seraphis/tx_fee_calculator_mocks.h"
#include "seraphis/tx_fee_calculator_squashed_v1.h"
#include "seraphis/tx_input_selection.h"
#include "seraphis/tx_input_selection_output_context_v1.h"
#include "seraphis/tx_input_selector_mocks.h"
#include "seraphis/tx_legacy_enote_record_utils.h"
#include "seraphis/tx_misc_utils.h"
#include "seraphis/tx_validation_context_mock.h"
#include "seraphis/txtype_squashed_v1.h"

#include "boost/multiprecision/cpp_int.hpp"
#include "gtest/gtest.h"


class Invocable
{
public:
    virtual ~Invocable() = default;
    Invocable& operator=(Invocable&&) = delete;
    virtual void invoke() = 0;
};

class DummyInvocable final : public Invocable
{
public:
    void invoke() override {}
};

namespace sp
{

////
// EnoteScanningContextLedgerTEST
// - enote scanning context for injecting behavior into a scanning process
///
class EnoteScanningContextLedgerTEST final : public EnoteScanningContextLedger
{
public:
//constructors
    /// normal constructor
    EnoteScanningContextLedgerTEST(EnoteScanningContextLedgerSimple &core_scanning_context,
        Invocable &invocable_begin_scanning,
        Invocable &invocable_get_onchain_chunk,
        Invocable &invocable_get_unconfirmed_chunk,
        Invocable &invocable_terminate) :
            m_core_scanning_context{core_scanning_context},
            m_invocable_begin_scanning{invocable_begin_scanning},
            m_invocable_get_onchain_chunk{invocable_get_onchain_chunk},
            m_invocable_get_unconfirmed_chunk{invocable_get_unconfirmed_chunk},
            m_invocable_terminate{invocable_terminate}
    {}

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference werapper])
    EnoteScanningContextLedgerTEST& operator=(EnoteScanningContextLedgerTEST&&) = delete;

//member functions
    /// tell the enote finder it can start scanning from a specified block height
    void begin_scanning_from_height(const std::uint64_t initial_start_height,
        const std::uint64_t max_chunk_size) override
    {
        m_invocable_begin_scanning.invoke();
        m_core_scanning_context.begin_scanning_from_height(initial_start_height, max_chunk_size);
    }
    /// get the next available onchain chunk (must be contiguous with the last chunk acquired since starting to scan)
    /// note: if chunk is empty, chunk represents top of current chain
    void get_onchain_chunk(EnoteScanningChunkLedgerV1 &chunk_out) override
    {
        m_invocable_get_onchain_chunk.invoke();
        m_core_scanning_context.get_onchain_chunk(chunk_out);
    }
    /// try to get a scanning chunk for the unconfirmed txs in a ledger
    bool try_get_unconfirmed_chunk(EnoteScanningChunkNonLedgerV1 &chunk_out) override
    {
        m_invocable_get_unconfirmed_chunk.invoke();
        return m_core_scanning_context.try_get_unconfirmed_chunk(chunk_out);
    }
    /// tell the enote finder to stop its scanning process (should be no-throw no-fail)
    void terminate_scanning() override
    {
        m_invocable_terminate.invoke();
        m_core_scanning_context.terminate_scanning();
    }

private:
    /// enote scanning context that this test context wraps
    EnoteScanningContextLedgerSimple &m_core_scanning_context;

    /// injected invocable objects
    Invocable &m_invocable_begin_scanning;
    Invocable &m_invocable_get_onchain_chunk;
    Invocable &m_invocable_get_unconfirmed_chunk;
    Invocable &m_invocable_terminate;
};

} //namespace sp


//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::secret_key make_secret_key()
{
    return rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_random_address_for_user(const sp::jamtis::jamtis_mock_keys &user_keys,
    sp::jamtis::JamtisDestinationV1 &user_address_out)
{
    using namespace sp;
    using namespace jamtis;

    address_index_t address_index;
    address_index.gen();

    ASSERT_NO_THROW(make_jamtis_destination_v1(user_keys.K_1_base,
        user_keys.xK_ua,
        user_keys.xK_fr,
        user_keys.s_ga,
        address_index,
        user_address_out));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_legacy_subaddress(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    rct::key &subaddr_spendkey_out,
    rct::key &subaddr_viewkey_out,
    cryptonote::subaddress_index &subaddr_index_out)
{
    // random subaddress index: i
    crypto::rand(sizeof(subaddr_index_out.minor), reinterpret_cast<unsigned char*>(&subaddr_index_out.minor));
    crypto::rand(sizeof(subaddr_index_out.major), reinterpret_cast<unsigned char*>(&subaddr_index_out.major));

    // subaddress spendkey: (Hn(k^v, i) + k^s) G
    sp::make_legacy_subaddress_spendkey(legacy_base_spend_pubkey,
        legacy_view_privkey,
        subaddr_index_out,
        subaddr_spendkey_out);

    // subaddress viewkey: k^v * K^{s,i}
    rct::scalarmultKey(subaddr_viewkey_out, subaddr_spendkey_out, rct::sk2rct(legacy_view_privkey));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void append_legacy_enote_ephemeral_pubkeys_to_tx_extra(const std::vector<rct::key> &enote_ephemeral_pubkeys,
    sp::TxExtra &tx_extra_inout)
{
    std::vector<crypto::public_key> enote_ephemeral_pubkeys_typed;
    enote_ephemeral_pubkeys_typed.reserve(enote_ephemeral_pubkeys.size());
    for (const rct::key &enote_ephemeral_pubkey : enote_ephemeral_pubkeys)
        enote_ephemeral_pubkeys_typed.emplace_back(rct::rct2pk(enote_ephemeral_pubkey));

    ASSERT_TRUE(cryptonote::add_additional_tx_pub_keys_to_extra(tx_extra_inout, enote_ephemeral_pubkeys_typed));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void convert_outlay_to_payment_proposal(const rct::xmr_amount outlay_amount,
    const sp::jamtis::JamtisDestinationV1 &destination,
    const sp::TxExtra &partial_memo_for_destination,
    sp::jamtis::JamtisPaymentProposalV1 &payment_proposal_out)
{
    using namespace sp;
    using namespace jamtis;

    payment_proposal_out = JamtisPaymentProposalV1{
            .m_destination = destination,
            .m_amount = outlay_amount,
            .m_enote_ephemeral_privkey = crypto::x25519_secret_key_gen(),
            .m_partial_memo = partial_memo_for_destination
        };
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void add_coinbase_enotes_for_user(const rct::key &mock_input_context,
    const std::vector<rct::xmr_amount> &coinbase_amounts,
    const sp::jamtis::JamtisDestinationV1 &user_address,
    std::vector<sp::SpEnoteV1> &coinbase_enotes_inout,
    sp::SpTxSupplementV1 &tx_supplement_inout)
{
    using namespace sp;
    using namespace jamtis;

    // prepare mock coinbase enotes
    JamtisPaymentProposalV1 payment_proposal_temp;
    coinbase_enotes_inout.reserve(coinbase_enotes_inout.size() + coinbase_amounts.size());
    tx_supplement_inout.m_output_enote_ephemeral_pubkeys.reserve(
        tx_supplement_inout.m_output_enote_ephemeral_pubkeys.size() + coinbase_amounts.size());

    for (const rct::xmr_amount coinbase_amount : coinbase_amounts)
    {
        // make payment proposal
        convert_outlay_to_payment_proposal(coinbase_amount, user_address, TxExtra{}, payment_proposal_temp);

        // get output proposal
        SpOutputProposalV1 output_proposal;
        payment_proposal_temp.get_output_proposal_v1(mock_input_context, output_proposal);

        // save enote and ephemeral pubkey
        coinbase_enotes_inout.emplace_back();
        output_proposal.get_enote_v1(coinbase_enotes_inout.back());
        tx_supplement_inout.m_output_enote_ephemeral_pubkeys.emplace_back(output_proposal.m_enote_ephemeral_pubkey);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void send_coinbase_amounts_to_users(const std::vector<std::vector<rct::xmr_amount>> &coinbase_amounts_per_user,
    const std::vector<sp::jamtis::JamtisDestinationV1> &user_addresses,
    sp::MockLedgerContext &ledger_context_inout)
{
    ASSERT_TRUE(coinbase_amounts_per_user.size() == user_addresses.size());

    using namespace sp;
    using namespace jamtis;

    // prepare mock coinbase enotes
    const rct::key mock_input_context{rct::pkGen()};
    std::vector<SpEnoteV1> coinbase_enotes;
    SpTxSupplementV1 tx_supplement;

    for (std::size_t user_index{0}; user_index < user_addresses.size(); ++user_index)
    {
        add_coinbase_enotes_for_user(mock_input_context,
            coinbase_amounts_per_user[user_index],
            user_addresses[user_index],
            coinbase_enotes,
            tx_supplement);
    }

    // commit coinbase enotes as new block
    ASSERT_NO_THROW(ledger_context_inout.commit_unconfirmed_txs_v1(mock_input_context,
        std::move(tx_supplement),
        std::move(coinbase_enotes)));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void refresh_user_enote_store(const sp::jamtis::jamtis_mock_keys &user_keys,
    const sp::RefreshLedgerEnoteStoreConfig &refresh_config,
    const sp::MockLedgerContext &ledger_context,
    sp::SpEnoteStoreMockV1 &user_enote_store_inout)
{
    using namespace sp;

    const EnoteFindingContextLedgerMock enote_finding_context{ledger_context, user_keys.xk_fr};
    EnoteScanningContextLedgerSimple enote_scanning_context{enote_finding_context};
    EnoteStoreUpdaterLedgerMock enote_store_updater{user_keys.K_1_base, user_keys.k_vb, user_enote_store_inout};

    ASSERT_NO_THROW(refresh_enote_store_ledger(refresh_config, enote_scanning_context, enote_store_updater));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void refresh_user_enote_store_PV(const sp::jamtis::jamtis_mock_keys &user_keys,
    const sp::RefreshLedgerEnoteStoreConfig &refresh_config,
    const sp::MockLedgerContext &ledger_context,
    sp::SpEnoteStoreMockPaymentValidatorV1 &user_enote_store_inout)
{
    using namespace sp;

    const EnoteFindingContextLedgerMock enote_finding_context{ledger_context, user_keys.xk_fr};
    EnoteScanningContextLedgerSimple enote_scanning_context{enote_finding_context};
    EnoteStoreUpdaterLedgerMockIntermediate enote_store_updater{
            user_keys.K_1_base,
            user_keys.xk_ua,
            user_keys.xk_fr,
            user_keys.s_ga,
            user_enote_store_inout
        };

    ASSERT_NO_THROW(refresh_enote_store_ledger(refresh_config, enote_scanning_context, enote_store_updater));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void refresh_user_enote_store_legacy_full(const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    const sp::RefreshLedgerEnoteStoreConfig &refresh_config,
    const sp::MockLedgerContext &ledger_context,
    sp::SpEnoteStoreMockV1 &user_enote_store_inout)
{
    using namespace sp;

    const EnoteFindingContextLedgerMockLegacy enote_finding_context{
            ledger_context,
            legacy_base_spend_pubkey,
            legacy_subaddress_map,
            legacy_view_privkey
        };
    EnoteScanningContextLedgerSimple enote_scanning_context{enote_finding_context};
    EnoteStoreUpdaterLedgerMockLegacy enote_store_updater{
            legacy_base_spend_pubkey,
            legacy_spend_privkey,
            legacy_view_privkey,
            user_enote_store_inout
        };

    ASSERT_NO_THROW(refresh_enote_store_ledger(refresh_config, enote_scanning_context, enote_store_updater));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void refresh_user_enote_store_legacy_intermediate(const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const bool key_image_refresh_mode,
    const sp::RefreshLedgerEnoteStoreConfig &refresh_config,
    const sp::MockLedgerContext &ledger_context,
    sp::SpEnoteStoreMockV1 &user_enote_store_inout)
{
    using namespace sp;

    const EnoteFindingContextLedgerMockLegacy enote_finding_context{
            ledger_context,
            legacy_base_spend_pubkey,
            legacy_subaddress_map,
            key_image_refresh_mode
                ? boost::optional<crypto::secret_key>{}
                : legacy_view_privkey
        };
    EnoteScanningContextLedgerSimple enote_scanning_context{enote_finding_context};
    EnoteStoreUpdaterLedgerMockLegacyIntermediate enote_store_updater{
            legacy_base_spend_pubkey,
            legacy_view_privkey,
            key_image_refresh_mode,
            user_enote_store_inout
        };

    ASSERT_NO_THROW(refresh_enote_store_ledger(refresh_config, enote_scanning_context, enote_store_updater));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void construct_tx_for_mock_ledger_v1(const sp::jamtis::jamtis_mock_keys &local_user_keys,
    const sp::InputSelectorV1 &local_user_input_selector,
    const sp::FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const std::vector<std::tuple<rct::xmr_amount, sp::jamtis::JamtisDestinationV1, sp::TxExtra>> &outlays,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const sp::SpBinnedReferenceSetConfigV1 &bin_config,
    sp::MockLedgerContext &ledger_context_inout,
    sp::SpTxSquashedV1 &tx_out)
{
    using namespace sp;
    using namespace jamtis;

    /// build transaction

    // 1. prepare dummy and change addresses
    JamtisDestinationV1 change_address;
    JamtisDestinationV1 dummy_address;
    make_random_address_for_user(local_user_keys, change_address);
    make_random_address_for_user(local_user_keys, dummy_address);

    // 2. convert outlays to normal payment proposals
    std::vector<JamtisPaymentProposalV1> normal_payment_proposals;
    normal_payment_proposals.reserve(outlays.size());

    for (const auto &outlay : outlays)
    {
        normal_payment_proposals.emplace_back();

        convert_outlay_to_payment_proposal(std::get<rct::xmr_amount>(outlay),
            std::get<JamtisDestinationV1>(outlay),
            std::get<TxExtra>(outlay),
            normal_payment_proposals.back());
    }

    // 2. tx proposal
    SpTxProposalV1 tx_proposal;
    std::unordered_map<crypto::key_image, std::uint64_t> legacy_input_ledger_mappings;
    std::unordered_map<crypto::key_image, std::uint64_t> sp_input_ledger_mappings;
    ASSERT_NO_THROW(ASSERT_TRUE(try_make_v1_tx_proposal_for_transfer_v1(change_address,
        dummy_address,
        local_user_input_selector,
        tx_fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        std::move(normal_payment_proposals),
        std::vector<JamtisPaymentProposalSelfSendV1>{},
        TxExtra{},
        local_user_keys.k_vb,
        tx_proposal,
        legacy_input_ledger_mappings,  //todo: legacy
        sp_input_ledger_mappings)));

    // 3. prepare for membership proofs
    std::vector<SpMembershipProofPrepV1> membership_proof_preps;
    ASSERT_NO_THROW(make_mock_sp_membership_proof_preps_for_inputs_v1(sp_input_ledger_mappings,
        tx_proposal.m_sp_input_proposals,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_inout,
        membership_proof_preps));

    // 4. complete tx
    ASSERT_NO_THROW(make_seraphis_tx_squashed_v1(tx_proposal,
        {},  //todo: legacy
        std::move(membership_proof_preps),
        SpTxSquashedV1::SemanticRulesVersion::MOCK,
        crypto::secret_key{},  //todo: legacy
        local_user_keys.k_m,
        local_user_keys.k_vb,
        tx_out));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void transfer_funds_single_mock_v1_unconfirmed(const sp::jamtis::jamtis_mock_keys &local_user_keys,
    const sp::InputSelectorV1 &local_user_input_selector,
    const sp::FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const std::vector<std::tuple<rct::xmr_amount, sp::jamtis::JamtisDestinationV1, sp::TxExtra>> &outlays,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const sp::SpBinnedReferenceSetConfigV1 &bin_config,
    sp::MockLedgerContext &ledger_context_inout)
{
    using namespace sp;
    using namespace jamtis;

    // make one tx
    SpTxSquashedV1 single_tx;
    construct_tx_for_mock_ledger_v1(local_user_keys,
        local_user_input_selector,
        tx_fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        outlays,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context_inout,
        single_tx);

    // validate and submit to the mock ledger
    const sp::TxValidationContextMock tx_validation_context{ledger_context_inout};
    ASSERT_TRUE(validate_tx(single_tx, tx_validation_context));
    ASSERT_TRUE(ledger_context_inout.try_add_unconfirmed_tx_v1(single_tx));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void prepare_legacy_enote_for_transfer(const rct::key &destination_subaddr_spendkey,
    const rct::key &destination_subaddr_viewkey,
    const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    const rct::xmr_amount amount,
    const std::uint64_t tx_output_index,
    const crypto::secret_key &enote_ephemeral_privkey,
    sp::LegacyEnoteV4 &legacy_enote_out,
    rct::key &enote_ephemeral_pubkey_out,
    crypto::key_image &key_image_out)
{
    using namespace sp;

    // prepare enote
    enote_ephemeral_pubkey_out = rct::scalarmultKey(destination_subaddr_spendkey, rct::sk2rct(enote_ephemeral_privkey));

    ASSERT_NO_THROW(make_legacy_enote_v4(destination_subaddr_spendkey,
        destination_subaddr_viewkey,
        amount,
        tx_output_index,
        enote_ephemeral_privkey,
        legacy_enote_out));

    // recover key image of enote
    LegacyEnoteRecord full_record_recovered;

    ASSERT_TRUE(try_get_legacy_enote_record(legacy_enote_out,
        enote_ephemeral_pubkey_out,
        tx_output_index,
        0,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        full_record_recovered));

    key_image_out = full_record_recovered.m_key_image;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, trivial_ledger)
{
    using namespace sp;
    using namespace jamtis;

    // make user keys
    jamtis_mock_keys user_keys;
    make_jamtis_mock_keys(user_keys);

    // make user address
    address_index_t j;
    j.gen();
    JamtisDestinationV1 user_address;

    ASSERT_NO_THROW(make_jamtis_destination_v1(user_keys.K_1_base,
        user_keys.xK_ua,
        user_keys.xK_fr,
        user_keys.s_ga,
        j,
        user_address));

    // make enote for user
    const rct::xmr_amount enote_amount{1};
    const rct::key mock_input_context{rct::skGen()};
    SpTxSupplementV1 mock_tx_supplement{};

    const JamtisPaymentProposalV1 payment_proposal{
            .m_destination = user_address,
            .m_amount = enote_amount,
            .m_enote_ephemeral_privkey = crypto::x25519_secret_key_gen(),
            .m_partial_memo = mock_tx_supplement.m_tx_extra
        };
    SpOutputProposalV1 output_proposal;
    payment_proposal.get_output_proposal_v1(mock_input_context, output_proposal);

    SpEnoteV1 single_enote;
    output_proposal.get_enote_v1(single_enote);
    mock_tx_supplement.m_output_enote_ephemeral_pubkeys.emplace_back(output_proposal.m_enote_ephemeral_pubkey);

    // add enote to mock ledger context as a coinbase enote
    MockLedgerContext ledger_context{0, 0};
    ASSERT_NO_THROW(ledger_context.commit_unconfirmed_txs_v1(mock_input_context, mock_tx_supplement, {single_enote}));

    // make and refresh enote store with mock ledger context
    SpEnoteStoreMockV1 user_enote_store{0, 0, 0};
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };
    const EnoteFindingContextLedgerMock enote_finding_context{ledger_context, user_keys.xk_fr};
    EnoteScanningContextLedgerSimple enote_scanning_context{enote_finding_context};
    EnoteStoreUpdaterLedgerMock enote_store_updater{user_keys.K_1_base, user_keys.k_vb, user_enote_store};

    ASSERT_NO_THROW(refresh_enote_store_ledger(refresh_config, enote_scanning_context, enote_store_updater));

    // make a copy of the expected enote record
    SpEnoteRecordV1 single_enote_record;

    ASSERT_TRUE(try_get_enote_record_v1(single_enote,
        output_proposal.m_enote_ephemeral_pubkey,
        mock_input_context,
        user_keys.K_1_base,
        user_keys.k_vb,
        single_enote_record));

    // expect the enote to be found
    ASSERT_TRUE(user_enote_store.has_enote_with_key_image(single_enote_record.m_key_image));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, simple_ledger_1)
{
    using namespace sp;
    using namespace jamtis;

    /// setup

    // 1. config
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 0,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);


    /// test

    // 1. one coinbase to user
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
    send_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, simple_ledger_2)
{
    using namespace sp;
    using namespace jamtis;

    /// setup

    // 1. config
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 0,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);


    /// test

    // 2. two coinbase to user (one coinbase tx)
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
    send_coinbase_amounts_to_users({{1, 1}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, simple_ledger_3)
{
    using namespace sp;
    using namespace jamtis;

    /// setup

    // 1. config
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 0,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);


    /// test

    // 3. two coinbase owned by different users (one coinbase tx)
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
    SpEnoteStoreMockV1 enote_store_B{0, 0, 0};
    send_coinbase_amounts_to_users({{1}, {2}}, {destination_A, destination_B}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, simple_ledger_4)
{
    using namespace sp;
    using namespace jamtis;

    /// setup

    // 1. config
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 0,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);


    /// test

    // 4. two coinbase to user, search between each send (two coinbase txs i.e. two blocks)
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
    send_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);

    send_coinbase_amounts_to_users({{2}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, simple_ledger_5)
{
    using namespace sp;
    using namespace jamtis;

    /// setup

    // 1. config
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);


    /// test

    // 5. search once, three coinbase to user, search once, pop 2, search again, 1 coinbase to user, search again
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);

    send_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);
    send_coinbase_amounts_to_users({{2}}, {destination_A}, ledger_context);
    send_coinbase_amounts_to_users({{4}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 7);

    ledger_context.pop_blocks(2);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);

    send_coinbase_amounts_to_users({{8}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 9);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, simple_ledger_6)
{
    using namespace sp;
    using namespace jamtis;

    /// setup

    // 1. config
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);


    /// test

    // 6. search, three coinbase to user, search, pop 2, search, 1 coinbase to user, search, pop 3, search
    // - refresh height 1
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStoreMockV1 enote_store_A{1, 0, 0};
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);

    send_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);
    send_coinbase_amounts_to_users({{2}}, {destination_A}, ledger_context);
    send_coinbase_amounts_to_users({{4}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 6);

    ledger_context.pop_blocks(2);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);

    send_coinbase_amounts_to_users({{8}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 8);

    ledger_context.pop_blocks(3);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::OFFCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_OFFCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, simple_ledger_locked)
{
    using namespace sp;
    using namespace jamtis;

    /// setup

    // 1. config
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 0,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    make_jamtis_mock_keys(user_keys_A);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    make_random_address_for_user(user_keys_A, destination_A);


    /// test

    // test locked enotes
    const std::uint64_t default_spendable_age{2};
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStoreMockV1 enote_store_A{0, 0, default_spendable_age};
    SpEnoteStoreMockPaymentValidatorV1 enote_store_PV_A{0, default_spendable_age};
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store_PV(user_keys_A, refresh_config, ledger_context, enote_store_PV_A);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);
    ASSERT_TRUE(enote_store_PV_A.get_received_sum({SpEnoteOriginStatus::ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_PV_A.get_received_sum({SpEnoteOriginStatus::ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    send_coinbase_amounts_to_users({{1}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store_PV(user_keys_A, refresh_config, ledger_context, enote_store_PV_A);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //amount 1 locked
    ASSERT_TRUE(enote_store_PV_A.get_received_sum({SpEnoteOriginStatus::ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store_PV_A.get_received_sum({SpEnoteOriginStatus::ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //amount 1 locked

    send_coinbase_amounts_to_users({{2}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store_PV(user_keys_A, refresh_config, ledger_context, enote_store_PV_A);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 1);  //amount 2 locked
    ASSERT_TRUE(enote_store_PV_A.get_received_sum({SpEnoteOriginStatus::ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store_PV_A.get_received_sum({SpEnoteOriginStatus::ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 1);  //amount 2 locked

    send_coinbase_amounts_to_users({}, {}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store_PV(user_keys_A, refresh_config, ledger_context, enote_store_PV_A);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 3);  //none locked
    ASSERT_TRUE(enote_store_PV_A.get_received_sum({SpEnoteOriginStatus::ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store_PV_A.get_received_sum({SpEnoteOriginStatus::ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 3);  //none
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, basic_ledger_tx_passing_1)
{
    using namespace sp;
    using namespace jamtis;

    /// setup

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = 1,
            .m_num_bin_members = 2
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);


    /// test

    // 1. one unconfirmed tx (no change), then commit it (include payment validator checks)
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
    SpEnoteStoreMockPaymentValidatorV1 enote_store_PV_A{0, 0};
    SpEnoteStoreMockV1 enote_store_B{0, 0, 0};
    const sp::InputSelectorMockV1 input_selector_A{enote_store_A};
    const sp::InputSelectorMockV1 input_selector_B{enote_store_B};
    send_coinbase_amounts_to_users({{1, 1, 1, 1}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{2, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store_PV(user_keys_A, refresh_config, ledger_context, enote_store_PV_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 4);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 2);
    ASSERT_TRUE(enote_store_PV_A.get_received_sum({SpEnoteOriginStatus::OFFCHAIN,
        SpEnoteOriginStatus::UNCONFIRMED}) == 0);  //can't find change
    ASSERT_TRUE(enote_store_PV_A.get_received_sum({SpEnoteOriginStatus::ONCHAIN}) == 4);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 2);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 2);

    ledger_context.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store_PV(user_keys_A, refresh_config, ledger_context, enote_store_PV_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 2);
    ASSERT_TRUE(enote_store_PV_A.get_received_sum({SpEnoteOriginStatus::OFFCHAIN,
        SpEnoteOriginStatus::UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_PV_A.get_received_sum({SpEnoteOriginStatus::ONCHAIN}) == 4); //coinbase + can't find change
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 2);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, basic_ledger_tx_passing_2)
{
    using namespace sp;
    using namespace jamtis;

    /// setup

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = 1,
            .m_num_bin_members = 2
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);

    /// test

    // 2. one unconfirmed tx (>0 change), then commit it
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
    SpEnoteStoreMockV1 enote_store_B{0, 0, 0};
    const sp::InputSelectorMockV1 input_selector_A{enote_store_A};
    const sp::InputSelectorMockV1 input_selector_B{enote_store_B};
    send_coinbase_amounts_to_users({{0, 0, 0, 8}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{3, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 8);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 5);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 5);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);

    ledger_context.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 5);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 5);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, basic_ledger_tx_passing_3)
{
    using namespace sp;
    using namespace jamtis;

    /// setup

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = 1,
            .m_num_bin_members = 2
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);


    /// test

    // 3. one unconfirmed tx (>0 change), then commit it + coinbase to B
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
    SpEnoteStoreMockV1 enote_store_B{0, 0, 0};
    const sp::InputSelectorMockV1 input_selector_A{enote_store_A};
    const sp::InputSelectorMockV1 input_selector_B{enote_store_B};
    send_coinbase_amounts_to_users({{0, 0, 0, 8}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{3, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 8);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 5);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 5);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);

    send_coinbase_amounts_to_users({{8}}, {destination_B}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 5);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 5);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 11);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 11);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, basic_ledger_tx_passing_4)
{
    using namespace sp;
    using namespace jamtis;

    /// setup

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = 1,
            .m_num_bin_members = 2
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);


    /// test

    // 4. pass funds around with unconfirmed cache clear
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
    SpEnoteStoreMockV1 enote_store_B{0, 0, 0};
    const sp::InputSelectorMockV1 input_selector_A{enote_store_A};
    const sp::InputSelectorMockV1 input_selector_B{enote_store_B};
    send_coinbase_amounts_to_users({{10, 10, 10, 10}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{20, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 40);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 20);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 20);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 20);

    ledger_context.clear_unconfirmed_cache();
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 40);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 40);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{30, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 40);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 10);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 30);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 30);

    ledger_context.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 10);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 10);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 30);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 30);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{3, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 10);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 7);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 7);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 30);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 33);

    ledger_context.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 7);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 7);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 33);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 33);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, basic_ledger_tx_passing_5)
{
    using namespace sp;
    using namespace jamtis;

    /// setup

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = 1,
            .m_num_bin_members = 2
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);


    /// test

    // 5. pass funds around with non-zero refresh height and reorging
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
    SpEnoteStoreMockV1 enote_store_B{2, 0, 0};
    const sp::InputSelectorMockV1 input_selector_A{enote_store_A};
    const sp::InputSelectorMockV1 input_selector_B{enote_store_B};
    send_coinbase_amounts_to_users({{10, 10, 10, 10}}, {destination_A}, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{11, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 40);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 9);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 29);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 11);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 11);

    ledger_context.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 29);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 29);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{12, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 29);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) >= 7);  //can be (10 + 9) - 12 OR (10 + 10) - 12
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 17);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 12);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 12);

    ledger_context.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 17);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 17);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 12);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 12);

    ledger_context.pop_blocks(1);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 29);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 29);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{13, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);

    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 29);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) >= 6);  //can be (10 + 9) - 13 OR (10 + 10) - 13
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 16);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 13);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 13);

    ledger_context.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 16);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 16);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 13);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 13);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, basic_ledger_tx_passing_6)
{
    using namespace sp;
    using namespace jamtis;

    /// setup

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 5,
            .m_max_partialscan_attempts = 0
        };

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = 1,
            .m_num_bin_members = 2
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    make_jamtis_mock_keys(user_keys_A);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    make_random_address_for_user(user_keys_A, destination_A);


    /// test

    // 6. pass funds back and forth to the same account, with a max chunk size > 1 so multiple self-sends can be sent
    //    and spent within a single chunk
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
    const sp::InputSelectorMockV1 input_selector_A{enote_store_A};
    send_coinbase_amounts_to_users({{16, 0, 0, 0}}, {destination_A}, ledger_context);

    for (std::size_t iteration{0}; iteration < 12; ++iteration)
    {
        // refresh enote store for input selection
        refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

        ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN}, {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 16);

        // churn some of user A's funds
        rct::xmr_amount amnt1 = crypto::rand_range<rct::xmr_amount>(1, 16);

        transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
            input_selector_A,
            fee_calculator,
            fee_per_tx_weight,
            max_inputs,
            {
                {amnt1, destination_A, TxExtra{}}
            },
            ref_set_decomp_n,
            ref_set_decomp_m,
            bin_config,
            ledger_context);
        ledger_context.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});

        // full refresh of user A
        SpEnoteStoreMockV1 enote_store_A_full_refresh{0, 0, 0};
        refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A_full_refresh);

        ASSERT_TRUE(enote_store_A_full_refresh.get_balance({SpEnoteOriginStatus::ONCHAIN},
            {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 16);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
class InvocableTest1 final : public Invocable
{
public:
    InvocableTest1(sp::MockLedgerContext &ledger_context) : m_ledger_contex{ledger_context} {}
    InvocableTest1& operator=(InvocableTest1&&) = delete;

    /// invoke: on the third call, pop 2 blocks from the ledger context
    void invoke() override
    {
        ++m_num_calls;

        if (m_num_calls == 3)
            m_ledger_contex.pop_blocks(2);
    }
private:
    sp::MockLedgerContext &m_ledger_contex;
    std::size_t m_num_calls{0};
};
//-------------------------------------------------------------------------------------------------------------------
class InvocableTest2 final : public Invocable
{
public:
    InvocableTest2(const sp::jamtis::JamtisDestinationV1 &user_address,
        std::vector<rct::xmr_amount> amounts_per_new_coinbase,
        sp::MockLedgerContext &ledger_context) :
            m_user_address{user_address},
            m_amounts_per_new_coinbase{std::move(amounts_per_new_coinbase)},
            m_ledger_contex{ledger_context}
    {}
    InvocableTest2& operator=(InvocableTest2&&) = delete;

    /// invoke: on the first call, pop 2 blocks then push back N new blocks with one coinbase amount each
    void invoke() override
    {
        ++m_num_calls;

        if (m_num_calls == 1)
        {
            m_ledger_contex.pop_blocks(2);
            for (const rct::xmr_amount new_coinbase_amount : m_amounts_per_new_coinbase)
                send_coinbase_amounts_to_users({{new_coinbase_amount}}, {m_user_address}, m_ledger_contex);
        }
    }
private:
    const sp::jamtis::JamtisDestinationV1 &m_user_address;
    const std::vector<rct::xmr_amount> m_amounts_per_new_coinbase;
    sp::MockLedgerContext &m_ledger_contex;
    std::size_t m_num_calls{0};
};
//-------------------------------------------------------------------------------------------------------------------
class InvocableTest3 final : public Invocable
{
public:
    InvocableTest3(const sp::jamtis::JamtisDestinationV1 &user_address,
        std::vector<rct::xmr_amount> amounts_per_new_coinbase,
        sp::MockLedgerContext &ledger_context) :
            m_user_address{user_address},
            m_amounts_per_new_coinbase{std::move(amounts_per_new_coinbase)},
            m_ledger_contex{ledger_context}
    {}
    InvocableTest3& operator=(InvocableTest3&&) = delete;

    /// invoke: on the third call, pop 2 blocks then push back N new blocks with one coinbase amount each
    void invoke() override
    {
        ++m_num_calls;

        if (m_num_calls == 3)
        {
            m_ledger_contex.pop_blocks(2);
            for (const rct::xmr_amount new_coinbase_amount : m_amounts_per_new_coinbase)
                send_coinbase_amounts_to_users({{new_coinbase_amount}}, {m_user_address}, m_ledger_contex);
        }
    }

    /// return number of invocations
    std::size_t num_invocations() const { return m_num_calls; }
private:
    const sp::jamtis::JamtisDestinationV1 &m_user_address;
    const std::vector<rct::xmr_amount> m_amounts_per_new_coinbase;
    sp::MockLedgerContext &m_ledger_contex;
    std::size_t m_num_calls{0};
};
//-------------------------------------------------------------------------------------------------------------------
class InvocableTest4 final : public Invocable
{
public:
    InvocableTest4(const sp::jamtis::JamtisDestinationV1 &user_address,
        const rct::xmr_amount amount_new_coinbase,
        sp::MockLedgerContext &ledger_context) :
            m_user_address{user_address},
            m_amount_new_coinbase{amount_new_coinbase},
            m_ledger_contex{ledger_context}
    {}
    InvocableTest4& operator=(InvocableTest4&&) = delete;

    /// invoke: on every third call, pop 1 block then push back 1 new block with one coinbase amount
    void invoke() override
    {
        ++m_num_calls;

        if (m_num_calls % 3 == 0)
        {
            m_ledger_contex.pop_blocks(1);
            send_coinbase_amounts_to_users({{m_amount_new_coinbase}}, {m_user_address}, m_ledger_contex);
        }
    }
private:
    const sp::jamtis::JamtisDestinationV1 &m_user_address;
    const rct::xmr_amount m_amount_new_coinbase;
    sp::MockLedgerContext &m_ledger_contex;
    std::size_t m_num_calls{0};
};
//-------------------------------------------------------------------------------------------------------------------
class InvocableTest5Submit final : public Invocable
{
public:
    InvocableTest5Submit(sp::SpTxSquashedV1 tx_to_submit,
        sp::MockLedgerContext &ledger_context) :
            m_tx_to_submit{std::move(tx_to_submit)},
            m_ledger_contex{ledger_context}
    {}
    InvocableTest5Submit& operator=(InvocableTest5Submit&&) = delete;

    /// invoke: on the first call, submit prepared tx to the unconfirmed cache of the ledger
    void invoke() override
    {
        ++m_num_calls;

        if (m_num_calls == 1)
        {
            // validate and submit to the mock ledger
            const sp::TxValidationContextMock tx_validation_context{m_ledger_contex};
            ASSERT_TRUE(validate_tx(m_tx_to_submit, tx_validation_context));
            ASSERT_TRUE(m_ledger_contex.try_add_unconfirmed_tx_v1(m_tx_to_submit));
        }
    }
private:
    const sp::SpTxSquashedV1 m_tx_to_submit;
    sp::MockLedgerContext &m_ledger_contex;
    std::size_t m_num_calls{0};
};
//-------------------------------------------------------------------------------------------------------------------
class InvocableTest5Commit final : public Invocable
{
public:
    InvocableTest5Commit(sp::MockLedgerContext &ledger_context) : m_ledger_contex{ledger_context} {}
    InvocableTest5Commit& operator=(InvocableTest5Commit&&) = delete;

    /// invoke: commit any unconfirmed txs in the ledger's unconfirmed chache
    void invoke() override
    {
        m_ledger_contex.commit_unconfirmed_txs_v1(rct::key{}, sp::SpTxSupplementV1{}, std::vector<sp::SpEnoteV1>{});
    }
private:
    sp::MockLedgerContext &m_ledger_contex;
};
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, reorgs_while_scanning_1)
{
    using namespace sp;
    using namespace jamtis;

    /// setup
    DummyInvocable dummy_invocable;

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = 1,
            .m_num_bin_members = 2
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);


    /// test

    // 1. full internal reorg
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
    SpEnoteStoreMockV1 enote_store_B{0, 0, 0};
    const sp::InputSelectorMockV1 input_selector_A{enote_store_A};
    const sp::InputSelectorMockV1 input_selector_B{enote_store_B};
    send_coinbase_amounts_to_users({{1, 1, 1, 1}}, {destination_A}, ledger_context);

    // a. refresh once so alignment will begin on block 0 in the test
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    // b. send tx A -> B
    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{2, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});

    // c. refresh user A with injected invocable
    // current chain state: {block0[{1, 1, 1, 1} -> A], block1[A -> {2} -> B]}
    // current enote context A: [enotes: block0{1, 1, 1, 1}], [blocks: 0{...}]
    // expected refresh sequence:
    // 1. desired start height = block 1
    // 2. actual start height = block 0 = ([desired start] 1 - [reorg depth] 1)
    // 3. scan process
    //   a. onchain loop
    //     i.   get onchain chunk: block 0  (success: chunk range [0, 1))
    //     ii.  get onchain chunk: block 1  (success: chunk range [1, 2))
    //     iii. get onchain chunk: block 2  (injected: pop 2)  (fail: chunk range [0,0) -> NEED_FULLSCAN)
    //   b. skip unconfirmed chunk: (NEED_FULLSCAN)
    // 4. NEED_FULLSCAN: rescan from block 0
    //   a. onchain loop
    //     i.   get onchain chunk: block 0  (success: chunk range [0, 0) -> DONE)
    //   b. unconfirmed chunk: empty
    //   c. follow-up onchain loop: success on block 0 (range [0, 0) -> DONE)
    // 5. DONE: refresh enote store of A
    const EnoteFindingContextLedgerMock enote_finding_context_A{ledger_context, user_keys_A.xk_fr};
    EnoteScanningContextLedgerSimple enote_scanning_context_A{enote_finding_context_A};
    InvocableTest1 invocable_get_onchain{ledger_context};
    EnoteScanningContextLedgerTEST test_scanning_context_A(enote_scanning_context_A,
        dummy_invocable,
        invocable_get_onchain,
        dummy_invocable,
        dummy_invocable);
    EnoteStoreUpdaterLedgerMock enote_store_updater{user_keys_A.K_1_base, user_keys_A.k_vb, enote_store_A};
    ASSERT_NO_THROW(refresh_enote_store_ledger(refresh_config,
        test_scanning_context_A,
        enote_store_updater));

    // d. after refreshing, both users should have no balance
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, reorgs_while_scanning_2)
{
    using namespace sp;
    using namespace jamtis;

    /// setup
    DummyInvocable dummy_invocable;

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = 1,
            .m_num_bin_members = 2
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);


    /// test

    // 2. full internal reorg with replacement
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
    SpEnoteStoreMockV1 enote_store_B{0, 0, 0};
    const sp::InputSelectorMockV1 input_selector_A{enote_store_A};
    const sp::InputSelectorMockV1 input_selector_B{enote_store_B};
    send_coinbase_amounts_to_users({{1, 1, 1, 1}}, {destination_A}, ledger_context);

    // a. refresh A so coinbase funds are available
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    // b. send two tx A -> B in two blocks
    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{1, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{2, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});

    // c. refresh A so top block is block 2
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    // d. refresh user A with injected invocable
    // current chain state: {block0[{1, 1, 1, 1} -> A], block1[A -> {1} -> B], block2[A -> {2} -> B]}
    // current enote context A: [enotes: block0{1, 1, 1, 1}, block1{0}, block2{0}], [blocks: 0{...}, 1{...}, 2{...}]
    // expected refresh sequence:
    // 1. desired start height = block 3
    // 2. actual start height = block 2 = ([desired start] 3 - [reorg depth] 1)
    // 3. scan process
    //   a. onchain loop
    //     i.   get onchain chunk: block 2  (injected: pop 2, +2 blocks)  (fail: chunk range [2, 3) -> NEED_FULLSCAN)
    //   b. skip unconfirmed chunk: (NEED_FULLSCAN)
    // 4. NEED_FULLSCAN: rescan from block 1
    //   a. onchain loop
    //     i.   get onchain chunk: block 1  (success: chunk range [1, 2))
    //     ii.  get onchain chunk: block 2  (success: chunk range [2, 3))
    //     iii. get onchain chunk: block 3  (success: chunk range [3, 3) -> DONE)
    //   b. unconfirmed chunk: empty
    //   c. follow-up onchain loop: success on block 3 (range [3, 3) -> DONE)
    // 5. DONE: refresh enote store of A
    const EnoteFindingContextLedgerMock enote_finding_context_A{ledger_context, user_keys_A.xk_fr};
    EnoteScanningContextLedgerSimple enote_scanning_context_A{enote_finding_context_A};
    InvocableTest2 invocable_get_onchain{destination_A, {3, 5}, ledger_context};
    EnoteScanningContextLedgerTEST test_scanning_context_A(enote_scanning_context_A,
        dummy_invocable,
        invocable_get_onchain,
        dummy_invocable,
        dummy_invocable);
    EnoteStoreUpdaterLedgerMock enote_store_updater{user_keys_A.K_1_base, user_keys_A.k_vb, enote_store_A};
    ASSERT_NO_THROW(refresh_enote_store_ledger(refresh_config,
        test_scanning_context_A,
        enote_store_updater));

    // d. check balances after refreshing
    refresh_user_enote_store(user_keys_B, refresh_config, ledger_context, enote_store_B);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 12);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 12);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, reorgs_while_scanning_3)
{
    using namespace sp;
    using namespace jamtis;

    /// setup
    DummyInvocable dummy_invocable;

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = 1,
            .m_num_bin_members = 2
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);


    /// test

    // 3. partial internal reorg with replacement
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 1
        };
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
    SpEnoteStoreMockV1 enote_store_B{0, 0, 0};
    const sp::InputSelectorMockV1 input_selector_A{enote_store_A};
    const sp::InputSelectorMockV1 input_selector_B{enote_store_B};
    send_coinbase_amounts_to_users({{1, 1, 1, 1}}, {destination_A}, ledger_context);

    // a. refresh once so user A can make a tx
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    // b. send two txs A -> B in two blocks
    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{1, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{2, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});

    // c. refresh user B with injected invocable
    // current chain state: {block0[{2, 2, 2, 2} -> A], block1[A -> {1} -> B], block2[A -> {2} -> B]}
    // current enote context B: [enotes: none, [blocks: none]
    // expected refresh sequence:
    // 1. desired start height = block 0
    // 2. actual start height = block 0 = round_to_0([desired start] 0 - [reorg depth] 1)
    // 3. scan process
    //   a. onchain loop
    //     i.   get onchain chunk: block 0  (success: chunk range [0, 1))
    //     ii.  get onchain chunk: block 1  (success: chunk range [1, 2))
    //     iii. get onchain chunk: block 2  (injected: pop 2, +2 blocks)  (fail: chunk range [2, 3) -> NEED_PARTIALSCAN)
    //   b. skip unconfirmed chunk: (NEED_PARTIALSCAN)
    // 4. NEED_PARTIALSCAN: rescan from block 1 (desired block: 2, reorg depth: 1)
    //   a. onchain loop
    //     i.   get onchain chunk: block 1  (success: chunk range [1, 2))
    //     ii.  get onchain chunk: block 2  (success: chunk range [2, 3))
    //     iii. get onchain chunk: block 3  (success: chunk range [3, 3) -> DONE)
    //   b. unconfirmed chunk: empty
    //   c. follow-up onchain loop: success on block 3 (range [3, 3) -> DONE)
    // 5. DONE: refresh enote store of B
    const EnoteFindingContextLedgerMock enote_finding_context_B{ledger_context, user_keys_B.xk_fr};
    EnoteScanningContextLedgerSimple enote_scanning_context_B{enote_finding_context_B};
    InvocableTest3 invocable_get_onchain{destination_B, {3, 5}, ledger_context};
    EnoteScanningContextLedgerTEST test_scanning_context_B(enote_scanning_context_B,
        dummy_invocable,
        invocable_get_onchain,
        dummy_invocable,
        dummy_invocable);
    EnoteStoreUpdaterLedgerMock enote_store_updater{user_keys_B.K_1_base, user_keys_B.k_vb, enote_store_B};
    ASSERT_NO_THROW(refresh_enote_store_ledger(refresh_config,
        test_scanning_context_B,
        enote_store_updater));

    // d. make sure NEED_FULLSCAN was not triggered on the reorg (would be == 8 here because fullscan will rescan block 0)
    ASSERT_TRUE(invocable_get_onchain.num_invocations() == 7);

    // e. check users' balances
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 4);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 4);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 8);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 8);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, reorgs_while_scanning_4)
{
    using namespace sp;
    using namespace jamtis;

    /// setup
    DummyInvocable dummy_invocable;

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = 1,
            .m_num_bin_members = 2
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);


    /// test

    // 4. partial internal reorgs to failure
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 4
        };
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
    SpEnoteStoreMockV1 enote_store_B{0, 0, 0};
    const sp::InputSelectorMockV1 input_selector_A{enote_store_A};
    const sp::InputSelectorMockV1 input_selector_B{enote_store_B};
    send_coinbase_amounts_to_users({{1, 1, 1, 1}}, {destination_A}, ledger_context);

    // a. refresh once so user A can make a tx
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    // b. send tx A -> B
    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{1, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});

    // c. refresh user B with injected invocable
    // current chain state: {block0[{1, 1, 1, 1} -> A], block1[A -> {1} -> B]}
    // current enote context B: [enotes: none], [blocks: none]
    // expected refresh sequence:
    // 1. desired start height = block 0
    // 2. actual start height = block 0 = ([desired start] 0 - [reorg depth] 0)
    // 3. scan process
    //   a. onchain loop
    //     i.   get onchain chunk: block 0  (success: chunk range [0, 1))
    //     ii.  get onchain chunk: block 1  (success: chunk range [1, 2))
    //     iii. get onchain chunk: block 2  (inject: pop 1, +1 blocks) (fail: chunk range [2, 2) -> NEED_PARTIALSCAN)
    //   b. skip unconfirmed chunk: (NEED_PARTIALSCAN)
    // 4. NEED_PARTIALSCAN: rescan from block 0
    //   a. onchain loop
    //     i.   get onchain chunk: block 0  (success: chunk range [0, 1))
    //     ii.  get onchain chunk: block 1  (success: chunk range [1, 2))
    //     iii. get onchain chunk: block 2  (inject: pop 1, +1 blocks) (fail: chunk range [2, 2) -> NEED_PARTIALSCAN)
    //   b. skip unconfirmed chunk: (NEED_PARTIALSCAN)
    // 5. ... etc. until partialscan attempts runs out (then throw)
    const EnoteFindingContextLedgerMock enote_finding_context_B{ledger_context, user_keys_B.xk_fr};
    EnoteScanningContextLedgerSimple enote_scanning_context_B{enote_finding_context_B};
    InvocableTest4 invocable_get_onchain{destination_B, 1, ledger_context};
    EnoteScanningContextLedgerTEST test_scanning_context_B(enote_scanning_context_B,
        dummy_invocable,
        invocable_get_onchain,
        dummy_invocable,
        dummy_invocable);
    EnoteStoreUpdaterLedgerMock enote_store_updater{user_keys_B.K_1_base, user_keys_B.k_vb, enote_store_B};
    ASSERT_ANY_THROW(refresh_enote_store_ledger(refresh_config,
        test_scanning_context_B,
        enote_store_updater));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, reorgs_while_scanning_5)
{
    using namespace sp;
    using namespace jamtis;

    /// setup
    DummyInvocable dummy_invocable;

    // 1. config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{0};  // 0 fee here
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    const FeeCalculatorMockTrivial fee_calculator;  //just do a trivial calculator here (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = 1,
            .m_num_bin_members = 2
        };

    // 2. user keys
    jamtis_mock_keys user_keys_A;
    jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_A);
    make_jamtis_mock_keys(user_keys_B);

    // 3. user addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);


    /// test

    // 5. sneaky tx found in follow-up loop
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 4
        };
    MockLedgerContext ledger_context{0, 0};
    SpEnoteStoreMockV1 enote_store_A{0, 0, 0};
    SpEnoteStoreMockV1 enote_store_B{0, 0, 0};
    const sp::InputSelectorMockV1 input_selector_A{enote_store_A};
    const sp::InputSelectorMockV1 input_selector_B{enote_store_B};
    send_coinbase_amounts_to_users({{1, 1, 1, 1}}, {destination_A}, ledger_context);

    // a. refresh once so user A can make a tx
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    // b. send tx A -> B
    transfer_funds_single_mock_v1_unconfirmed(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{1, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context);
    ledger_context.commit_unconfirmed_txs_v1(rct::key{}, SpTxSupplementV1{}, std::vector<SpEnoteV1>{});
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    // c. prepare sneaky tx to insert while scanning
    SpTxSquashedV1 sneaky_tx;
    construct_tx_for_mock_ledger_v1(user_keys_A,
        input_selector_A,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{2, destination_B, TxExtra{}}},
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context,
        sneaky_tx);

    // c. refresh user B with injected invocable
    // current chain state: {block0[{1, 1, 1, 1} -> A], block1[A -> {1} -> B]}
    // current enote context B: [enotes: none], [blocks: none]
    // expected refresh sequence:
    // 1. desired start height = block 0
    // 2. actual start height = block 0 = ([desired start] 0 - [reorg depth] 0)
    // 3. scan process
    //   a. onchain loop
    //     i.   get onchain chunk: block 0  (success: chunk range [0, 1))
    //     ii.  get onchain chunk: block 1  (success: chunk range [1, 2))
    //     iii. get onchain chunk: block 2  (success: chunk range [2, 2) -> DONE)
    //   b. unconfirmed chunk: (inject: submit A -> {2} -> B)  (success: found {2})
    //   c. follow-up onchain loop
    //     i.   get onchain chunk: block 2  (inject: commit unconfirmed)  (success: chunk range [2, 3])
    //     ii.  get onchain chunk: block 3  (success: chunk range [3, 3) -> DONE)
    // 4. DONE: refresh enote store of B
    const EnoteFindingContextLedgerMock enote_finding_context_B{ledger_context, user_keys_B.xk_fr};
    EnoteScanningContextLedgerSimple enote_scanning_context_B{enote_finding_context_B};
    InvocableTest5Submit invocable_get_onchain{std::move(sneaky_tx), ledger_context};
    InvocableTest5Commit invocable_get_unconfirmed{ledger_context};
    EnoteScanningContextLedgerTEST test_scanning_context_B(enote_scanning_context_B,
        dummy_invocable,
        invocable_get_onchain,
        invocable_get_unconfirmed,
        dummy_invocable);
    EnoteStoreUpdaterLedgerMock enote_store_updater{user_keys_B.K_1_base, user_keys_B.k_vb, enote_store_B};
    ASSERT_NO_THROW(refresh_enote_store_ledger(refresh_config,
        test_scanning_context_B,
        enote_store_updater));

    // d. check users' balances
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_A);

    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_A.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 1);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store_B.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 3);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_pre_transition_1)
{
    using namespace sp;

    /// setup

    // 1. config
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    // 2. user keys
    const crypto::secret_key legacy_spend_privkey{make_secret_key()};
    const crypto::secret_key legacy_view_privkey{make_secret_key()};
    const rct::key legacy_base_spend_pubkey{rct::scalarmultBase(rct::sk2rct(legacy_spend_privkey))};

    // 3. user normal address
    const rct::key normal_addr_spendkey{legacy_base_spend_pubkey};
    const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_view_privkey))};

    // 4. user subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    make_legacy_subaddress(legacy_base_spend_pubkey, legacy_view_privkey, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;


    /// test

    // 1. v1-v4 legacy enotes (both normal and subaddress destinations)
    MockLedgerContext ledger_context{10000, 10000};
    SpEnoteStoreMockV1 enote_store{0, 10000, 0};

    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);

    LegacyEnoteV1 enote_v1_1;  //to normal destination
    const crypto::secret_key enote_ephemeral_privkey_1{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_1{
            rct::scalarmultBase(rct::sk2rct(enote_ephemeral_privkey_1))
        };

    ASSERT_NO_THROW(make_legacy_enote_v1(normal_addr_spendkey,
        normal_addr_viewkey,
        1,  //amount
        0,  //index in planned mock coinbase tx
        enote_ephemeral_privkey_1,
        enote_v1_1));

    LegacyEnoteV1 enote_v1_2;  //to subaddress destination
    const crypto::secret_key enote_ephemeral_privkey_2{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_2{
            rct::scalarmultKey(subaddr_spendkey, rct::sk2rct(enote_ephemeral_privkey_2))
        };

    ASSERT_NO_THROW(make_legacy_enote_v1(subaddr_spendkey,
        subaddr_viewkey,
        1,  //amount
        1,  //index in planned mock coinbase tx
        enote_ephemeral_privkey_2,
        enote_v1_2));

    LegacyEnoteV2 enote_v2_1;  //to normal destination
    const crypto::secret_key enote_ephemeral_privkey_3{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_3{
            rct::scalarmultBase(rct::sk2rct(enote_ephemeral_privkey_3))
        };

    ASSERT_NO_THROW(make_legacy_enote_v2(normal_addr_spendkey,
        normal_addr_viewkey,
        1,  //amount
        2,  //index in planned mock coinbase tx
        enote_ephemeral_privkey_3,
        enote_v2_1));

    LegacyEnoteV2 enote_v2_2;  //to subaddress destination
    const crypto::secret_key enote_ephemeral_privkey_4{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_4{
            rct::scalarmultKey(subaddr_spendkey, rct::sk2rct(enote_ephemeral_privkey_4))
        };

    ASSERT_NO_THROW(make_legacy_enote_v2(subaddr_spendkey,
        subaddr_viewkey,
        1,  //amount
        3,  //index in planned mock coinbase tx
        enote_ephemeral_privkey_4,
        enote_v2_2));

    LegacyEnoteV3 enote_v3_1;  //to normal destination
    const crypto::secret_key enote_ephemeral_privkey_5{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_5{
            rct::scalarmultBase(rct::sk2rct(enote_ephemeral_privkey_5))
        };

    ASSERT_NO_THROW(make_legacy_enote_v3(normal_addr_spendkey,
        normal_addr_viewkey,
        1,  //amount
        4,  //index in planned mock coinbase tx
        enote_ephemeral_privkey_5,
        enote_v3_1));

    LegacyEnoteV3 enote_v3_2;  //to subaddress destination
    const crypto::secret_key enote_ephemeral_privkey_6{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_6{
            rct::scalarmultKey(subaddr_spendkey, rct::sk2rct(enote_ephemeral_privkey_6))
        };

    ASSERT_NO_THROW(make_legacy_enote_v3(subaddr_spendkey,
        subaddr_viewkey,
        1,  //amount
        5,  //index in planned mock coinbase tx
        enote_ephemeral_privkey_6,
        enote_v3_2));

    LegacyEnoteV4 enote_v4_1;  //to normal destination
    const crypto::secret_key enote_ephemeral_privkey_7{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_7{
            rct::scalarmultBase(rct::sk2rct(enote_ephemeral_privkey_7))
        };

    ASSERT_NO_THROW(make_legacy_enote_v4(normal_addr_spendkey,
        normal_addr_viewkey,
        1,  //amount
        6,  //index in planned mock coinbase tx
        enote_ephemeral_privkey_7,
        enote_v4_1));

    LegacyEnoteV4 enote_v4_2;  //to subaddress destination
    const crypto::secret_key enote_ephemeral_privkey_8{make_secret_key()};
    const rct::key enote_ephemeral_pubkey_8{
            rct::scalarmultKey(subaddr_spendkey, rct::sk2rct(enote_ephemeral_privkey_8))
        };

    ASSERT_NO_THROW(make_legacy_enote_v4(subaddr_spendkey,
        subaddr_viewkey,
        1,  //amount
        7,  //index in planned mock coinbase tx
        enote_ephemeral_privkey_8,
        enote_v4_2));

    TxExtra tx_extra_1;
    append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_1,
                enote_ephemeral_pubkey_2,
                enote_ephemeral_pubkey_3,
                enote_ephemeral_pubkey_4,
                enote_ephemeral_pubkey_5,
                enote_ephemeral_pubkey_6,
                enote_ephemeral_pubkey_7,
                enote_ephemeral_pubkey_8
            },
            tx_extra_1
        );
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                enote_v1_1,
                enote_v1_2,
                enote_v2_1,
                enote_v2_2,
                enote_v3_1,
                enote_v3_2,
                enote_v4_1,
                enote_v4_2
            }
        ));

    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 8);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 8);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_pre_transition_2)
{
    using namespace sp;

    /// setup

    // 1. config
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    // 2. user keys
    const crypto::secret_key legacy_spend_privkey{make_secret_key()};
    const crypto::secret_key legacy_view_privkey{make_secret_key()};
    const rct::key legacy_base_spend_pubkey{rct::scalarmultBase(rct::sk2rct(legacy_spend_privkey))};

    // 3. user normal address
    //const rct::key normal_addr_spendkey{legacy_base_spend_pubkey};
    //const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_view_privkey))};

    // 4. user subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    make_legacy_subaddress(legacy_base_spend_pubkey, legacy_view_privkey, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;


    /// test

    // 2. manual scanning with key image imports: test 1
    MockLedgerContext ledger_context{10000, 10000};
    SpEnoteStoreMockV1 enote_store{0, 10000, 0};

    //make enote for test
    LegacyEnoteV4 enote_1;
    rct::key enote_ephemeral_pubkey_1;
    crypto::key_image key_image;

    prepare_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        1,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_1,
        enote_ephemeral_pubkey_1,
        key_image);

    TxExtra tx_extra_1;
    append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_1
            },
            tx_extra_1
        );

    //add legacy enote in block 0
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                enote_1
            }
        ));

    //intermediate refresh
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 0);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == -1);
    ASSERT_TRUE(enote_store.get_legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 1);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 0);

    //spend enote in block 1
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {
                key_image
            },
            {}
        ));

    //intermediate refresh
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == -1);
    ASSERT_TRUE(enote_store.get_legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 1);

    //export intermediate onetime addresses that need key images
    //(not done for this mock-up)

    //save current height that was legacy partial-scanned
    const std::uint64_t intermediate_height_pre_import_cycle{
            enote_store.get_top_legacy_partialscanned_block_height()
        };

    //import key images for onetime addresses of intermediate records in the enote store
    ASSERT_NO_THROW(enote_store.import_legacy_key_image(key_image, enote_1.m_onetime_address));

    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == -1);
    ASSERT_TRUE(enote_store.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 1);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 1);  //intermediate record promoted to full

    //add empty block 2 (inject to test ledger height trackers)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {},
            {}
        ));

    //collect legacy key images since last fullscan (block -1)
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        true,  //only collect key images with spent contexts
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED},
        {SpEnoteSpentStatus::SPENT_ONCHAIN, SpEnoteSpentStatus::SPENT_UNCONFIRMED}) == 0);

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 1);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == -1);
    ASSERT_TRUE(enote_store.get_top_sp_scanned_block_height() == 1);
    ASSERT_TRUE(enote_store.get_top_block_height() == 1);  //key image recovery scan should not update block height

    //update legacy fullscan height in enote store to partialscan height the store had when exporting onetime addresses
    ASSERT_NO_THROW(enote_store.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle));

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 1);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 1);
    ASSERT_TRUE(enote_store.get_top_block_height() == 1);

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 2);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 1);
    ASSERT_TRUE(enote_store.get_top_sp_scanned_block_height() == 2);
    ASSERT_TRUE(enote_store.get_top_block_height() == 2);
    ASSERT_TRUE(enote_store.get_legacy_intermediate_records().size() == 0);

    //remove block 2
    ledger_context.pop_blocks(1);

    //collect legacy key images since last fullscan (block 1)
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        true,  //key image recovery mode to demonstrate it doesn't affect seraphis block height tracker or block ids
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 1);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 1);
    ASSERT_TRUE(enote_store.get_top_sp_scanned_block_height() == 2);
    ASSERT_TRUE(enote_store.get_top_block_height() == 2);

    //mock seraphis refresh to fix enote store block height trackers after reorg
    refresh_user_enote_store(jamtis::jamtis_mock_keys{},
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 1);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 1);
    ASSERT_TRUE(enote_store.get_top_sp_scanned_block_height() == 1);
    ASSERT_TRUE(enote_store.get_top_block_height() == 1);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_pre_transition_3)
{
    using namespace sp;

    /// setup

    // 1. config
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    // 2. user keys
    const crypto::secret_key legacy_spend_privkey{make_secret_key()};
    const crypto::secret_key legacy_view_privkey{make_secret_key()};
    const rct::key legacy_base_spend_pubkey{rct::scalarmultBase(rct::sk2rct(legacy_spend_privkey))};

    // 3. user normal address
    //const rct::key normal_addr_spendkey{legacy_base_spend_pubkey};
    //const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_view_privkey))};

    // 4. user subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    make_legacy_subaddress(legacy_base_spend_pubkey, legacy_view_privkey, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;

    // 5. random 'other' address
    const rct::key subaddr_spendkey_rand{rct::pkGen()};
    const rct::key subaddr_viewkey_rand{rct::pkGen()};


    /// test

    // 3. manual scanning with key image imports: test 2
    MockLedgerContext ledger_context{10000, 10000};
    SpEnoteStoreMockV1 enote_store{0, 10000, 0};

    //make enotes: 1 -> user, 1 -> rand
    LegacyEnoteV4 enote_1;
    rct::key enote_ephemeral_pubkey_1;
    crypto::key_image key_image_1;

    prepare_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        1,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_1,
        enote_ephemeral_pubkey_1,
        key_image_1);

    LegacyEnoteV4 enote_rand;
    ASSERT_NO_THROW(make_legacy_enote_v4(subaddr_spendkey_rand,  //random enote
        subaddr_viewkey_rand,
        1,  //amount
        1,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_rand));

    TxExtra tx_extra_1;
    append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_1,
                rct::pkGen()  //random enote gets a random enote ephemeral pubkey
            },
            tx_extra_1
        );

    //block 0: 1 -> user, 1 -> rand
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                enote_1,
                enote_rand
            }
        ));

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 0);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == -1);
    ASSERT_TRUE(enote_store.get_legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 0);

    //make enote: 2 -> user
    LegacyEnoteV4 enote_2;
    rct::key enote_ephemeral_pubkey_2;
    crypto::key_image key_image_2;

    prepare_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        2,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_2,
        enote_ephemeral_pubkey_2,
        key_image_2);

    TxExtra tx_extra_2;
    append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_2
            },
            tx_extra_2
        );

    //block 1: 2 -> user
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_2,
            {},
            {
                enote_2
            }
        ));

    //get intermediate scan height
    const std::uint64_t intermediate_height_pre_import_cycle_1{
            enote_store.get_top_legacy_partialscanned_block_height()
        };

    //import key images: enote 1 in block 0
    ASSERT_NO_THROW(enote_store.import_legacy_key_image(key_image_1, enote_1.m_onetime_address));

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 0);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == -1);
    ASSERT_TRUE(enote_store.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 1);  //intermediate record promoted to full

    //legacy key image scan
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        true,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 0);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == -1);
    ASSERT_TRUE(enote_store.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 1);

    //set fullscan height to saved intermediate height
    ASSERT_NO_THROW(enote_store.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle_1));

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 0);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 0);

    //intermediate scan (to read block 1)
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 1);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 0);
    ASSERT_TRUE(enote_store.get_legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 1);

    //get intermediate height
    const std::uint64_t intermediate_height_pre_import_cycle_2{
            enote_store.get_top_legacy_partialscanned_block_height()
        };

    //import key image: enote 2 in block 1
    ASSERT_NO_THROW(enote_store.import_legacy_key_image(key_image_2, enote_2.m_onetime_address));

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 1);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 0);
    ASSERT_TRUE(enote_store.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 3);  //intermediate record promoted to full

    //legacy key image scan
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        true,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 1);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 0);
    ASSERT_TRUE(enote_store.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 3);

    //set fullscan height to saved intermediate height
    ASSERT_NO_THROW(enote_store.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle_2));

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 1);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 1);

    //block 2: spend enote 2
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {
                key_image_2
            },
            {}
        ));

    //intermediate scan (to read block 2)
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 2);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 1);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 1);

    //get intermediate height
    const std::uint64_t intermediate_height_pre_import_cycle_3{
            enote_store.get_top_legacy_partialscanned_block_height()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store.get_legacy_intermediate_records().size() == 0);

    //set fullscan height to saved intermediate height
    ASSERT_NO_THROW(enote_store.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle_3));

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 2);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 2);

    //pop block 2
    ledger_context.pop_blocks(1);

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 1);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 1);
    ASSERT_TRUE(enote_store.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);  //enote 2 is now unspent
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 3);

    //get intermediate height
    const std::uint64_t intermediate_height_pre_import_cycle_4{
            enote_store.get_top_legacy_partialscanned_block_height()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store.get_legacy_intermediate_records().size() == 0);

    //set fullscan height to saved intermediate height (this is redundant since the reorg only popped blocks)
    ASSERT_NO_THROW(enote_store.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle_4));

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 1);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 1);

    //make enote: 4 -> user
    LegacyEnoteV4 enote_3;
    rct::key enote_ephemeral_pubkey_3;
    crypto::key_image key_image_3;

    prepare_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        4,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_3,
        enote_ephemeral_pubkey_3,
        key_image_3);

    TxExtra tx_extra_3;
    append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_3
            },
            tx_extra_3
        );

    //block 2: 4 -> user, spend enote 1
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_3,
            {
                key_image_1
            },
            {
                enote_3
            }
        ));

    //full scan
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 2);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 2);
    ASSERT_TRUE(enote_store.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 6);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 6);

    //intermediate scan (this should have no effect right after a full scan)
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 2);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 2);
    ASSERT_TRUE(enote_store.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 6);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 6);

    //get intermediate height
    const std::uint64_t intermediate_height_pre_import_cycle_5{
            enote_store.get_top_legacy_partialscanned_block_height()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store.get_legacy_intermediate_records().size() == 0);

    //set fullscan height to saved intermediate height (should do nothing)
    ASSERT_NO_THROW(enote_store.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle_5));

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 2);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 2);

    //block 3: spend enote 3
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {
                key_image_3
            },
            {}
        ));

    //full scan
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 3);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 3);
    ASSERT_TRUE(enote_store.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 2);

    //pop block 3
    ledger_context.pop_blocks(1);

    //full scan
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 3);  //incorrect, must intermediate scan
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 2);
    ASSERT_TRUE(enote_store.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 6);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 6);

    //intermediate scan to fix height trackers (these can get messed up if doing both intermediate and full scans,
    //which will never be done in practice)
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store);

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 2);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 2);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 6);
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 6);

    //get intermediate height
    const std::uint64_t intermediate_height_pre_import_cycle_6{
            enote_store.get_top_legacy_partialscanned_block_height()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store.get_legacy_intermediate_records().size() == 0);

    //set fullscan height to saved intermediate height (should do nothing)
    ASSERT_NO_THROW(enote_store.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle_6));

    ASSERT_TRUE(enote_store.get_top_legacy_partialscanned_block_height() == 2);
    ASSERT_TRUE(enote_store.get_top_legacy_fullscanned_block_height() == 2);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_pre_transition_4)
{
    using namespace sp;

    /// setup

    // 1. config
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    // 2. user keys
    const crypto::secret_key legacy_spend_privkey{make_secret_key()};
    const crypto::secret_key legacy_view_privkey{make_secret_key()};
    const rct::key legacy_base_spend_pubkey{rct::scalarmultBase(rct::sk2rct(legacy_spend_privkey))};

    // 3. user normal address
   // const rct::key normal_addr_spendkey{legacy_base_spend_pubkey};
    //const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_view_privkey))};

    // 4. user subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    make_legacy_subaddress(legacy_base_spend_pubkey, legacy_view_privkey, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;


    /// test

    // 4. duplicate onetime addresses: same amounts
    MockLedgerContext ledger_context{10000, 10000};
    SpEnoteStoreMockV1 enote_store_int{0, 10000, 0};  //for view-only scanning
    SpEnoteStoreMockV1 enote_store_full{0, 10000, 0};  //for full scanning

    //make enote: 1 -> user (this will be reused throughout the test)
    LegacyEnoteV4 enote_1;
    rct::key enote_ephemeral_pubkey_1;
    crypto::key_image key_image_1;

    prepare_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        1,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_1,
        enote_ephemeral_pubkey_1,
        key_image_1);

    TxExtra tx_extra_1;
    append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_1
            },
            tx_extra_1
        );

    //block 0: enote 1-a
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                enote_1
            }
        ));

    //intermediate scan (don't import key image yet)
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);

    //block 1: enote 1-b
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                enote_1
            }
        ));

    //intermediate scan (don't import key image yet); should still be only 1 intermediate record, with origin height 0
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(
            enote_store_int.get_legacy_intermediate_records().begin()->second.m_origin_context.m_block_height == 0
        );
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 0);

    //full scan (separate enote store); balance should still be 1
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);

    //pop block 1
    ledger_context.pop_blocks(1);

    //intermediate scan: still one intermediate record for enote 1-a
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(
            enote_store_int.get_legacy_intermediate_records().begin()->second.m_origin_context.m_block_height == 0
        );
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 0);

    //get intermediate height
    const std::uint64_t intermediate_height_pre_import_cycle_1{
            enote_store_int.get_top_legacy_partialscanned_block_height()
        };

    //import key image: enote 1
    ASSERT_NO_THROW(enote_store_int.import_legacy_key_image(key_image_1, enote_1.m_onetime_address));

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 0);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == -1);
    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 1);  //intermediate record promoted to full

    //legacy key image scan
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        true,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 0);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == -1);
    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 1);

    //set fullscan height to saved intermediate height
    ASSERT_NO_THROW(enote_store_int.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle_1));

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 0);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == 0);

    //full scan
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);

    //block 1: enote 1-c
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                enote_1
            }
        ));

    //intermediate scan: no intermediate records
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 1);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == 0);
    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 1);

    //get intermediate height
    const std::uint64_t intermediate_height_pre_import_cycle_2{
            enote_store_int.get_top_legacy_partialscanned_block_height()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);

    //set fullscan height to saved intermediate height
    ASSERT_NO_THROW(enote_store_int.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle_2));

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 1);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == 1);

    //full scan
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);

    //pop block 1
    ledger_context.pop_blocks(1);

    //intermediate scan: still no intermediate records, balance still has enote 1-a
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 1);

    //get intermediate height
    const std::uint64_t intermediate_height_pre_import_cycle_3{
            enote_store_int.get_top_legacy_partialscanned_block_height()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);

    //set fullscan height to saved intermediate height
    ASSERT_NO_THROW(enote_store_int.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle_3));

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 0);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == 0);

    //full scan
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);

    //block 1: enote 1-d
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                enote_1
            }
        ));

    //intermediate scan: still no intermediate records, balance still has enote 1-a
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 1);

    //get intermediate height
    const std::uint64_t intermediate_height_pre_import_cycle_4{
            enote_store_int.get_top_legacy_partialscanned_block_height()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);

    //set fullscan height to saved intermediate height
    ASSERT_NO_THROW(enote_store_int.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle_4));

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 1);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == 1);

    //full scan
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);

    //block 2: spend enote 1
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {
                key_image_1
            },
            {}
        ));

    //intermediate scan: still no intermediate records, 0 balance now
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 0);

    //get intermediate height
    const std::uint64_t intermediate_height_pre_import_cycle_5{
            enote_store_int.get_top_legacy_partialscanned_block_height()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);

    //set fullscan height to saved intermediate height
    ASSERT_NO_THROW(enote_store_int.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle_5));

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 2);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == 2);

    //full scan
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_pre_transition_5)
{
    using namespace sp;

    /// setup

    // 1. config
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    // 2. user keys
    const crypto::secret_key legacy_spend_privkey{make_secret_key()};
    const crypto::secret_key legacy_view_privkey{make_secret_key()};
    const rct::key legacy_base_spend_pubkey{rct::scalarmultBase(rct::sk2rct(legacy_spend_privkey))};

    // 3. user normal address
    //const rct::key normal_addr_spendkey{legacy_base_spend_pubkey};
    //const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_view_privkey))};

    // 4. user subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    make_legacy_subaddress(legacy_base_spend_pubkey, legacy_view_privkey, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;


    /// test

    // 5. duplicate onetime addresses: different amounts
    MockLedgerContext ledger_context{10000, 10000};
    SpEnoteStoreMockV1 enote_store_int{0, 10000, 0};  //for view-only scanning
    SpEnoteStoreMockV1 enote_store_full{0, 10000, 0};  //for full scanning

    //make enotes: 1-a (amount 3), 1-b (amount 5), 1-c (amount 1), 1-d (amount 4)
    LegacyEnoteV4 enote_1a;
    LegacyEnoteV4 enote_1b;
    LegacyEnoteV4 enote_1c;
    LegacyEnoteV4 enote_1d;
    const crypto::secret_key enote_ephemeral_privkey{make_secret_key()};
    rct::key enote_ephemeral_pubkey;
    rct::key enote_ephemeral_pubkey_temp;
    crypto::key_image key_image;
    crypto::key_image key_image_temp;

    prepare_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        3,  //amount
        0,  //index in planned mock coinbase tx
        enote_ephemeral_privkey,
        enote_1a,
        enote_ephemeral_pubkey,
        key_image);

    prepare_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        5,  //amount
        0,  //index in planned mock coinbase tx
        enote_ephemeral_privkey,
        enote_1b,
        enote_ephemeral_pubkey_temp,
        key_image_temp);
    ASSERT_TRUE(enote_ephemeral_pubkey_temp == enote_ephemeral_pubkey);
    ASSERT_TRUE(key_image_temp == key_image);

    prepare_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        1,  //amount
        0,  //index in planned mock coinbase tx
        enote_ephemeral_privkey,
        enote_1c,
        enote_ephemeral_pubkey_temp,
        key_image_temp);
    ASSERT_TRUE(enote_ephemeral_pubkey_temp == enote_ephemeral_pubkey);
    ASSERT_TRUE(key_image_temp == key_image);

    prepare_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        4,  //amount
        0,  //index in planned mock coinbase tx
        enote_ephemeral_privkey,
        enote_1d,
        enote_ephemeral_pubkey_temp,
        key_image_temp);
    ASSERT_TRUE(enote_ephemeral_pubkey_temp == enote_ephemeral_pubkey);
    ASSERT_TRUE(key_image_temp == key_image);

    TxExtra tx_extra;
    append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey
            },
            tx_extra
        );

    //block 0: enote 1-a (amount 3)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra,
            {},
            {
                enote_1a
            }
        ));

    //intermediate scan (don't import key image yet)
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);

    //block 1: enote 1-b (amount 5)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra,
            {},
            {
                enote_1b
            }
        ));

    //intermediate scan (with key image import)
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 2);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 5);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 0);

    //get intermediate height
    const std::uint64_t intermediate_height_pre_import_cycle_1{
            enote_store_int.get_top_legacy_partialscanned_block_height()
        };

    //import key image: enote 1
    ASSERT_NO_THROW(enote_store_int.import_legacy_key_image(key_image, enote_1a.m_onetime_address));

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 1);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == -1);
    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 5);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 5);  //intermediate records promoted to full

    //legacy key image scan
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        true,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 1);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == -1);
    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 5);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 5);

    //set fullscan height to saved intermediate height
    ASSERT_NO_THROW(enote_store_int.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle_1));

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 1);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == 1);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 5);

    //pop block 1
    ledger_context.pop_blocks(1);

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 3);

    //get intermediate height
    const std::uint64_t intermediate_height_pre_import_cycle_2{
            enote_store_int.get_top_legacy_partialscanned_block_height()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);

    //set fullscan height to saved intermediate height
    ASSERT_NO_THROW(enote_store_int.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle_2));

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 0);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);

    //block 1: enote 1-c (amount 1)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra,
            {},
            {
                enote_1c
            }
        ));

    //block 2: enote 1-d (amount 4)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra,
            {},
            {
                enote_1d
            }
        ));

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 4);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 4);

    //get intermediate height
    const std::uint64_t intermediate_height_pre_import_cycle_3{
            enote_store_int.get_top_legacy_partialscanned_block_height()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);

    //set fullscan height to saved intermediate height
    ASSERT_NO_THROW(enote_store_int.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle_3));

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 2);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == 2);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 4);

    //block 3: spend enote 1
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {
                key_image
            },
            {}
        ));

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN}, {}) == 4);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 0);

    //get intermediate height
    const std::uint64_t intermediate_height_pre_import_cycle_4{
            enote_store_int.get_top_legacy_partialscanned_block_height()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);

    //set fullscan height to saved intermediate height
    ASSERT_NO_THROW(enote_store_int.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle_4));

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 3);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == 3);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN}, {}) == 4);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);

    //pop block 3
    ledger_context.pop_blocks(1);

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN}, {}) == 4);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 4);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE}) == 4);

    //get intermediate height
    const std::uint64_t intermediate_height_pre_import_cycle_5{
            enote_store_int.get_top_legacy_partialscanned_block_height()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);

    //set fullscan height to saved intermediate height
    ASSERT_NO_THROW(enote_store_int.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle_5));

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 2);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == 2);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN}, {}) == 4);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 4);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_pre_transition_6)
{
    using namespace sp;

    /// setup

    // 1. config
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    // 2. user keys
    const crypto::secret_key legacy_spend_privkey{make_secret_key()};
    const crypto::secret_key legacy_view_privkey{make_secret_key()};
    const rct::key legacy_base_spend_pubkey{rct::scalarmultBase(rct::sk2rct(legacy_spend_privkey))};

    // 3. user normal address
    //const rct::key normal_addr_spendkey{legacy_base_spend_pubkey};
    //const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_view_privkey))};

    // 4. user subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    make_legacy_subaddress(legacy_base_spend_pubkey, legacy_view_privkey, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;


    /// test

    // 6. locktime test 1: basic
    MockLedgerContext ledger_context{10000, 10000};
    SpEnoteStoreMockV1 enote_store_int{0, 10000, 2};  //for view-only scanning
    SpEnoteStoreMockV1 enote_store_full{0, 10000, 2};  //for full scanning

    //make enotes: enote 1, 2, 3
    LegacyEnoteV4 enote_1;
    LegacyEnoteV4 enote_2;
    LegacyEnoteV4 enote_3;
    rct::key enote_ephemeral_pubkey_1;
    rct::key enote_ephemeral_pubkey_2;
    rct::key enote_ephemeral_pubkey_3;
    crypto::key_image key_image_1;
    crypto::key_image key_image_2;
    crypto::key_image key_image_3;

    prepare_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        1,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_1,
        enote_ephemeral_pubkey_1,
        key_image_1);

    prepare_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        1,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_2,
        enote_ephemeral_pubkey_2,
        key_image_2);

    prepare_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        1,  //amount
        0,  //index in planned mock coinbase tx
        make_secret_key(),
        enote_3,
        enote_ephemeral_pubkey_3,
        key_image_3);

    TxExtra tx_extra_1;
    append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_1
            },
            tx_extra_1
        );
    TxExtra tx_extra_2;
    append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_2
            },
            tx_extra_2
        );
    TxExtra tx_extra_3;
    append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey_3
            },
            tx_extra_3
        );

    //block 0: enote 1 (unlock 0)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra_1,
            {},
            {
                enote_1
            }
        ));

    //intermediate scan (don't import key image yet)
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //enote 1 is locked
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE,
        EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //enote 1 is locked

    //block 1: enote 2 (unlock at block 3)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            3,
            tx_extra_2,
            {},
            {
                enote_2
            }
        ));

    //intermediate scan (don't import key image yet)
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 2);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 1);  //enote 1 is unlocked, enote 2 is locked
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE,
        EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 1);  //enote 1 is unlocked, enote 2 is locked

    //block 2: enote 3 (unlock at block 5)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            5,
            tx_extra_3,
            {},
            {
                enote_3
            }
        ));

    //intermediate scan (don't import key image yet)
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 3);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 2);  //enotes 1, 2 are unlocked, enote 3 is locked
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE,
        EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 2);  //enotes 1, 2 are unlocked, enote 3 is locked

    //block 3: empty
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {},
            {}
        ));

    //intermediate scan (don't import key image yet)
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 3);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 2);  //enotes 1, 2 are unlocked, enote 3 is locked
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE,
        EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 2);  //enotes 1, 2 are unlocked, enote 3 is locked

    //block 4: empty
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {},
            {}
        ));

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 3);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 3);  //enotes 1, 2, 3 are unlocked
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE,
        EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //get intermediate height
    const std::uint64_t intermediate_height_pre_import_cycle_1{
            enote_store_int.get_top_legacy_partialscanned_block_height()
        };

    //import key images: enotes 1, 2, 3
    ASSERT_NO_THROW(enote_store_int.import_legacy_key_image(key_image_1, enote_1.m_onetime_address));
    ASSERT_NO_THROW(enote_store_int.import_legacy_key_image(key_image_2, enote_2.m_onetime_address));
    ASSERT_NO_THROW(enote_store_int.import_legacy_key_image(key_image_3, enote_3.m_onetime_address));

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 4);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == -1);
    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 3);  //enotes 1, 2, 3 are unlocked
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE,
        EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 3);  //intermediate records promoted to full

    //legacy key image scan
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        true,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 4);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == -1);
    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 3);  //enotes 1, 2, 3 are unlocked
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE,
        EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 3);

    //set fullscan height to saved intermediate height
    ASSERT_NO_THROW(enote_store_int.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle_1));

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 4);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == 4);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 3);  //enotes 1, 2, 3 are unlocked
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_enote_scanning, legacy_pre_transition_7)
{
    using namespace sp;

    /// setup

    // 1. config
    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    // 2. user keys
    const crypto::secret_key legacy_spend_privkey{make_secret_key()};
    const crypto::secret_key legacy_view_privkey{make_secret_key()};
    const rct::key legacy_base_spend_pubkey{rct::scalarmultBase(rct::sk2rct(legacy_spend_privkey))};

    // 3. user normal address
    //const rct::key normal_addr_spendkey{legacy_base_spend_pubkey};
    //const rct::key normal_addr_viewkey{rct::scalarmultBase(rct::sk2rct(legacy_view_privkey))};

    // 4. user subaddress
    rct::key subaddr_spendkey;
    rct::key subaddr_viewkey;
    cryptonote::subaddress_index subaddr_index;

    make_legacy_subaddress(legacy_base_spend_pubkey, legacy_view_privkey, subaddr_spendkey, subaddr_viewkey, subaddr_index);

    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;
    legacy_subaddress_map[subaddr_spendkey] = subaddr_index;


    /// test

    // 7. locktime test 2: duplicate onetime addresses
    MockLedgerContext ledger_context{10000, 10000};
    SpEnoteStoreMockV1 enote_store_int{0, 10000, 2};  //for view-only scanning
    SpEnoteStoreMockV1 enote_store_full{0, 10000, 2};  //for full scanning

    //make enotes: 1-a (amount 1), 1-b (amount 2), 1-c (amount 3)
    LegacyEnoteV4 enote_1a;
    LegacyEnoteV4 enote_1b;
    LegacyEnoteV4 enote_1c;
    const crypto::secret_key enote_ephemeral_privkey{make_secret_key()};
    rct::key enote_ephemeral_pubkey;
    rct::key enote_ephemeral_pubkey_temp;
    crypto::key_image key_image;
    crypto::key_image key_image_temp;

    prepare_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        1,  //amount
        0,  //index in planned mock coinbase tx
        enote_ephemeral_privkey,
        enote_1a,
        enote_ephemeral_pubkey,
        key_image);

    prepare_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        2,  //amount
        0,  //index in planned mock coinbase tx
        enote_ephemeral_privkey,
        enote_1b,
        enote_ephemeral_pubkey_temp,
        key_image_temp);
    ASSERT_TRUE(enote_ephemeral_pubkey_temp == enote_ephemeral_pubkey);
    ASSERT_TRUE(key_image_temp == key_image);

    prepare_legacy_enote_for_transfer(subaddr_spendkey,
        subaddr_viewkey,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        3,  //amount
        0,  //index in planned mock coinbase tx
        enote_ephemeral_privkey,
        enote_1c,
        enote_ephemeral_pubkey_temp,
        key_image_temp);
    ASSERT_TRUE(enote_ephemeral_pubkey_temp == enote_ephemeral_pubkey);
    ASSERT_TRUE(key_image_temp == key_image);

    TxExtra tx_extra;
    append_legacy_enote_ephemeral_pubkeys_to_tx_extra(
            {
                enote_ephemeral_pubkey
            },
            tx_extra
        );

    //block 0: enote 1-a (amount 1; unlock 0)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra,
            {},
            {
                enote_1a
            }
        ));

    //intermediate scan (don't import key image yet)
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //enote 1a is locked
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE,
        EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //enote 1a is locked

    //block 1: empty
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {},
            {}
        ));

    //intermediate scan (don't import key image yet)
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 1);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 1);  //enote 1a is unlocked
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE,
        EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 1);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 1);  //enote 1a is unlocked

    //block 2: enote 1-b (amount 2; unlock 0)
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra,
            {},
            {
                enote_1b
            }
        ));

    //intermediate scan (don't import key image yet)
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 2);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //enote 1a is unlocked, 1b is locked (hides 1a)
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE,
        EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //enote 1a is unlocked, 1b is locked (hides 1a)

    //block 3: empty
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            TxExtra{},
            {},
            {}
        ));

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 2);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 2);  //enotes 1a, 1b are unlocked
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE,
        EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //get intermediate height
    const std::uint64_t intermediate_height_pre_import_cycle_1{
            enote_store_int.get_top_legacy_partialscanned_block_height()
        };

    //import key image: enote 1
    ASSERT_NO_THROW(enote_store_int.import_legacy_key_image(key_image, enote_1a.m_onetime_address));

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 3);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == -1);
    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 2);  //enotes 1a, 1b are unlocked
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE,
        EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 2);  //intermediate records promoted to full

    //legacy key image scan
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        true,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 3);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == -1);
    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 2);  //enotes 1a, 1b are unlocked
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE,
        EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 2);

    //set fullscan height to saved intermediate height
    ASSERT_NO_THROW(enote_store_int.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle_1));

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 3);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == 3);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 2);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 2);  //enotes 1a, 1b are unlocked

    //block 4: enote 1-c (amount 3; unlock 0), spend enote 1   (check balance with a locked and spent enote [enote 1-c])
    ASSERT_NO_THROW(ledger_context.add_legacy_coinbase(
            rct::pkGen(),
            0,
            tx_extra,
            {
                key_image
            },
            {
                enote_1c
            }
        ));

    //intermediate scan
    refresh_user_enote_store_legacy_intermediate(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        false,
        refresh_config,
        ledger_context,
        enote_store_int);

    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //enotes 1a, 1b, are unlocked, 1c is locked
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);
    ASSERT_TRUE(enote_store_int.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::LEGACY_INTERMEDIATE,
        EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);

    //get intermediate height
    const std::uint64_t intermediate_height_pre_import_cycle_2{
            enote_store_int.get_top_legacy_partialscanned_block_height()
        };

    //skip key image import + legacy key image scan (no intermediate records)
    ASSERT_TRUE(enote_store_int.get_legacy_intermediate_records().size() == 0);

    //set fullscan height to saved intermediate height
    ASSERT_NO_THROW(enote_store_int.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle_2));

    ASSERT_TRUE(enote_store_int.get_top_legacy_partialscanned_block_height() == 4);
    ASSERT_TRUE(enote_store_int.get_top_legacy_fullscanned_block_height() == 4);

    //full scan (separate enote store)
    refresh_user_enote_store_legacy_full(legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_spend_privkey,
        legacy_view_privkey,
        refresh_config,
        ledger_context,
        enote_store_full);

    ASSERT_TRUE(enote_store_full.get_legacy_intermediate_records().size() == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN}) == 3);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == 0);
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);  //enotes 1a, 1b are unlocked, 1c is locked
    ASSERT_TRUE(enote_store_full.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN},
        {EnoteStoreBalanceUpdateExclusions::ORIGIN_LEDGER_LOCKED}) == 0);
}
//-------------------------------------------------------------------------------------------------------------------

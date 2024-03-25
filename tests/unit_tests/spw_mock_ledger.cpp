// Copyright (c) 2014-2024, The Monero Project
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

#include <boost/filesystem/path.hpp>
#include <cstdint>
#include <gtest/gtest.h>
#include "seraphis_wallet/encrypted_file.h"
#include "unit_tests_utils.h"

#include "crypto/chacha.h"
#include "seraphis_core/binned_reference_set_utils.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_impl/enote_store_utils.h"
#include "seraphis_impl/serialization_demo_types.h"
#include "seraphis_impl/serialization_demo_utils.h"
#include "seraphis_wallet/address_utils.h"
#include "seraphis_wallet/key_container.h"
#include "seraphis_wallet/send_receive.h"
#include "unit_tests_utils.h"

// mocks
#include "seraphis_mocks/mock_ledger_context.h"
#include "seraphis_mocks/tx_fee_calculator_mocks.h"
#include "seraphis_mocks/tx_input_selector_mocks.h"
#include "seraphis_mocks/tx_validation_context_mock.h"

using namespace seraphis_wallet;

static void create_tx(KeyContainer &key_container, sp::SpEnoteStore &enote_store, sp::mocks::MockLedgerContext &ledger_context)
{
    JamtisDestinationV1 destination_address;
    JamtisAddressNetwork destination_network{JamtisAddressNetwork::MAINNET};
    JamtisAddressVersion destination_version{JamtisAddressVersion::V1};
    key_container.get_random_destination(destination_address);

    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{1};
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};
    const std::size_t legacy_ring_size{2};
    const sp::SpBinnedReferenceSetConfigV1 bin_config{.bin_radius = 1, .num_bin_members = 2};

    const sp::mocks::FeeCalculatorMockTrivial fee_calculator;  // just do a trivial calculator for now (fee = fee/weight * 1 weight)

    const sp::mocks::InputSelectorMockV1 input_selector{enote_store};

    const sp::scanning::ScanMachineConfig refresh_config{
        .reorg_avoidance_increment = 1, .max_chunk_size_hint = 1, .max_partialscan_attempts = 0};

    rct::xmr_amount amount{500};

    // b. add enough fake enotes to the ledger so we can reliably make seraphis membership proofs
    std::vector<rct::xmr_amount> fake_sp_enote_amounts(
            static_cast<std::size_t>(sp::compute_bin_width(bin_config.bin_radius)),
            0
        );

    sp::send_sp_coinbase_amounts_to_user({1000, 1000, 1000, 1000, 1000}, destination_address, destination_version, destination_network,ledger_context);

    refresh_user_enote_store(key_container.get_sp_keys(), refresh_config, ledger_context, enote_store);

    std::vector<rct::xmr_amount> fake_legacy_enote_amounts(128*static_cast<std::size_t>(legacy_ring_size), 0);
    const rct::key fake_legacy_spendkey{rct::pkGen()};
    const rct::key fake_legacy_viewkey{rct::pkGen()};
    // const rct::key fake_legacy_spendkey{key_container.get_legacy_keys().Ks};
    // const rct::key fake_legacy_viewkey{key_container.get_legacy_keys().Kv};

    sp::send_legacy_coinbase_amounts_to_user(fake_legacy_enote_amounts,
        fake_legacy_spendkey,
        fake_legacy_viewkey,
        ledger_context);


    rct::key legacy_subaddr_spendkey;
    rct::key legacy_subaddr_viewkey;
    cryptonote::subaddress_index legacy_subaddr_index;
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;

    gen_legacy_subaddress(key_container.get_legacy_keys().Ks,
        key_container.get_legacy_keys().k_v,
        legacy_subaddr_spendkey,
        legacy_subaddr_viewkey,
        legacy_subaddr_index);

    legacy_subaddress_map[legacy_subaddr_spendkey] = legacy_subaddr_index;

    sp::send_legacy_coinbase_amounts_to_user(
        {1000}, legacy_subaddr_spendkey, legacy_subaddr_viewkey, ledger_context);
    refresh_user_enote_store_legacy_full(key_container.get_legacy_keys().Ks,
        legacy_subaddress_map,
        key_container.get_legacy_keys().k_s,
        key_container.get_legacy_keys().k_v,
        refresh_config,
        ledger_context,
        enote_store);

    refresh_user_enote_store(key_container.get_sp_keys(), refresh_config, ledger_context, enote_store);

    sp::SpTxSquashedV1 single_tx{};
    std::vector<JamtisPaymentProposalV1> normal_payments;
    std::vector<JamtisPaymentProposalSelfSendV1> selfsend_payments;
    construct_tx_for_mock_ledger_v1(key_container.get_legacy_keys(),
        key_container.get_sp_keys(),
        input_selector,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{amount, sp::TxExtra{}, destination_address, destination_version, destination_network}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context,
        single_tx,
        selfsend_payments,
        normal_payments);

    // validate and submit to the mock ledger
    const sp::mocks::TxValidationContextMock tx_validation_context{ledger_context};
    CHECK_AND_ASSERT_THROW_MES(
        validate_tx(single_tx, tx_validation_context), "transfer funds single mock: validating tx failed.");
    CHECK_AND_ASSERT_THROW_MES(try_add_tx_to_ledger(single_tx, ledger_context),
        "transfer funds single mock: adding tx to mock ledger failed.");

    refresh_user_enote_store_legacy_full(key_container.get_legacy_keys().Ks,
        legacy_subaddress_map,
        key_container.get_legacy_keys().k_s,
        key_container.get_legacy_keys().k_v,
        refresh_config,
        ledger_context,
        enote_store);

    refresh_user_enote_store(key_container.get_sp_keys(), refresh_config, ledger_context, enote_store);

}

TEST(seraphis_wallet,mock_ledger)
{
    sp::mocks::MockLedgerContext ledger_context({0, 10000});
    sp::mocks::MockLedgerContext recovered_ledger_context({0, 10000});

    // 1. generate enote_store and tx_store
    sp::SpEnoteStore enote_store_A{0, 0, 0};

    // 2. create user keys
    KeyContainer kc_A;
    kc_A.generate_jamtis_and_legacy_keys();

    // 3. make some txs
    // for (int i = 0; i<5; i++)
    create_tx(kc_A, enote_store_A, ledger_context);

    // save MockLedger
    crypto::chacha_key key_ledger;
    crypto::generate_chacha_key("mockledger_password", key_ledger, 1);
    sp::mocks::ser_MockLedgerContext ser_mock_ledger;
    sp::mocks::make_serializable_mock_ledger_context(ledger_context, ser_mock_ledger);
    write_encrypted_file("mockledger", key_ledger, ser_mock_ledger);

    // load MockLedger
    crypto::chacha_key key;
    crypto::generate_chacha_key("mockledger_password", key, 1);
    bool exist_ledger;
    exist_ledger = boost::filesystem::exists("mockledger");
    if (exist_ledger)
    {
        sp::mocks::ser_MockLedgerContext ser_mock_ledger;
        read_encrypted_file("mockledger", key, ser_mock_ledger);
        sp::mocks::recover_mock_ledger_context(ser_mock_ledger, recovered_ledger_context);
    }

    EXPECT_TRUE(recovered_ledger_context.m_legacy_enote_references == ledger_context.m_legacy_enote_references);
    EXPECT_TRUE(recovered_ledger_context.m_sp_squashed_enotes == ledger_context.m_sp_squashed_enotes);
    EXPECT_TRUE(recovered_ledger_context.m_block_infos == ledger_context.m_block_infos);

    // TODO: Fix failing tests:
    // EXPECT_TRUE(recovered_ledger_context.m_blocks_of_tx_key_images == ledger_context.m_blocks_of_tx_key_images);
    // EXPECT_TRUE(recovered_ledger_context.m_blocks_of_legacy_tx_output_contents == ledger_context.m_blocks_of_legacy_tx_output_contents);
    // EXPECT_TRUE(recovered_ledger_context.m_blocks_of_sp_tx_output_contents == ledger_context.m_blocks_of_sp_tx_output_contents);

    // EXPECT_TRUE(recovered_ledger_context == ledger_context);
}

#include <boost/filesystem/path.hpp>
#include <cstdint>
#include <gtest/gtest.h>

#include "seraphis_core/binned_reference_set_utils.h"
#include "crypto/chacha.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_impl/enote_store_utils.h"
#include "seraphis_wallet/key_container.h"
#include "seraphis_wallet/send_receive.h"
#include "unit_tests_utils.h"

// mocks
#include "seraphis_mocks/mock_ledger_context.h"
#include "seraphis_mocks/tx_fee_calculator_mocks.h"
#include "seraphis_mocks/tx_input_selector_mocks.h"
#include "seraphis_mocks/tx_validation_context_mock.h"

using namespace seraphis_wallet;

static void create_tx(KeyContainer &key_container, SpEnoteStore &enote_store, mocks::MockLedgerContext &ledger_context)
{
    JamtisDestinationV1 destination_address;
    key_container.get_random_destination(destination_address);

    rct::xmr_amount amount{500};

    const scanning::ScanMachineConfig refresh_config{
        .reorg_avoidance_increment = 1, .max_chunk_size_hint = 1, .max_partialscan_attempts = 0};

    send_sp_coinbase_amounts_to_user({1000, 1000, 1000, 1000, 1000}, destination_address, ledger_context);

    refresh_user_enote_store(key_container.get_sp_keys(), refresh_config, ledger_context, enote_store);
    auto balance = get_balance(enote_store, {SpEnoteOriginStatus::ONCHAIN}, {SpEnoteSpentStatus::SPENT_ONCHAIN});

    const sp::mocks::FeeCalculatorMockTrivial
        fee_calculator;  // just do a trivial calculator for now (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{.bin_radius = 1, .num_bin_members = 2};

    const sp::mocks::InputSelectorMockV1 input_selector{enote_store};

    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{1};
    const std::size_t legacy_ring_size{2};
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    //  make sure to have enough fake enotes to the ledger so we can reliably
    //  make seraphis membership proofs
    std::vector<rct::xmr_amount> fake_sp_enote_amounts(
        static_cast<std::size_t>(compute_bin_width(bin_config.bin_radius)), 0);

    SpTxSquashedV1 single_tx;
    construct_tx_for_mock_ledger_v1(key_container.get_legacy_keys(),
        key_container.get_sp_keys(),
        input_selector,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{amount, destination_address, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context,
        single_tx);

    // validate and submit to the mock ledger
    const sp::mocks::TxValidationContextMock tx_validation_context{ledger_context};
    CHECK_AND_ASSERT_THROW_MES(
        validate_tx(single_tx, tx_validation_context), "transfer funds single mock: validating tx failed.");
    CHECK_AND_ASSERT_THROW_MES(try_add_tx_to_ledger(single_tx, ledger_context),
        "transfer funds single mock: adding tx to mock ledger failed.");

    refresh_user_enote_store(key_container.get_sp_keys(), refresh_config, ledger_context, enote_store);
}

TEST(seraphis_wallet, store_and_load_enote_store)
{
    // 1. create variables, set password and path
    KeyContainer kc_all{},kc_all_recovered{},kc_vo{},kc_vb{};
    SpEnoteStore enote_store{0,0,0};
    sp::mocks::MockLedgerContext ledger_context{0, 10000};
    crypto::chacha_key chacha_key;
    const uint64_t kdf_rounds = 1;
    const epee::wipeable_string password = "password";

    // 2. generate chacha_key and keys of container
    crypto::generate_chacha_key(password.data(),password.length(),chacha_key,kdf_rounds);
    kc_all.generate_keys();

    // 3. create txs
    create_tx(kc_all, enote_store, ledger_context);

    // 4. serialize enote_store

    // 5. save enote_store to file

    // 6. load enote_store from file

    // 7. deserialize

    // 8. compare if they are equal
}
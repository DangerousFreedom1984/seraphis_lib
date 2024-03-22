#include <boost/filesystem/path.hpp>
#include <cstdint>
#include <gtest/gtest.h>

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
using namespace sp;

static void create_tx(KeyContainer &key_container, SpEnoteStore &enote_store, mocks::MockLedgerContext &ledger_context)
{
    JamtisDestinationV1 destination_address;
    JamtisAddressNetwork destination_network{JamtisAddressNetwork::MAINNET};
    JamtisAddressVersion destination_version{JamtisAddressVersion::V1};
    key_container.get_random_destination(destination_address);

    rct::xmr_amount amount{500};

    const scanning::ScanMachineConfig refresh_config{
        .reorg_avoidance_increment = 1, .max_chunk_size_hint = 1, .max_partialscan_attempts = 0};

    send_sp_coinbase_amounts_to_user({1000, 1000, 1000, 1000, 1000}, destination_address, destination_version, destination_network,ledger_context);

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
    std::vector<JamtisPaymentProposalV1> normal_payments;
    std::vector<JamtisPaymentProposalSelfSendV1> selfsend_payments;
    construct_tx_for_mock_ledger_v1(key_container.get_legacy_keys(),
        key_container.get_sp_keys(),
        input_selector,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{amount, TxExtra{}, destination_address, destination_version, destination_network}},
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

    refresh_user_enote_store(key_container.get_sp_keys(), refresh_config, ledger_context, enote_store);
}

TEST(seraphis_wallet, store_and_load_enote_store)
{
    // 1. generate enote_store and tx_store
    SpEnoteStore enote_store_A{0, 0, 0};
    sp::mocks::MockLedgerContext ledger_context{0, 10000};

    // 2. create user keys
    KeyContainer kc_A;
    kc_A.generate_keys();

    // 3. make some txs
    for (int i = 0; i<5; i++)
        create_tx(kc_A, enote_store_A, ledger_context);

    // 4. get all enote records
    std::vector<SpContextualEnoteRecordV1> all_enote_records;
    all_enote_records.reserve(enote_store_A.sp_records().size());

    for (const auto &enote_record : enote_store_A.sp_records())
        all_enote_records.push_back(enote_record.second);

    // 5. serialize enote record
    sp::serialization::ser_SpContextualEnoteRecordV1 ser_sp_contextual_record;
    make_serializable_sp_contextual_enote_record_v1(all_enote_records[0], ser_sp_contextual_record);

    // 6. get string
    std::string str_serialized_sp_contextual_record;
    try_append_serializable(ser_sp_contextual_record, str_serialized_sp_contextual_record);

    // 6. recover from string
    sp::serialization::ser_SpContextualEnoteRecordV1 ser_recovered_serializable_enote_record;
    try_get_serializable(epee::strspan<std::uint8_t>(str_serialized_sp_contextual_record), ser_recovered_serializable_enote_record);

    // 7. recover enote record
    SpContextualEnoteRecordV1 recovered_enote_record;
    recover_sp_contextual_enote_record_v1(ser_recovered_serializable_enote_record, recovered_enote_record);

    // 8. test if contextual records are the same
    EXPECT_TRUE(recovered_enote_record == all_enote_records[0]);

    // 9. serialize enote_store
    sp::serialization::ser_SpEnoteStore ser_enote_store;
    make_serializable_sp_enote_store(enote_store_A, ser_enote_store);

    // 10. write serializable into str
    std::string str_serialized_enote_store;
    try_append_serializable(ser_enote_store, str_serialized_enote_store);

    // 11. recover serializable from str
    sp::serialization::ser_SpEnoteStore recovered_serializable;
    try_get_serializable(epee::strspan<std::uint8_t>(str_serialized_enote_store), recovered_serializable);

    // 12. recover struct from serializable
    SpEnoteStore recovered_enote_store{0, 0, 0};
    recover_sp_enote_store(recovered_serializable, recovered_enote_store);
    EXPECT_TRUE(recovered_enote_store==enote_store_A);
}

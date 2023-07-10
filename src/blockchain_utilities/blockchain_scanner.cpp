// Copyright (c) 2014-2023, The Monero Project
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
// 

#include <stdio.h>

#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <cstdint>
#include <thread>
#include <unordered_map>

#include "async/threadpool.h"
#include "common/command_line.h"
#include "common/varint.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/subaddress_index.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/tx_pool.h"
#include "seraphis_core/legacy_core_utils.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_impl/enote_store_utils.h"
#include "seraphis_impl/scan_context_simple.h"
#include "seraphis_impl/scan_process_basic.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/scan_machine_types.h"
#include "seraphis_mocks/enote_finding_context_mocks.h"
#include "seraphis_mocks/scan_chunk_consumer_mocks.h"
#include "seraphis_mocks/scan_context_async_mock.h"
#include "seraphis_wallet/legacy_knowledge_proofs.h"
#include "version.h"

// wallet2 dependencies
#include "common/scoped_message_writer.h"
#include "mnemonics/electrum-words.h"
#include "mnemonics/english.h"
#include "wallet/wallet2.h"
#include "wipeable_string.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "bcutil"

const std::string DEFAULT_WALLET_FILE = "monero_blockchain_scanner_test_wallet_file";

const std::uint64_t DEFAULT_LOOP_COUNT = 1;

namespace po = boost::program_options;
using namespace epee;
using namespace cryptonote;

class Wallet2Callback : public tools::i_wallet2_callback
{
   public:
    Wallet2Callback(tools::wallet2 &wallet2, std::chrono::milliseconds &scanner_duration)
        : m_refresh_progress_reporter(wallet2), m_scanner_duration(scanner_duration)
    {
    }

    virtual void on_new_block(uint64_t height, const cryptonote::block &block)
    {
        m_refresh_progress_reporter.update(height);
    }

    virtual void on_scanner_complete(std::chrono::milliseconds duration) { m_scanner_duration = duration; }

   private:
    friend class refresh_progress_reporter_t;

    class refresh_progress_reporter_t
    {
       public:
        refresh_progress_reporter_t(tools::wallet2 &wallet2)
            : m_wallet2(wallet2), m_blockchain_height(0), m_blockchain_height_update_time(), m_print_time()
        {
        }

        void update(uint64_t height, bool force = false)
        {
            auto current_time = std::chrono::system_clock::now();
            const auto node_update_threshold = std::chrono::seconds(DIFFICULTY_TARGET_V1 / 2);  // use min of V1/V2
            if (node_update_threshold < current_time - m_blockchain_height_update_time || m_blockchain_height <= height)
            {
                update_blockchain_height();
                m_blockchain_height = (std::max)(m_blockchain_height, height);
            }

            if (std::chrono::milliseconds(20) < current_time - m_print_time || force)
            {
                std::cout << QT_TRANSLATE_NOOP("blockchain_scanner", "Height ") << height << " / "
                          << m_blockchain_height << '\r' << std::flush;
                m_print_time = current_time;
            }
        }

       private:
        void update_blockchain_height()
        {
            std::string err;
            uint64_t blockchain_height = m_wallet2.get_daemon_blockchain_height(err);
            if (err.empty())
            {
                m_blockchain_height = blockchain_height;
                m_blockchain_height_update_time = std::chrono::system_clock::now();
            }
            else
            {
                LOG_ERROR("Failed to get current blockchain height: " << err);
            }
        }

       private:
        tools::wallet2 &m_wallet2;
        uint64_t m_blockchain_height;
        std::chrono::system_clock::time_point m_blockchain_height_update_time;
        std::chrono::system_clock::time_point m_print_time;
    };

   private:
    refresh_progress_reporter_t m_refresh_progress_reporter;
    std::chrono::milliseconds &m_scanner_duration;
};

void add_default_subaddresses(const rct::key &legacy_base_spend_pubkey, const crypto::secret_key &legacy_view_privkey,
                              std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map)
{
    const uint32_t SUBADDR_MAJOR_DEFAULT_LOOKAHEAD = 50;
    const uint32_t SUBADDR_MINOR_DEFAULT_LOOKAHEAD = 200;

    for (uint32_t i = 0; i < SUBADDR_MAJOR_DEFAULT_LOOKAHEAD; ++i)
    {
        for (uint32_t j = 0; j < SUBADDR_MINOR_DEFAULT_LOOKAHEAD; ++j)
        {
            const cryptonote::subaddress_index subaddr_index{i, j};

            rct::key legacy_subaddress_spendkey;
            sp::make_legacy_subaddress_spendkey(legacy_base_spend_pubkey, legacy_view_privkey, subaddr_index,
                                                hw::get_device("default"), legacy_subaddress_spendkey);

            legacy_subaddress_map[legacy_subaddress_spendkey] = subaddr_index;
        }
    }
};

void initialize_connection_pool(sp::mocks::EnoteFindingContextMockLegacy &enote_finding_context,
                                const uint64_t init_connection_pool_size, const std::string daemon_address,
                                const epee::net_utils::ssl_options_t ssl_support)
{
    async::Threadpool &threadpool{async::get_default_threadpool()};

    // 1. make join signal
    auto join_signal = threadpool.make_join_signal();

    // 2. get join token
    auto join_token = threadpool.get_join_token(join_signal);

    // 3. submit tasks to join on
    for (size_t i = 0; i < init_connection_pool_size; ++i)
    {
        // initialize http client and grab a lock for the client at that index
        CHECK_AND_ASSERT_THROW_MES(enote_finding_context.http_client_index() == i, "unexpected http client index");

        threadpool.submit(async::make_simple_task(
            async::DefaultPriorityLevels::MEDIUM,
            [&threadpool, &enote_finding_context, i, daemon_address, ssl_support, join_token]() -> async::TaskVariant
            {
                async::fanout_token_t fanout_token{threadpool.launch_temporary_worker()};

                CHECK_AND_ASSERT_THROW_MES(!enote_finding_context.m_http_clients[i]->is_connected(),
                                           "http client already connected");
                CHECK_AND_ASSERT_THROW_MES(
                    enote_finding_context.m_http_clients[i]->set_server(
                        daemon_address, boost::optional<epee::net_utils::http::login>(), ssl_support),
                    "failed to set server");
                CHECK_AND_ASSERT_THROW_MES(enote_finding_context.m_http_clients[i]->connect(std::chrono::seconds(30)),
                                           "http client failed to connect");
                CHECK_AND_ASSERT_THROW_MES(enote_finding_context.m_http_clients[i]->is_connected(),
                                           "http client is not connected");

                // make sure RPC version matches and make sure connection is
                // initialized by making first request
                cryptonote::COMMAND_RPC_GET_VERSION::request req_t = AUTO_VAL_INIT(req_t);
                cryptonote::COMMAND_RPC_GET_VERSION::response resp_t = AUTO_VAL_INIT(resp_t);
                bool r = epee::net_utils::invoke_http_json_rpc("/json_rpc", "get_version", req_t, resp_t,
                                                               *enote_finding_context.m_http_clients[i]);
                CHECK_AND_ASSERT_THROW_MES(r && resp_t.status == CORE_RPC_STATUS_OK, "failed /get_version");
                CHECK_AND_ASSERT_THROW_MES(
                    resp_t.version >= MAKE_CORE_RPC_VERSION(CORE_RPC_VERSION_MAJOR, CORE_RPC_VERSION_MINOR),
                    "unexpected daemon version (must be running an updated daemon "
                    "for accurate benchmarks)");

                return boost::none;
            }));
    }

    // 4. get join condition
    auto join_condition = threadpool.get_join_condition(std::move(join_signal), std::move(join_token));

    // 5. join the tasks
    threadpool.work_while_waiting(std::move(join_condition));

    // release all http client locks
    for (size_t i = 0; i < init_connection_pool_size; ++i) enote_finding_context.release_http_client(i);
}

std::chrono::milliseconds scan_chain(
    const uint64_t start_height, const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey, const crypto::secret_key &legacy_spend_privkey,
    const std::string daemon_address, const epee::net_utils::ssl_options_t ssl_support,
    sp::SpEnoteStore &user_enote_store)
{
    const sp::scanning::ScanMachineConfig scan_config{
        .reorg_avoidance_increment = 1, .max_chunk_size_hint = 1000, .max_partialscan_attempts = 0};

    sp::mocks::EnoteFindingContextMockLegacy enote_finding_context{legacy_base_spend_pubkey, legacy_subaddress_map,
                                                                   legacy_view_privkey, daemon_address, ssl_support};

    const uint64_t pending_chunk_queue_size =
        std::min((std::uint64_t)(std::thread::hardware_concurrency() + 2), static_cast<std::uint64_t>(10));
    LOG_PRINT_L0("Pending chunk queue size: " << pending_chunk_queue_size);

    // initialize a connection pool
    // TODO: implement ability to make concurrent network requests via http lib
    // and remove need for connection pool
    LOG_PRINT_L0("Initializing connection pool...");
    const uint64_t init_connection_pool_size = pending_chunk_queue_size * 15 / 10;
    initialize_connection_pool(enote_finding_context, init_connection_pool_size, daemon_address, ssl_support);

    sp::scanning::mocks::AsyncScanContext scan_context_ledger{
        pending_chunk_queue_size,  // TODO: stick this in scan conifg
        scan_config.max_chunk_size_hint, enote_finding_context};

    sp::mocks::ChunkConsumerMockLegacy chunk_consumer{legacy_base_spend_pubkey, legacy_spend_privkey,
                                                      legacy_view_privkey, user_enote_store};

    sp::scanning::ScanContextNonLedgerDummy scan_context_nonledger{};

    LOG_PRINT_L0("Scanning using the updated Seraphis lib...");
    auto start = std::chrono::high_resolution_clock::now();

    if (!sp::refresh_enote_store(scan_config, scan_context_nonledger, scan_context_ledger, chunk_consumer))
    {
        throw std::runtime_error("Failed to refresh enote store");
    };

    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);

    return duration;
    // return sp::get_balance(user_enote_store,
    //       {sp::SpEnoteOriginStatus::ONCHAIN,
    //       sp::SpEnoteOriginStatus::UNCONFIRMED},
    //       {sp::SpEnoteSpentStatus::SPENT_ONCHAIN,
    //       sp::SpEnoteSpentStatus::SPENT_UNCONFIRMED}).str();
}

int main(int argc, char *argv[])
{
    TRY_ENTRY();

    epee::string_tools::set_module_name_and_folder(argv[0]);

    uint32_t log_level = 0;

    tools::on_startup();

    boost::filesystem::path output_file_path;

    po::options_description desc_cmd_only("Command line options");
    po::options_description desc_cmd_sett("Command line options and settings options");
    const command_line::arg_descriptor<std::string> arg_log_level = {"log-level", "0-4 or categories", ""};
    const command_line::arg_descriptor<std::string> arg_daemon_address = {"daemon-address",
                                                                          "Use daemon instance at <host>:<port>", ""};
    const command_line::arg_descriptor<std::uint64_t> arg_start_height = {"start-height", "Scan from height", 0};
    const command_line::arg_descriptor<std::uint64_t> arg_loop_count = {"loop-count", "Attempt to scan this many times",
                                                                        DEFAULT_LOOP_COUNT};

    command_line::add_arg(desc_cmd_sett, cryptonote::arg_testnet_on);
    command_line::add_arg(desc_cmd_sett, cryptonote::arg_stagenet_on);
    command_line::add_arg(desc_cmd_sett, arg_log_level);
    command_line::add_arg(desc_cmd_sett, arg_daemon_address);
    command_line::add_arg(desc_cmd_sett, arg_start_height);
    command_line::add_arg(desc_cmd_sett, arg_loop_count);
    command_line::add_arg(desc_cmd_only, command_line::arg_help);

    po::options_description desc_options("Allowed options");
    desc_options.add(desc_cmd_only).add(desc_cmd_sett);

    po::variables_map vm;
    bool r = command_line::handle_error_helper(desc_options,
                                               [&]()
                                               {
                                                   auto parser =
                                                       po::command_line_parser(argc, argv).options(desc_options);
                                                   po::store(parser.run(), vm);
                                                   po::notify(vm);
                                                   return true;
                                               });
    if (!r) return 1;

    if (command_line::get_arg(vm, command_line::arg_help))
    {
        std::cout << "Monero '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")" << ENDL << ENDL;
        std::cout << desc_options << std::endl;
        return 1;
    }

    mlog_configure(mlog_get_default_log_path("monero-blockchain-scanner.log"), true);
    if (!command_line::is_arg_defaulted(vm, arg_log_level))
        mlog_set_log(command_line::get_arg(vm, arg_log_level).c_str());
    else
        mlog_set_log(std::string(std::to_string(log_level) + ",bcutil:INFO").c_str());

    std::string daemon_address;
    if (command_line::is_arg_defaulted(vm, arg_daemon_address))
        throw std::runtime_error("Missing daemon address");
    else
        daemon_address = command_line::get_arg(vm, arg_daemon_address);

    std::uint64_t start_height = 0;
    if (!command_line::is_arg_defaulted(vm, arg_start_height))
        start_height = command_line::get_arg(vm, arg_start_height);

    if (boost::filesystem::exists(DEFAULT_WALLET_FILE))
    {
        std::remove(DEFAULT_WALLET_FILE.c_str());
        std::remove((DEFAULT_WALLET_FILE + ".keys").c_str());
    }

    std::uint64_t loop_count = DEFAULT_LOOP_COUNT;
    if (!command_line::is_arg_defaulted(vm, arg_loop_count)) loop_count = command_line::get_arg(vm, arg_loop_count);
    if (loop_count == 0) loop_count = DEFAULT_LOOP_COUNT;

    LOG_PRINT_L0("Starting... (loop_count=" << loop_count << ")");

    bool opt_testnet = command_line::get_arg(vm, cryptonote::arg_testnet_on);
    bool opt_stagenet = command_line::get_arg(vm, cryptonote::arg_stagenet_on);
    network_type net_type = opt_testnet ? TESTNET : opt_stagenet ? STAGENET : MAINNET;

    // TODO: allow user to securely input seed manually (make sure I password
    // protect the file wallet2 generates)
    const std::string mnemonic =
        "timber stunning intended swept shrugged spout summon sonic wonders "
        "ionic fleet request vortex people addicted directed opacity eight bugs "
        "isolated camp meeting succeed sugar eight";
    const std::string priv_spend_key = "7592b09b6e6d720995317c2e26ca316a68a23e5d64de54a060d129b717f8ac00";
    const std::string pub_spend_key = "567329349ba22e5e4726edeba0c639a1e0751223190e6a522aad5f7fa4925435";
    const std::string priv_view_key = "932e483aff2f027dc61f7706981285002d6481fbba27f8d3e0047a9a699d7705";

    crypto::secret_key legacy_spend_privkey;
    crypto::public_key legacy_base_spend_pubkey_t;
    rct::key legacy_base_spend_pubkey;
    epee::string_tools::hex_to_pod(priv_spend_key, legacy_spend_privkey);
    crypto::secret_key_to_public_key(legacy_spend_privkey, legacy_base_spend_pubkey_t);
    legacy_base_spend_pubkey = rct::pk2rct(legacy_base_spend_pubkey_t);
    /// view key
    crypto::secret_key legacy_view_privkey;
    epee::string_tools::hex_to_pod(priv_view_key, legacy_view_privkey);
    crypto::public_key legacy_view_pubkey;
    crypto::secret_key_to_public_key(legacy_view_privkey, legacy_view_pubkey);
    rct::key legacy_base_view_pubkey;
    legacy_base_view_pubkey = rct::pk2rct(legacy_view_pubkey);

    /// subaddresses
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map{};
    add_default_subaddresses(legacy_base_spend_pubkey, legacy_view_privkey, legacy_subaddress_map);

    /// EnoteStore
    sp::SpEnoteStore user_enote_store{start_height == 0 ? 1 : start_height, 3000000, 10};

    std::vector<std::chrono::milliseconds> seraphis_lib_results;
    std::vector<std::chrono::milliseconds> wallet2_results;

    seraphis_lib_results.reserve(loop_count);
    wallet2_results.reserve(loop_count);

    for (std::uint64_t i = 0; i < loop_count; ++i)
    {
        LOG_PRINT_L0("Starting loop " << i + 1 << " / " << loop_count);

        // wallet2
        LOG_PRINT_L0("Initalizing the wallet2 client...");
        std::unique_ptr<tools::wallet2> wallet2 = std::unique_ptr<tools::wallet2>(
            new tools::wallet2(static_cast<cryptonote::network_type>(net_type), 1, true));

        crypto::secret_key recovery_key;
        std::string language = Language::English().get_language_name();
        if (!crypto::ElectrumWords::words_to_bytes(mnemonic, recovery_key, language))
            throw std::runtime_error("Invalid mnemonic");
        wallet2->set_seed_language(language);

        wallet2->set_refresh_from_block_height(start_height);
        wallet2->set_daemon(daemon_address);
        // TODO: allow user to password protect entered seed
        wallet2->generate(DEFAULT_WALLET_FILE, "", recovery_key, true, false, false);

        // set callback to print progress
        std::chrono::milliseconds wallet2_duration;
        std::unique_ptr<Wallet2Callback> wallet2_callback =
            std::unique_ptr<Wallet2Callback>(new Wallet2Callback(*wallet2, wallet2_duration));
        wallet2->callback(wallet2_callback.get());

        // start scanning using wallet2
        LOG_PRINT_L0("Scanning using wallet2...");
        wallet2->refresh(true);
        LOG_PRINT_L0("Time to scan using wallet2: " << wallet2_duration.count() << "ms");
        if (i == 0)
        {
            LOG_PRINT_L0(
                "Warning: sometimes the first scan attempt is slower than "
                "the subsequent attempts because "
                << "the daemon is spending most of its time reading blocks "
                   "from the database.");
            // To reproduce this slow first attempt, restart the machine the daemon is
            // running on and rescan. It appears the blocks read from the db are
            // getting cached in memory for subsequent scan attempts.
            // TODO: investigate this further
        }

        wallet2_results.push_back(std::move(wallet2_duration));

        std::remove(DEFAULT_WALLET_FILE.c_str());
        std::remove((DEFAULT_WALLET_FILE + ".keys").c_str());
        // end wallet2

        // seraphis lib
        LOG_PRINT_L0("Initializing the client using the updated Seraphis lib...");
        auto seraphis_lib_duration = scan_chain(
            start_height, legacy_base_spend_pubkey, legacy_subaddress_map, legacy_view_privkey, legacy_spend_privkey,
            daemon_address, epee::net_utils::ssl_support_t::e_ssl_support_autodetect, user_enote_store);
        LOG_PRINT_L0("Time to scan using the updated Seraphis lib: " << seraphis_lib_duration.count() << "ms");
        seraphis_lib_results.push_back(std::move(seraphis_lib_duration));
        // end seraphis lib
    }

    // Get legacy spend_proof
    crypto::hash txid;
    std::string txid_str = "e4f0a15057f8961b13b8e9e024e4c3c856dc912bc7e62a3012e22b075135eb79";
    std::string message{};

    epee::string_tools::hex_to_pod(txid_str, txid);

    std::string spend_proof_str{};

    spend_proof_str = generate_legacy_spend_proof(message, txid, legacy_spend_privkey, user_enote_store);

    if (check_legacy_spend_proof(txid, message, spend_proof_str))
        std::cout << "Spend_Proof signature is valid" << std::endl;

    /// Get legacy InProof
    // Get info of is_subaddress
    //   cryptonote::address_parse_info info;
    crypto::hash txid_inproof;
    std::string txid_inproof_str = "e139cc0cc1f9e1ed7d1a7adafd3558a83618c98d85190940f1d727cc0015248c";
    std::string message_inproof{};

    epee::string_tools::hex_to_pod(txid_inproof_str, txid_inproof);
    std::string inproof_str = generate_legacy_inproof(txid_inproof, legacy_base_spend_pubkey, legacy_base_view_pubkey,
                                                      legacy_view_privkey, false, message_inproof);

    std::uint64_t received_inproof;
    std::uint64_t confirmations_inproof;
    bool in_pool_inproof;
    cryptonote::account_public_address address_inproof{rct::rct2pk(legacy_base_spend_pubkey),
                                                       rct::rct2pk(legacy_base_view_pubkey)};

    bool valid_inproof = check_tx_proof(txid_inproof, address_inproof, false, message_inproof, inproof_str,
                                        received_inproof, in_pool_inproof, confirmations_inproof);

    if (valid_inproof)
        std::cout << "InProof signature is valid. "
                  << "Confirmations: " << confirmations_inproof << std::endl;
    else
        std::cout << "InProof signature is not valid." << std::endl;

    std::sort(seraphis_lib_results.begin(), seraphis_lib_results.end());
    std::sort(wallet2_results.begin(), wallet2_results.end());

    // print final results
    LOG_PRINT_L0("**********************************************************************");
    std::chrono::milliseconds min_seraphis_lib_duration = seraphis_lib_results[0];
    std::chrono::milliseconds min_wallet2_duration = wallet2_results[0];

    if (min_wallet2_duration > min_seraphis_lib_duration)
    {
        auto percent_diff =
            (min_wallet2_duration.count() - min_seraphis_lib_duration.count()) / (double)min_wallet2_duration.count();
        LOG_PRINT_L0("Success!");
        LOG_PRINT_L0("The updated Seraphis lib was " << percent_diff * 100 << "\% faster than wallet2\n");
    }
    else
    {
        auto percent_diff =
            (min_seraphis_lib_duration.count() - min_wallet2_duration.count()) / (double)min_wallet2_duration.count();
        LOG_PRINT_L0("Unexpected result...");
        LOG_PRINT_L0("The updated Seraphis lib was " << percent_diff * 100 << "\% slower than wallet2\n");
    }

    if (loop_count > 1)
    {
        LOG_PRINT_L0("Updated Seraphis lib (min):   " << min_seraphis_lib_duration.count() << "ms");
        LOG_PRINT_L0("wallet2              (min):   " << min_wallet2_duration.count() << "ms");

        auto median_wallet2_result = wallet2_results[loop_count / 2];
        auto median_seraphis_lib_result = seraphis_lib_results[loop_count / 2];

        LOG_PRINT_L0("Updated Seraphis lib (median):   " << median_seraphis_lib_result.count() << "ms");
        LOG_PRINT_L0("wallet2              (median):   " << median_wallet2_result.count() << "ms");
    }
    else
    {
        LOG_PRINT_L0("Updated Seraphis lib:   " << min_seraphis_lib_duration.count() << "ms");
        LOG_PRINT_L0("wallet2             :   " << min_wallet2_duration.count() << "ms");
    }
    LOG_PRINT_L0(
        "**********************************************************************");

    LOG_PRINT_L0("Blockchain scanner complete");
    return 0;

    CATCH_ENTRY("Scanner error", 1);
}

// Copyright (c) 2024, The Monero Project
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

// paired header
#include "wallet3.h"
#include <boost/multiprecision/cpp_int.hpp>
#include <cstdint>

// local headers
#include "address_utils.h"
#include "common/i18n.h"
#include "common/command_line.h"
#include "common/password.h"
#include "common/scoped_message_writer.h"
#include "console_handler.h"
#include "crypto/chacha.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/account.h"
#include "key_container.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "send_receive.h"
#include "seraphis_core/binned_reference_set_utils.h"
#include "seraphis_core/jamtis_enote_utils.h"
#include "seraphis_impl/enote_store_utils.h"
#include "seraphis_impl/serialization_demo_utils.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/sp_knowledge_proof_utils.h"
#include "seraphis_mocks/mock_ledger_context.h"
#include "seraphis_wallet/encrypted_file.h"
#include "seraphis_wallet/serialization_types.h"
#include "seraphis_wallet/show_enotes.h"
#include "seraphis_wallet/sp_knowledge_proofs.h"
#include "seraphis_wallet/transaction_history.h"
#include "string_tools.h"
#include "wallet/wallet2_basic/wallet2_storage.h"

// seraphis lib
#include "seraphis_impl/enote_store.h"
#include "seraphis_main/scan_machine_types.h"
#include "seraphis_wallet/address_utils.h"

// seraphis mocks - to be deleted
#include "seraphis_mocks/tx_fee_calculator_mocks.h"
#include "seraphis_mocks/tx_input_selector_mocks.h"
#include "seraphis_mocks/tx_validation_context_mock.h"
extern "C"
{
#include "crypto/crypto-ops.h"
#include "crypto/keccak.h"
}

// standard headers
#include <openssl/pem.h>

#include <boost/algorithm/string.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/format.hpp>
#include <boost/format/format_fwd.hpp>
#include <iostream>
#include <string>
#include <vector>

// use boost bind placeholders for now
#define BOOST_BIND_GLOBAL_PLACEHOLDERS 1
#include <boost/bind.hpp>

#ifdef WIN32
#include <boost/locale.hpp>
#include <boost/filesystem.hpp>
#include <fcntl.h>
#endif

#ifdef HAVE_READLINE
#include "readline_buffer.h"
#endif

using namespace epee;
using namespace std;
using namespace sp;
using namespace sp::jamtis;

#define LOCK_IDLE_SCOPE()                                                                                        \
    bool auto_refresh_enabled = m_auto_refresh_enabled.load(std::memory_order_relaxed);                          \
    m_auto_refresh_enabled.store(false, std::memory_order_relaxed);                                              \
    /* stop any background refresh and other processes, and take over */                                         \
    /* TODO */                                                                                                   \
    boost::unique_lock<boost::mutex> lock(m_idle_mutex);                                                         \
    m_idle_cond.notify_all();                                                                                    \
    epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler( \
        [&]()                                                                                                    \
        {                                                                                                        \
            /* m_idle_mutex is still locked here */                                                              \
            m_auto_refresh_enabled.store(auto_refresh_enabled, std::memory_order_relaxed);                       \
            m_idle_cond.notify_one();                                                                            \
        })

#define SCOPED_WALLET_UNLOCK_ON_BAD_PASSWORD(code)                          \
    LOCK_IDLE_SCOPE();                                                      \
    boost::optional<tools::password_container> pwd_container = boost::none; \
    if (!(pwd_container = get_and_verify_password()))                       \
    {                                                                       \
        code;                                                               \
    }                                                                       \
    wallet_keys_unlocker unlocker(*this, pwd_container);

#define SCOPED_WALLET_UNLOCK() SCOPED_WALLET_UNLOCK_ON_BAD_PASSWORD(return true;)

// #define REFRESH_PERIOD 90                   // seconds
#define DEFAULT_INACTIVITY_LOCK_TIMEOUT 0  // seconds

#define PRINT_USAGE(usage_help) tools::fail_msg_writer() << boost::format(tr("usage: %s")) % usage_help;

const char *USAGE_SHOW_ADDRESS("address");
const char *USAGE_SHOW_BALANCE("balance");
const char *USAGE_SHOW_TRANSFER("transfer <address> <amount>");
const char *USAGE_SHOW_VIEWALL("save_viewall");
const char *USAGE_SHOW_VIEWRECEIVED("save_viewreceived");
const char *USAGE_SHOW_FINDRECEIVED("save_findreceived");
const char *USAGE_SHOW_ADDRGEN("save_addrgen");
const char *USAGE_SHOW_ENOTES("show_enotes [in/out/pool/pending/failed/all] between [height1] and [height2]");
const char *USAGE_SHOW_SPECIFIC_ENOTE("show_specific_enote [key_image]");
const char *USAGE_GET_ENOTE_OWNERSHIP_PROOF_SENDER("get_enote_ownership_proof_sender [tx_id] [onetime_address]");
const char *USAGE_GET_ENOTE_OWNERSHIP_PROOF_RECEIVER("get_enote_ownership_proof_receiver [key_image]");
const char *USAGE_CHECK_ENOTE_OWNERSHIP_PROOF("check_enote_ownership_proof [filename]");

int main(int argc, char *argv[])
{
    // 1. create wallet object
    wallet3 my_wallet;

    // 2. initialize wallet (open a wallet file or create a new one)
    my_wallet.init();

    // 3. let the wallet run (initialize idle thread)
    my_wallet.run();

    // 4. terminate threads
    my_wallet.stop();

    return 1;
}
//----------------------------------------------------------------------------------------------------
wallet3::wallet3() :
    m_last_activity_time(time(NULL)),
    m_idle_run(true),
    m_auto_refresh_enabled(false),
    m_auto_refresh_refreshing(false),
    m_locked(false),
    m_in_command(false),
    m_inactivity_lock_timeout(DEFAULT_INACTIVITY_LOCK_TIMEOUT),
    m_enote_store({0, 0, 0}),
    m_kdf_rounds(1),
    m_address_network(JamtisAddressNetwork::MAINNET),
    m_address_version(JamtisAddressVersion::V1)
{
    // 1. set commands
    m_cmd_binder.set_handler(
        "help", boost::bind(&wallet3::on_command, this, &wallet3::help, _1), tr(USAGE_SHOW_VIEWALL), tr("Show help."));
    m_cmd_binder.set_handler("save_viewall",
        boost::bind(&wallet3::on_command, this, &wallet3::save_viewall, _1),
        tr(USAGE_SHOW_VIEWALL),
        tr("Create a view_all wallet from a master wallet."));
    m_cmd_binder.set_handler("save_viewreceived",
        boost::bind(&wallet3::on_command, this, &wallet3::save_viewreceived, _1),
        tr(USAGE_SHOW_VIEWRECEIVED),
        tr("Create a view_received wallet from a master or a view_all wallet."));
    m_cmd_binder.set_handler("save_findreceived",
        boost::bind(&wallet3::on_command, this, &wallet3::save_findreceived, _1),
        tr(USAGE_SHOW_FINDRECEIVED),
        tr("Create a find_received wallet from a master or a view_all wallet."));
    m_cmd_binder.set_handler("save_addrgen",
        boost::bind(&wallet3::on_command, this, &wallet3::save_addrgen, _1),
        tr(USAGE_SHOW_ADDRGEN),
        tr("Create a address_generator wallet from a master or a view_all wallet."));
    m_cmd_binder.set_handler("transfer",
        boost::bind(&wallet3::on_command, this, &wallet3::transfer, _1),
        tr(USAGE_SHOW_TRANSFER),
        tr("Transfer <address> <amount>."));
    m_cmd_binder.set_handler("balance",
        boost::bind(&wallet3::on_command, this, &wallet3::show_balance, _1),
        tr(USAGE_SHOW_BALANCE),
        tr("Show the wallet's balance of the currently selected account."));
    m_cmd_binder.set_handler("address",
        boost::bind(&wallet3::on_command, this, &wallet3::show_address, _1),
        tr(USAGE_SHOW_ADDRESS),
        tr("Show the wallet's current address."));
    m_cmd_binder.set_handler("show_enotes",
        boost::bind(&wallet3::on_command, this, &wallet3::show_enotes_cmd, _1),
        tr(USAGE_SHOW_ENOTES),
        tr("Show wallet's enotes spent or unspent."));
    m_cmd_binder.set_handler("show_specific_enote",
        boost::bind(&wallet3::on_command, this, &wallet3::show_specific_enote_cmd, _1),
        tr(USAGE_SHOW_SPECIFIC_ENOTE),
        tr("Show detailed info of a specific enote."));
    m_cmd_binder.set_handler("get_enote_ownership_proof_sender",
        boost::bind(&wallet3::on_command, this, &wallet3::get_enote_ownership_proof_sender_cmd, _1),
        tr(USAGE_GET_ENOTE_OWNERSHIP_PROOF_SENDER),
        tr("Make enote ownership proof from sender."));
    m_cmd_binder.set_handler("get_enote_ownership_proof_receiver",
        boost::bind(&wallet3::on_command, this, &wallet3::get_enote_ownership_proof_receiver_cmd, _1),
        tr(USAGE_GET_ENOTE_OWNERSHIP_PROOF_RECEIVER),
        tr("Make enote ownership proof from sender."));
    m_cmd_binder.set_handler("check_enote_ownership_proof",
        boost::bind(&wallet3::on_command, this, &wallet3::check_enote_ownership_proof_cmd, _1),
        tr(USAGE_CHECK_ENOTE_OWNERSHIP_PROOF),
        tr("Check enote ownership proof."));
    m_cmd_binder.set_handler("create_money_sp",
        boost::bind(&wallet3::on_command, this, &wallet3::create_money_sp, _1),
        tr("Create sp enotes for wallets."));
    // m_cmd_binder.set_handler("create_money_legacy",
    //     boost::bind(&wallet3::on_command, this, &wallet3::create_money_legacy, _1),
    //     tr("Create legacy enotes for wallets."));

    // 2. set unknow command
    m_cmd_binder.set_unknown_command_handler(boost::bind(&wallet3::on_command, this, &wallet3::on_unknown_command, _1));

    // 3. set empty command
    m_cmd_binder.set_empty_command_handler(boost::bind(&wallet3::on_empty_command, this));

    // 4. set cancel handler
    m_cmd_binder.set_cancel_handler(boost::bind(&wallet3::on_cancelled_command, this));
}
//----------------------------------------------------------------------------------------------------
bool wallet3::init()
{
    // TODO

    // 1. create a new wallet or open an existing one
    create_or_open_wallet();

    m_last_activity_time = time(NULL);

    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::run()
{
    // 1. start idle thread
    m_idle_thread = boost::thread([&] { wallet_idle_thread(); });

    // 2. inform that idle thread is running
    message_writer(console_color_green, false) << "Background refresh thread started";

    // 3. run console_handler
    return m_cmd_binder.run_handling([this]() { return get_prompt(); }, "");
}
//----------------------------------------------------------------------------------------------------
void wallet3::stop()
{
    // 1. terminates console handling thread
    m_cmd_binder.stop_handling();

    // 2.save enote_store
    // TODO: remove dependency on password here
    auto pw = default_password_prompter(false);
    crypto::chacha_key chacha_key;
    crypto::generate_chacha_key(pw->password().data(),pw->password().length(), chacha_key, m_kdf_rounds);
    save_enote_and_tx_store(chacha_key);

    // 3. terminates idle thread
    close_wallet();
}
//----------------------------------------------------------------------------------------------------
bool wallet3::create_or_open_wallet()
{
    LOG_PRINT_L3("Basic wallet creation");

    // 1. define function variables
    std::string wallet_path;                                       // default empty
    bool keys_file_exists, wallet_file_exists, wallet_name_valid;  // default false

    // 2. loop to load or create new wallet
    do
    {
        if (!ask_wallet_name(wallet_path, keys_file_exists, wallet_file_exists))
            continue;

        // load MockLedger
        // (TEMPORARY)
        crypto::chacha_key key;
        crypto::generate_chacha_key("mockledger_password", key, m_kdf_rounds);
        bool exist_ledger;
        exist_ledger = boost::filesystem::exists("mockledger");
        if (exist_ledger)
        {
            mocks::ser_MockLedgerContext ser_mock_ledger;
            read_encrypted_file("mockledger", key, ser_mock_ledger);
            mocks::recover_mock_ledger_context(ser_mock_ledger, m_ledger_context);
        }

        // 3. if wallet keys exist
        if (keys_file_exists)
            try_to_load_wallet(wallet_name_valid);
        // 4. if wallet keys dont exist, try to create a new one
        else
            try_to_create_wallet(wallet_path, wallet_name_valid);
    }
    while (!wallet_name_valid);

    // LOG_ERROR("Failed out of do-while loop in create_or_open_wallet()");
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::ask_wallet_name(std::string &wallet_path, bool &keys_file_exists, bool &wallet_file_exists)
{
    LOG_PRINT_L3("User asked to specify wallet file name.");
    wallet_path = input_line(
        "Enter your wallet file name or specify a new wallet file "
        "name for your Jamtis/Seraphis wallet (e.g., "
        "MyWallet).\nWallet file name (or Ctrl-C to quit)",
        false);
    if (std::cin.eof())
    {
        LOG_ERROR("Unexpected std::cin.eof() - Exited seraphis_create_basic::");
        return false;
    }
    // check if wallet exists and fill variables m_wallet_file,m_wallet_keys,m_wallet_version
    if (!wallet_path.empty())
        CHECK_AND_ASSERT_THROW_MES(check_wallet_filenames(wallet_path, keys_file_exists, wallet_file_exists),
        "create_or_open_wallet: failed checking filenames.");
    else
        return false;

    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::try_to_load_wallet(bool &wallet_name_valid)
{
    try
    {
        tools::success_msg_writer() << tr("Wallet found");
        auto pw = default_password_prompter(false);
        if (m_wallet_derivation == WalletDerivation::Seraphis)
        {
            // seraphis wallet keys found
            if (load_keys_and_cache_from_file_sp(pw.get().password()))
            {
                wallet_name_valid = true;
                get_current_address(pw.get().password());
            }
            else
            {
                tools::fail_msg_writer() << tr("Wrong password.");
            }
        }
        else if (m_wallet_derivation == WalletDerivation::Legacy)
        {
            // legacy wallet keys found
            wallet2_basic::load_keys_and_cache_from_file(
                m_wallet_file, pw.get().password(), m_legacy_cache, m_legacy_keys);
            // derive seraphis wallet from legacy
            if (!handle_legacy_keys(m_legacy_keys.m_account, pw.get().password()))
                return false;

            get_current_address(pw.get().password());

            wallet_name_valid = true;
        }
        else
        {
            // Should never get here. Derivation Unknown.
        }
    }
    catch (...)
    {
    }
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::try_to_create_wallet(const std::string &wallet_path, bool &wallet_name_valid)
{
    try
    {
        std::string confirm_creation;
        bool ok = true;
        message_writer() << tr("No wallet found with that name. Confirm "
                               "creation of new seraphis wallet named: ")
                         << wallet_path;
        confirm_creation = input_line("", true);
        if (std::cin.eof())
        {
            LOG_ERROR(
                "Unexpected std::cin.eof() - Exited "
                "wallet3::ask_wallet_create_if_needed()");
            return false;
        }
        ok = command_line::is_yes(confirm_creation);
        if (ok)
        {
            // if 'yes' - create new wallet
            tools::success_msg_writer() << tr("Generating new seraphis wallet...");
            auto pw = default_password_prompter(true);

            if (create_new_wallet(pw.get().password()))
                wallet_name_valid = true;
        }
    }
    catch (...)
    {
    }
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::load_keys_and_cache_from_file_sp(const epee::wipeable_string &password)
{
    // // 1. get chacha_key from password
    crypto::chacha_key chacha_key;
    crypto::generate_chacha_key(password.data(), password.length(), chacha_key, m_kdf_rounds);

    // 2. load wallet keys
    unlock_keys_file();
    CHECK_AND_ASSERT_THROW_MES(
        m_key_container.load_from_keys_file(m_keys_file, chacha_key, false), "load_wallet: Error loading wallet.");
    lock_keys_file();

    m_key_container.encrypt(chacha_key);

    // TODO
    // 3. load wallet cache file
    bool exist_cache;
    exist_cache = boost::filesystem::exists(m_wallet_file + ".spdata");
    if (exist_cache)
        load_enote_and_tx_store(chacha_key);

    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::create_new_wallet(const epee::wipeable_string &password)
{
    // 1. get chacha_key from password
    crypto::chacha_key chacha_key;
    crypto::generate_chacha_key(password.data(), password.length(), chacha_key, m_kdf_rounds);

    // 2. generate new keys considering a master wallet
    // CHANGE WITH INITIAL WALLET SETTINGS
    m_address_network = JamtisAddressNetwork::MAINNET;
    m_address_version = JamtisAddressVersion::V1;

    m_key_container.generate_keys();
    if (m_key_container.write_master(m_keys_file, chacha_key))
    {
        m_current_address = m_key_container.get_address_zero(m_address_version, m_address_network);
        tools::msg_writer() << "Wallet generated: " + m_current_address;
    }
    else
    {
        tools::fail_msg_writer() << "Error generating wallet.";
        return false;
    }

    // 3. lock wallet file
    lock_keys_file();

    m_key_container.encrypt(chacha_key);

    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::create_view_all(const epee::wipeable_string &password)
{
    // 1. get chacha_key from password and decrypt keys in memory
    crypto::chacha_key chacha_key;
    crypto::generate_chacha_key(password.data(), password.length(), chacha_key, m_kdf_rounds);
    m_key_container.decrypt(chacha_key);

    // 2. check if appropriate tier to create wallet
    seraphis_wallet::WalletType type = m_key_container.get_wallet_type();
    if (type != seraphis_wallet::WalletType::Master)
    {
        tools::fail_msg_writer() << "Only Master wallets can generate ViewAll wallets.";
        m_key_container.encrypt(chacha_key);
        return false;
    }

    // 3. set new password for generated wallet
    std::string derived_tier{m_wallet_file + "_viewall"};
    tools::msg_writer() << "New password for " + derived_tier + " wallet.";
    auto pw_new = default_password_prompter(true);
    crypto::chacha_key chacha_key_new;
    crypto::generate_chacha_key(pw_new->password().data(), pw_new->password().length(), chacha_key_new, m_kdf_rounds);

    // 4. write wallet
    m_key_container.write_view_all(derived_tier + ".spkeys", chacha_key_new);

    // 5. lock wallet file and encrypt
    lock_keys_file();
    m_key_container.encrypt(chacha_key);

    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::create_view_received(const epee::wipeable_string &password)
{
    // 1. get chacha_key from password and decrypt keys in memory
    crypto::chacha_key chacha_key;
    crypto::generate_chacha_key(password.data(), password.length(), chacha_key, m_kdf_rounds);
    m_key_container.decrypt(chacha_key);

    // 2. check if appropriate tier to create wallet
    seraphis_wallet::WalletType type = m_key_container.get_wallet_type();
    if (type != seraphis_wallet::WalletType::Master && type != seraphis_wallet::WalletType::ViewAll)
    {
        tools::fail_msg_writer() << "Only Master and ViewAll wallets can generate ViewReceived wallets.";
        m_key_container.encrypt(chacha_key);
        return false;
    }

    // 3. check if appropriate tier to create wallet
    std::string derived_tier{m_wallet_file + "_viewreceived"};
    tools::msg_writer() << "New password for " + derived_tier + " wallet.";
    auto pw_new = default_password_prompter(true);
    crypto::chacha_key chacha_key_new;
    crypto::generate_chacha_key(pw_new->password().data(), pw_new->password().length(), chacha_key_new, m_kdf_rounds);

    // 4. write wallet
    m_key_container.write_view_received(derived_tier + ".spkeys", chacha_key_new);

    // 5. lock wallet file and encrypt
    lock_keys_file();
    m_key_container.encrypt(chacha_key);

    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::create_find_received(const epee::wipeable_string &password)
{
    // 1. get chacha_key from password and decrypt keys in memory
    crypto::chacha_key chacha_key;
    crypto::generate_chacha_key(password.data(), password.length(), chacha_key, m_kdf_rounds);
    m_key_container.decrypt(chacha_key);

    // 2. check if appropriate tier to create wallet
    seraphis_wallet::WalletType type = m_key_container.get_wallet_type();
    if (type != seraphis_wallet::WalletType::Master && type != seraphis_wallet::WalletType::ViewAll)
    {
        tools::fail_msg_writer() << "Only Master and ViewAll wallets can generate FindReceived wallets.";
        m_key_container.encrypt(chacha_key);
        return false;
    }

    // 3. check if appropriate tier to create wallet
    std::string derived_tier{m_wallet_file + "_findreceived"};
    tools::msg_writer() << "New password for " + derived_tier + " wallet.";
    auto pw_new = default_password_prompter(true);
    crypto::chacha_key chacha_key_new;
    crypto::generate_chacha_key(pw_new->password().data(), pw_new->password().length(), chacha_key_new, m_kdf_rounds);

    // 4. write wallet
    m_key_container.write_find_received(derived_tier + ".spkeys", chacha_key_new);

    // 5. lock wallet file and encrypt
    lock_keys_file();
    m_key_container.encrypt(chacha_key);

    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::create_address_generator(const epee::wipeable_string &password)
{
    // 1. get chacha_key from password and decrypt keys in memory
    crypto::chacha_key chacha_key;
    crypto::generate_chacha_key(password.data(), password.length(), chacha_key, m_kdf_rounds);
    m_key_container.decrypt(chacha_key);

    // 2. check if appropriate tier to create wallet
    seraphis_wallet::WalletType type = m_key_container.get_wallet_type();
    if (type != seraphis_wallet::WalletType::Master && type != seraphis_wallet::WalletType::ViewAll)
    {
        tools::fail_msg_writer() << "Only Master and ViewAll wallets can generate AddrrGen wallets.";
        m_key_container.encrypt(chacha_key);
        return false;
    }

    // 3. check if appropriate tier to create wallet
    std::string derived_tier{m_wallet_file + "_addrgen"};
    tools::msg_writer() << "New password for " + derived_tier + " wallet.";
    auto pw_new = default_password_prompter(true);
    crypto::chacha_key chacha_key_new;
    crypto::generate_chacha_key(pw_new->password().data(), pw_new->password().length(), chacha_key_new, m_kdf_rounds);

    // 4. write wallet
    m_key_container.write_address_generator(derived_tier + ".spkeys", chacha_key_new);

    // 5. lock wallet file and encrypt
    lock_keys_file();
    m_key_container.encrypt(chacha_key);

    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::handle_legacy_keys(const cryptonote::account_base &legacy_keys, const epee::wipeable_string &password)
{
    // 1. get chacha_key from password
    crypto::chacha_key chacha_key;
    crypto::generate_chacha_key(password.data(), password.length(), chacha_key, m_kdf_rounds);

    // 2. check if view-only wallet
    if (legacy_keys.get_keys().m_spend_secret_key == rct::rct2sk(rct::zero()))
    {
        tools::fail_msg_writer() << "Legacy view-only wallet cannot derive a seraphis wallet.";
        return false;
    }

    // 3. convert legacy keys to seraphis
    m_key_container.convert_legacy_keys(legacy_keys);
    m_key_container.derive_seraphis_keys_from_legacy();
    if (m_key_container.write_master(m_wallet_file + ".spkeys", chacha_key))
        m_keys_file = m_wallet_file + ".spkeys";

    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::close_wallet()
{
    // 1. if idle thread is running
    if (m_idle_run.load(std::memory_order_relaxed))
    {
        // 2. store false on idle thread running
        m_idle_run.store(false, std::memory_order_relaxed);
        {
            // 3. unblock thread
            boost::unique_lock<boost::mutex> lock(m_idle_mutex);
            m_idle_cond.notify_one();
        }
        // 4. finish idle thread
        m_idle_thread.join();
    }
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::save_enote_and_tx_store(const crypto::chacha_key &key)
{
    // 1. serialize enote_store
    sp::serialization::ser_SpEnoteStore ser_enote_store;
    make_serializable_sp_enote_store(m_enote_store, ser_enote_store);

    // 2. serialize tx_store
    ser_SpTransactionStoreV1 ser_tx_store;
    make_serializable_sp_transaction_store_v1(m_transaction_history.get_tx_store(), ser_tx_store);

    // 3. wrap them
    ser_SpWalletData ser_wallet_data{ser_enote_store,ser_tx_store};

    // 4. write into file
    write_encrypted_file(m_wallet_file+".spdata", key, ser_wallet_data);

    // save MockLedger
    // (TEMPORARY)
    crypto::chacha_key key_ledger;
    crypto::generate_chacha_key("mockledger_password", key_ledger, m_kdf_rounds);
    mocks::ser_MockLedgerContext ser_mock_ledger;
    mocks::make_serializable_mock_ledger_context(m_ledger_context, ser_mock_ledger);
    write_encrypted_file("mockledger", key_ledger, ser_mock_ledger);

    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::load_enote_and_tx_store(const crypto::chacha_key &key)
{
    // 1. read serialized data
    ser_SpWalletData ser_wallet_data;
    read_encrypted_file(m_wallet_file+".spdata", key, ser_wallet_data);

    // 2. restore into wallet struct member
    SpTransactionStore tx_store_recovered;
    recover_sp_transaction_store_v1(ser_wallet_data.transaction_store, tx_store_recovered);
    recover_sp_enote_store(ser_wallet_data.enote_store, m_enote_store);
    m_transaction_history.set_tx_store(tx_store_recovered);

    return true;
}
//----------------------------------------------------------------------------------------------------
void wallet3::get_current_address(const epee::wipeable_string &password)
{
    crypto::chacha_key chacha_key;
    crypto::generate_chacha_key(password.data(), password.length(), chacha_key, m_kdf_rounds);
    m_key_container.decrypt(chacha_key);
    m_current_address = m_key_container.get_address_zero(m_address_version, m_address_network);
    print_wallet_type();
    m_key_container.encrypt(chacha_key);
}
//----------------------------------------------------------------------------------------------------
void wallet3::prepare_file_names(const std::string &file_path, std::string &keys_file, std::string &wallet_file) {}
//----------------------------------------------------------------------------------------------------
bool wallet3::check_wallet_filenames(const std::string &file_path, bool &keys_file_exists, bool &wallet_file_exists)
{
    std::string keys_file, wallet_file;
    bool legacy_keys, sp_keys;
    WalletDerivation derivation{WalletDerivation::Legacy};

    boost::system::error_code ignore;

    // provided name with extension
    if (string_tools::get_extension(file_path) == "spkeys")
    {
        wallet_file = string_tools::cut_off_extension(file_path);
        keys_file   = file_path;
        derivation  = WalletDerivation::Seraphis;
    }
    else if (string_tools::get_extension(file_path) == "keys")
    {
        wallet_file = string_tools::cut_off_extension(file_path);
        keys_file   = file_path;
        derivation  = WalletDerivation::Legacy;
    }
    else if (string_tools::get_extension(file_path) == "spcache")
    {
        wallet_file = string_tools::cut_off_extension(file_path);
        keys_file   = wallet_file + ".spkeys";
        derivation  = WalletDerivation::Seraphis;
    }
    // provided wallet name without extension
    else
    {
        wallet_file = file_path;

        // check if legacy and sp wallet exists
        sp_keys     = boost::filesystem::exists(file_path + ".spkeys", ignore);
        legacy_keys = boost::filesystem::exists(file_path + ".keys", ignore);
        if (sp_keys)
        {
            keys_file  = wallet_file + ".spkeys";
            derivation = WalletDerivation::Seraphis;
            tools::msg_writer() << "Seraphis wallet keys found.";
        }
        else if (legacy_keys)
        {
            keys_file  = wallet_file + ".keys";
            derivation = WalletDerivation::Legacy;
            tools::msg_writer() << "Legacy wallet keys found.";
        }
        else
        {
            keys_file  = wallet_file + ".spkeys";
            derivation = WalletDerivation::Seraphis;
        }
    }

    m_wallet_derivation = derivation;
    m_keys_file         = keys_file;
    m_wallet_file       = wallet_file;

    keys_file_exists = boost::filesystem::exists(keys_file, ignore);

    if (m_wallet_derivation == WalletDerivation::Legacy)
        wallet_file_exists = boost::filesystem::exists(wallet_file, ignore);
    else
        wallet_file_exists = boost::filesystem::exists(wallet_file + ".spcache", ignore);

    return true;
}
//----------------------------------------------------------------------------------------------------
void wallet3::print_wallet_type()
{
    switch (m_key_container.get_wallet_type())
    {
        case seraphis_wallet::WalletType::Master:
            tools::msg_writer() << tr("Master wallet loaded.");
            break;
        case seraphis_wallet::WalletType::ViewAll:
            tools::msg_writer() << tr("View-all wallet loaded.");
            break;
        case seraphis_wallet::WalletType::ViewReceived:
            tools::msg_writer() << tr("View-received wallet loaded.");
            break;
        case seraphis_wallet::WalletType::FindReceived:
            tools::msg_writer() << tr("Find-received wallet loaded.");
            break;
        case seraphis_wallet::WalletType::AddrGen:
            tools::msg_writer() << tr("Address-generator wallet loaded.");
            break;
        default:
            tools::fail_msg_writer() << tr("Failed loading wallet type.");
    }
}
//----------------------------------------------------------------------------------------------------
bool wallet3::verify_password(const epee::wipeable_string &password)
{
    // 1. generate chacha key from password data
    crypto::chacha_key chacha_key;
    crypto::generate_chacha_key(password.data(), password.length(), chacha_key, m_kdf_rounds);

    // 2. load and verify keys with provided password
    unlock_keys_file();
    if (!m_key_container.load_from_keys_file(m_keys_file, chacha_key, true))
    {
        tools::fail_msg_writer() << tr("invalid password");
        return false;
    }
    lock_keys_file();

    return true;
}
//----------------------------------------------------------------------------------------------------
boost::optional<tools::password_container> wallet3::get_and_verify_password()
{
    auto pwd_container = default_password_prompter(false);
    if (!pwd_container)
        return boost::none;

    if (!verify_password(pwd_container->password()))
    {
        return boost::none;
    }
    return pwd_container;
}
//----------------------------------------------------------------------------------------------------
boost::optional<tools::password_container> wallet3::password_prompter(const char *prompt, bool verify)
{
    PAUSE_READLINE();
    auto pwd_container = tools::password_container::prompt(verify, prompt);
    if (!pwd_container)
    {
        tools::fail_msg_writer() << tr("failed to read wallet password");
    }
    return pwd_container;
}
//----------------------------------------------------------------------------------------------------
boost::optional<tools::password_container> wallet3::default_password_prompter(bool creation)
{
    return password_prompter(creation ? tr("Enter a new password for the wallet") : tr("Wallet password"), creation);
}
//----------------------------------------------------------------------------------------------------
void wallet3::generate_chacha_key_from_password(const epee::wipeable_string &pass, crypto::chacha_key &key)
{
    crypto::generate_chacha_key(pass.data(), pass.size(), key, m_kdf_rounds);
}
//----------------------------------------------------------------------------------------------------
bool wallet3::is_keys_file_locked() const { return m_keys_file_locker->locked(); }
//----------------------------------------------------------------------------------------------------
bool wallet3::lock_keys_file()
{
    if (m_keys_file_locker)
    {
        MDEBUG(m_keys_file << " is already locked.");
        return false;
    }
    m_keys_file_locker.reset(new tools::file_locker(m_keys_file));
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::unlock_keys_file()
{
    if (!m_keys_file_locker)
    {
        MDEBUG(m_keys_file << " is already unlocked.");
        return false;
    }
    m_keys_file_locker.reset();
    return true;
}
//----------------------------------------------------------------------------------------------------
void wallet3::encrypt_keys(const crypto::chacha_key &key) { m_key_container.encrypt(key); }
//----------------------------------------------------------------------------------------------------
void wallet3::decrypt_keys(const crypto::chacha_key &key) { m_key_container.decrypt(key); }
//----------------------------------------------------------------------------------------------------
bool wallet3::on_unknown_command(const std::vector<std::string> &args)
{
    // 1. check if 'exit' or 'q' was pressed and stop flow (return false) if so
    if (args[0] == "exit" || args[0] == "q")  // backward compat
        return false;
    tools::fail_msg_writer() << boost::format(tr("Unknown command '%s', try 'help'")) % args.front();
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::on_empty_command()
{
    // 1. restart idle time after a command
    m_last_activity_time = time(NULL);

    // 2. just keep the flow (return true)
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::on_cancelled_command()
{
    // 1. check if wallet should be locked
    check_for_inactivity_lock(false);
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::on_command(bool (wallet3::*cmd)(const std::vector<std::string> &), const std::vector<std::string> &args)
{
    // 1. restart idle time after a command
    m_last_activity_time = time(NULL);

    // 2. set atomic to true
    m_in_command = true;

    // 3. create scope and leave handler
    epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler(
        [&]()
        {
            m_last_activity_time = time(NULL);
            m_in_command         = false;
        });

    // 4. check if wallet should be locked
    check_for_inactivity_lock(false);

    return (this->*cmd)(args);
}
//----------------------------------------------------------------------------------------------------
std::string wallet3::get_prompt() const
{
    // 1. if wallet is locked, return locked message
    if (m_locked)
        return std::string{"[locked due to inactivity]"};

    // 2. show wallet address in use
    return std::string{"[sp-wallet: " + m_current_address.substr(0, 16) + "]: "};
}
//----------------------------------------------------------------------------------------------------
bool wallet3::get_command()
{
    // 1. wait user to enter a command
    std::string cmd_entered;
    cmd_entered = input_line("Enter command", false);
    if (std::cin.eof())
    {
        LOG_ERROR("Unexpected std::cin.eof() - Exited seraphis_create_basic::");
        return false;
    }
    return true;
}
//----------------------------------------------------------------------------------------------------
std::string wallet3::input_line(const std::string &prompt, bool yesno)
{
    // 1. try to read user input
    PAUSE_READLINE();
    std::cout << prompt;
    if (yesno)
        std::cout << "  (Y/Yes/N/No)";
    std::cout << ": " << std::flush;

    std::string buf;
#ifdef _WIN32
    buf = tools::input_line_win();
#else
    std::getline(std::cin, buf);
#endif

    return epee::string_tools::trim(buf);
}
//----------------------------------------------------------------------------------------------------
tools::scoped_message_writer wallet3::message_writer(epee::console_colors color, bool bright)
{
    return tools::scoped_message_writer(color, bright);
}
//----------------------------------------------------------------------------------------------------
void wallet3::check_for_inactivity_lock(bool user)
{
    // 1. do if wallet should be locked
    if (m_locked)
    {
#ifdef HAVE_READLINE
        PAUSE_READLINE();
        rdln::clear_screen();
#endif
        tools::clear_screen();
        m_in_command = true;
        if (!user)
        {
            tools::msg_writer() << " " << std::endl
                                << "        .n.      Your wallet was locked        " << std::endl
                                << "       /___\\      while you were away.  " << std::endl
                                << "       [|||]  See \"help set\" to configure it.   " << std::endl
                                << "       |-  | " << std::endl
                                << "       |.- |                p " << std::endl
                                << "~^=~^~-|_.-|~^-~^~ ~^~ -^~^~|\\ ~^-~^~- " << std::endl
                                << "^   .=.| _.|__  ^       ~  /| \\  " << std::endl
                                << " ~ /:. \\  _|_/\\    ~      /_| _\\  ^ " << std::endl
                                << ".-/::.  |   |::|-._    ^  \\____/ " << std::endl
                                << "  `===-'-----'"
                                   "`  '-.              ~"
                                << std::endl
                                << "" << std::endl;
        }
        // 2. loop until user enters the valid password
        while (1)
        {
            // 2.1 write message that wallet is locked
            const char *inactivity_msg = user ? "" : tr("Locked due to inactivity.");
            tools::msg_writer() << inactivity_msg << (inactivity_msg[0] ? " " : "")
                                << tr("The wallet password is required to unlock the console.");

            try
            {
                // 2.1 get password
                auto pwd_container = default_password_prompter(false);
                CHECK_AND_ASSERT_THROW_MES(pwd_container, "check_for_inactivity_lock: failed reading password.");

                // 2.2 if password entered is correct, break loop
                if (verify_password(pwd_container.get().password()))
                    break;
            }
            catch (...)
            { /* do nothing, just let the loop loop */
            }
        }

        // 3. restart timer and lock variables
        m_last_activity_time = time(NULL);
        m_in_command         = false;
        m_locked             = false;
    }
}
//----------------------------------------------------------------------------------------------------
void wallet3::wallet_idle_thread()
{
    // 1. get initial time
    const boost::posix_time::ptime start_time = boost::posix_time::microsec_clock::universal_time();

    // 2. loop until m_idle_run is false
    while (true)
    {
        boost::unique_lock<boost::mutex> lock(m_idle_mutex);
        if (!m_idle_run.load(std::memory_order_relaxed))
            break;

        // if another thread was busy (ie, a foreground refresh thread), we'll
        // end up here at some random time that's not what we slept for, so we
        // should not call refresh now or we'll be leaking that fact through
        // timing
        const boost::posix_time::ptime now0 = boost::posix_time::microsec_clock::universal_time();
        const uint64_t dt_actual            = (now0 - start_time).total_microseconds() % 1000000;
#ifdef _WIN32
        static const uint64_t threshold = 10000;
#else
        static const uint64_t threshold = 2000;
#endif
        if (dt_actual < threshold)  // if less than a threshold... would a very
                                    // slow machine always miss it ?
        {
#ifndef _WIN32
            m_inactivity_checker.do_call(boost::bind(&wallet3::check_inactivity, this));
#endif
            // TODO: call to refresh wallet here
            if (!m_idle_run.load(std::memory_order_relaxed))
                break;
        }

        // aim for the next multiple of 1 second
        const boost::posix_time::ptime now = boost::posix_time::microsec_clock::universal_time();
        const auto dt                      = (now - start_time).total_microseconds();
        const auto wait                    = 1000000 - dt % 1000000;
        m_idle_cond.wait_for(lock, boost::chrono::microseconds(wait));
    }
}
//----------------------------------------------------------------------------------------------------
bool wallet3::check_inactivity()
{
    // 1. check if wallet should not be locked nor is in command
    if (!m_locked && !m_in_command)
    {
        // 2. get lock_timeout
        const uint32_t seconds = inactivity_lock_timeout();

        // 3. check if time of last activity is greater than timeout
        if (seconds > 0 && time(NULL) - m_last_activity_time > seconds)
        {
            // 4. set variable to lock wallet
            m_locked = true;
            m_cmd_binder.cancel_input();
        }
    }
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::help(const std::vector<std::string> &args)
{
    if (args.empty())
    {
        message_writer() << "";
        message_writer() << tr("Important commands:");
        // message_writer() << tr("\"help <command>\" - Show a command's documentation.");
        message_writer() << tr("\"create_money_sp\" - Create 5 seraphis enotes of 1000 xmr each into mockledger.");
        message_writer() << tr("\"save_viewall\" - Save view-all wallet.");
        message_writer() << tr("\"save_viewreceived\" - Save view-received wallet.");
        message_writer() << tr("\"save_findreceived\" - Save find-received wallet.");
        message_writer() << tr("\"save_addrgen\" - Save address-generator wallet.");
        message_writer() << tr("\"balance\" - Show available funds.");
        message_writer() << tr("\"address\" - Show current wallet address.");
        message_writer() << tr("\"transfer <address> <amount>\" - Create a transaction and broadcast to the network.");
        message_writer() << tr("\"show_enotes [in|out|pool|pending|failed|all] between [height1] and [height2] \" - Show a list of enotes.");
        message_writer() << tr("\"show_specific_enote [key_image]\" - Show the detailed info of an enote.");
        message_writer() << tr("\"get_enote_ownership_proof_sender [tx_id] [onetime_address]\" - Get enote ownership proof from sender.");
        message_writer() << tr("\"get_enote_ownership_proof_receiver [key_image]\" - Get enote ownership proof from receiver.");
        message_writer() << tr("\"check_enote_ownership_proof [filename]]\" - Check enote ownership proof.");
        message_writer() << "";
    }
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::save_viewall(const std::vector<std::string> &args)
{
    try
    {
        // 1. get password
        auto pwd_container = default_password_prompter(false);
        CHECK_AND_ASSERT_THROW_MES(pwd_container, "save_viewall: failed reading password.");

        // 2. if password entered is correct, create wallet
        if (verify_password(pwd_container.get().password()))
        {
            if (create_view_all(pwd_container->password()))
                tools::success_msg_writer() << tr("View-all wallet saved.");
        }
    }
    catch (...)
    {
        tools::fail_msg_writer() << tr("Failed to save view-all wallet. ");
    }
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::save_viewreceived(const std::vector<std::string> &args)
{
    try
    {
        // 1. get password
        auto pwd_container = default_password_prompter(false);
        CHECK_AND_ASSERT_THROW_MES(pwd_container, "save_viewreceived: failed reading password.");

        // 2. if password entered is correct, create wallet
        if (verify_password(pwd_container.get().password()))
        {
            if (create_view_received(pwd_container->password()))
                tools::success_msg_writer() << tr("View-received wallet saved.");
        }
    }
    catch (...)
    {
        tools::fail_msg_writer() << tr("Failed to save view-received wallet. ");
    }
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::save_findreceived(const std::vector<std::string> &args)
{
    try
    {
        // 1. get password
        auto pwd_container = default_password_prompter(false);
        CHECK_AND_ASSERT_THROW_MES(pwd_container, "save_findreceived: failed reading password.");

        // 2. if password entered is correct, create wallet
        if (verify_password(pwd_container.get().password()))
        {
            if (create_view_received(pwd_container->password()))
                tools::success_msg_writer() << tr("Find-received wallet saved.");
        }
    }
    catch (...)
    {
        tools::fail_msg_writer() << tr("Failed to save find-received wallet. ");
    }
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::save_addrgen(const std::vector<std::string> &args)
{
    try
    {
        // 1. get password
        auto pwd_container = default_password_prompter(false);
        CHECK_AND_ASSERT_THROW_MES(pwd_container, "save_addrgren: failed reading password.");

        // 2. if password entered is correct, create wallet
        if (verify_password(pwd_container.get().password()))
        {
            if (create_address_generator(pwd_container->password()))
                tools::success_msg_writer() << tr("Address-generator wallet saved.");
        }
    }
    catch (...)
    {
        tools::fail_msg_writer() << tr("Failed to save addr-gen wallet. ");
    }
    return true;
}
//----------------------------------------------------------------------------------------------------
// Experimental testing functions
//----------------------------------------------------------------------------------------------------
bool wallet3::create_money_sp(const std::vector<std::string> &args)
{
    SCOPED_WALLET_UNLOCK();

    std::vector<std::string> local_args = args;
    JamtisDestinationV1 destination_address;
    JamtisAddressNetwork destination_network{};
    JamtisAddressVersion destination_version{};

    if (local_args.size() == 0)
        m_key_container.get_random_destination(destination_address);
    else
        get_destination_from_str(local_args[0], destination_address, destination_version, destination_network);

    const scanning::ScanMachineConfig refresh_config{
        .reorg_avoidance_increment = 1, .max_chunk_size_hint = 1, .max_partialscan_attempts = 1};
    send_sp_coinbase_amounts_to_user({1000, 1000, 1000, 1000, 1000}, destination_address, destination_version, destination_network ,m_ledger_context);
    refresh_user_enote_store(m_key_container.get_sp_keys(), refresh_config, m_ledger_context, m_enote_store);
    tools::success_msg_writer() << tr("Five enotes of 1000 each were created to this wallet.");
    return true;
}
//----------------------------------------------------------------------------------------------------
// bool wallet3::create_money_legacy(const std::vector<std::string> &args)
// {
//     SCOPED_WALLET_UNLOCK();

//     if (m_key_container.get_legacy_keys().k_s == rct2sk(rct::zero()))
//     {
//         tools::fail_msg_writer() << "Legacy enotes can only be generated to legacy derived wallets." << std::endl;
//         return true;
//     }

//     try
//     {
//         std::vector<std::string> local_args = args;

//         const scanning::ScanMachineConfig refresh_config{
//             .reorg_avoidance_increment = 1000, .max_chunk_size_hint = 1000, .max_partialscan_attempts = 100};

//         // b. add enough fake legacy enotes to the ledger so we can reliably make legacy ring signatures
//         std::vector<rct::xmr_amount> fake_legacy_enote_amounts(16, 0);
//         const rct::key fake_legacy_spendkey{rct::pkGen()};
//         const rct::key fake_legacy_viewkey{rct::pkGen()};

//         send_legacy_coinbase_amounts_to_user(
//             fake_legacy_enote_amounts, fake_legacy_spendkey, fake_legacy_viewkey, m_ledger_context);

//         rct::key legacy_subaddr_spendkey;
//         rct::key legacy_subaddr_viewkey;
//         cryptonote::subaddress_index legacy_subaddr_index;
//         std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;

//         gen_legacy_subaddress(m_key_container.get_legacy_keys().Ks,
//             m_key_container.get_legacy_keys().k_v,
//             legacy_subaddr_spendkey,
//             legacy_subaddr_viewkey,
//             legacy_subaddr_index);

//         legacy_subaddress_map[legacy_subaddr_spendkey] = legacy_subaddr_index;

//         send_legacy_coinbase_amounts_to_user({1000}, legacy_subaddr_spendkey, legacy_subaddr_viewkey, m_ledger_context);

//         refresh_user_enote_store_legacy_full(m_key_container.get_legacy_keys().Ks,
//             legacy_subaddress_map,
//             m_key_container.get_legacy_keys().k_s,
//             m_key_container.get_legacy_keys().k_v,
//             refresh_config,
//             m_ledger_context,
//             m_enote_store);

//         tools::success_msg_writer() << tr("Five legacy enotes of 1000 each were created to this wallet.");
//     }
//     catch (...)
//     {
//     }

//     return true;
// }
//----------------------------------------------------------------------------------------------------
bool wallet3::show_address(const std::vector<std::string> &args)
{
    SCOPED_WALLET_UNLOCK();

    tools::msg_writer() << tr("Wallet address: ");
    tools::msg_writer() << m_current_address << std::endl;
    tools::msg_writer() << "-------- Keys --------";
    tools::msg_writer() << "Legacy private spend-key: " << m_key_container.get_legacy_keys().k_s << std::endl;
    tools::msg_writer() << "Legacy private view-key: " << m_key_container.get_legacy_keys().k_v << std::endl;
    tools::msg_writer() << "Seraphis private master-key: " << m_key_container.get_sp_keys().k_m << std::endl;
    tools::msg_writer() << "Seraphis private viewbalance-key: " << m_key_container.get_sp_keys().k_vb << std::endl;

    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::show_balance(const std::vector<std::string> &args)
{
    SCOPED_WALLET_UNLOCK();

        const scanning::ScanMachineConfig refresh_config{
            .reorg_avoidance_increment = 1000, .max_chunk_size_hint = 1000, .max_partialscan_attempts = 100};

    refresh_user_enote_store(m_key_container.get_sp_keys(), refresh_config, m_ledger_context, m_enote_store);

    rct::key legacy_subaddr_spendkey;
    rct::key legacy_subaddr_viewkey;
    cryptonote::subaddress_index legacy_subaddr_index;
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;

    gen_legacy_subaddress(m_key_container.get_legacy_keys().Ks,
        m_key_container.get_legacy_keys().k_v,
        legacy_subaddr_spendkey,
        legacy_subaddr_viewkey,
        legacy_subaddr_index);

    legacy_subaddress_map[legacy_subaddr_spendkey] = legacy_subaddr_index;

    refresh_user_enote_store_legacy_full(m_key_container.get_legacy_keys().Ks,
        legacy_subaddress_map,
        m_key_container.get_legacy_keys().k_s,
        m_key_container.get_legacy_keys().k_v,
        refresh_config,
        m_ledger_context,
        m_enote_store);

    // get_balance should get UNSPENT instead??
    boost::multiprecision::uint128_t balance = get_balance(m_enote_store, {SpEnoteOriginStatus::ONCHAIN}, {SpEnoteSpentStatus::SPENT_ONCHAIN});
    set_console_color(epee::console_color_green, true);
    std::cout << "Wallet balance: " << balance << std::endl;
    epee::reset_console_color();

    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::transfer(const std::vector<std::string> &args)
{
    std::vector<std::string> local_args = args;

    if (local_args.size() != 2)
    {
        PRINT_USAGE(USAGE_SHOW_TRANSFER);
        return true;
    }

    SCOPED_WALLET_UNLOCK();

    JamtisDestinationV1 destination_address;
    JamtisAddressNetwork destination_network;
    JamtisAddressVersion destination_version;

    get_destination_from_str(local_args[0], destination_address, destination_version, destination_network);
    rct::xmr_amount amount{std::stoull(local_args[1])};

    const scanning::ScanMachineConfig refresh_config{
        .reorg_avoidance_increment = 1, .max_chunk_size_hint = 1, .max_partialscan_attempts = 0};

    refresh_user_enote_store(m_key_container.get_sp_keys(), refresh_config, m_ledger_context, m_enote_store);
    auto balance = get_balance(m_enote_store, {SpEnoteOriginStatus::ONCHAIN}, {SpEnoteSpentStatus::SPENT_ONCHAIN});
    if (amount >= balance)
    {
        tools::fail_msg_writer() << tr("Fail. You are trying to spend more than your available balance.");
        return true;
    }

    const sp::mocks::FeeCalculatorMockTrivial
        fee_calculator;  // just do a trivial calculator for now (fee = fee/weight * 1 weight)

    const SpBinnedReferenceSetConfigV1 bin_config{.bin_radius = 1, .num_bin_members = 2};

    const sp::mocks::InputSelectorMockV1 input_selector{m_enote_store};

    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{1};
    const std::size_t legacy_ring_size{2};
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};

    //  make sure to have enough fake enotes to the ledger so we can reliably
    std::vector<rct::xmr_amount> fake_sp_enote_amounts(
        static_cast<std::size_t>(compute_bin_width(bin_config.bin_radius)), 0);

    SpTxSquashedV1 single_tx;
    std::vector<JamtisPaymentProposalV1> normal_payments;
    std::vector<JamtisPaymentProposalSelfSendV1> selfsend_payments;

    construct_tx_for_mock_ledger_v1(m_key_container.get_legacy_keys(),
        m_key_container.get_sp_keys(),
        input_selector,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{amount, TxExtra{}, destination_address, destination_version, destination_network}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        m_ledger_context,
        single_tx,
        selfsend_payments,
        normal_payments);

    // validate and submit to the mock ledger
    const sp::mocks::TxValidationContextMock tx_validation_context{m_ledger_context};
    CHECK_AND_ASSERT_THROW_MES(
        validate_tx(single_tx, tx_validation_context), "transfer funds single mock: validating tx failed.");
    CHECK_AND_ASSERT_THROW_MES(try_add_tx_to_ledger(single_tx, m_ledger_context),
        "transfer funds single mock: adding tx to mock ledger failed.");

    refresh_user_enote_store(m_key_container.get_sp_keys(), refresh_config, m_ledger_context, m_enote_store);

    // add tx to tx_history
    m_transaction_history.add_single_tx(single_tx, selfsend_payments, normal_payments);

    rct::key tx_id;
    get_sp_tx_squashed_v1_txid(single_tx, tx_id);

    tools::msg_writer() << tr("Transaction ") << epee::string_tools::pod_to_hex(tx_id) << tr(" submitted to network.");

    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::show_enotes_cmd(const std::vector<std::string> &args)
{
    std::vector<std::string> local_args = args;
    std::string tx_direction = "all";
    uint64_t initial_height = 0, final_height = -1;

    if (local_args.size() > 3)
    {
        PRINT_USAGE(USAGE_SHOW_ENOTES);
        return true;
    }

    SCOPED_WALLET_UNLOCK();

    if (local_args.size() >= 1)
    {
        tx_direction = local_args[0];
        if (local_args.size() >= 2)
        {
            initial_height = std::stoul(local_args[1]);
            if (local_args.size() == 3)
            {
                final_height = std::stoul(local_args[2]);
            }
        }
    }

    std::vector<ContextualRecordVariant> enote_records;

    if (tx_direction == "in")
    {
        get_enotes(m_enote_store, SpTxDirectionStatus::IN_ONCHAIN, {initial_height, final_height}, enote_records);
        show_enotes(enote_records);
    }
    else if (tx_direction == "out")
    {
        get_enotes(m_enote_store, SpTxDirectionStatus::OUT_ONCHAIN, {initial_height, final_height}, enote_records);
        show_enotes(enote_records);
    }
    else if (tx_direction == "pending")
    {
        get_enotes(m_enote_store, SpTxDirectionStatus::IN_OFFCHAIN, {initial_height, final_height}, enote_records);
        get_enotes(m_enote_store, SpTxDirectionStatus::OUT_OFFCHAIN, {initial_height, final_height}, enote_records);
        show_enotes(enote_records);
    }
    else if (tx_direction == "pool")
    {
        get_enotes(m_enote_store, SpTxDirectionStatus::IN_POOL, {initial_height, final_height}, enote_records);
        get_enotes(m_enote_store, SpTxDirectionStatus::OUT_POOL, {initial_height, final_height}, enote_records);
        show_enotes(enote_records);
    }
    else if (tx_direction == "failed")
    {
        get_enotes(m_enote_store, SpTxDirectionStatus::FAILED, {initial_height, final_height}, enote_records);
        show_enotes(enote_records);
    }
    else if (tx_direction == "all")
    {
        get_enotes(m_enote_store, SpTxDirectionStatus::ALL, {initial_height, final_height}, enote_records);
        show_enotes(enote_records);
    }
    else
        tools::fail_msg_writer() << "Wrong option. See show_enotes usage.";

    return true;

}
//----------------------------------------------------------------------------------------------------
bool wallet3::show_specific_enote_cmd(const std::vector<std::string> &args)
{
    std::vector<std::string> local_args = args;
    crypto::key_image key_image;

    if (local_args.size() == 1)
        epee::string_tools::hex_to_pod(local_args[0], key_image);
    else
    {
        PRINT_USAGE(USAGE_SHOW_SPECIFIC_ENOTE);
        return true;
    }

    show_specific_enote(m_enote_store, m_transaction_history, key_image);

    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::get_enote_ownership_proof_sender_cmd(const std::vector<std::string> &args)
{
    // 1. check arguments
    std::vector<std::string> local_args = args;
    rct::key tx_id;
    rct::key onetime_address;

    if ((local_args.size() != 2))
    {
        PRINT_USAGE(USAGE_GET_ENOTE_OWNERSHIP_PROOF_SENDER);
        return true;
    }

    SCOPED_WALLET_UNLOCK();

    try
    {
        // 2. get tx_id and onetime_address
        epee::string_tools::hex_to_pod(local_args[0], tx_id);
        epee::string_tools::hex_to_pod(local_args[1], onetime_address);

        // 3. get the tx_record
        TransactionRecord tx_record;
        CHECK_AND_ASSERT_THROW_MES(m_transaction_history.try_get_tx_record_from_txid(tx_id, tx_record),
            "Error in kp_get_enote_ownership_proof: Transaction not found.");

        // 4. From tx_id get all output enotes of a tx by querying node.
        std::vector<SpEnoteVariant> out_enotes = m_ledger_context.get_sp_enotes_out_from_tx(tx_id);

        // 5. get input context
        rct::key input_context;
        make_jamtis_input_context_standard(tx_record.legacy_spent_enotes, tx_record.sp_spent_enotes, input_context);

        // 6. try to match enotes with destinations
        std::vector<EnoteInfo> vec_enote_out_info;
        CHECK_AND_ASSERT_THROW_MES(try_get_enote_out_info(out_enotes,
                                       tx_record.normal_payments,
                                       tx_record.selfsend_payments,
                                       input_context,
                                       m_key_container.get_sp_keys().k_vb,
                                       vec_enote_out_info),
            "Error in get_enote_out_info. Could not match onetime adresses with destinations.");

        EnoteInfo specific_enote_info{};
        get_specific_enote_out_info(vec_enote_out_info, onetime_address, specific_enote_info);

        // 7. make enote sent proof for normal and selfsend enotes
        boost::optional<std::string> filename{"tx_enote_ownership_proof_sender"};
        boost::optional<std::string> str_proof;
        str_proof = get_enote_ownership_proof_sender(
            tx_id, m_key_container.get_sp_keys().k_vb, specific_enote_info, m_transaction_history, filename);

        tools::success_msg_writer() << "Enote ownership proof sender generated." << std::endl;
        return true;
    }
    catch (...)
    {
        tools::fail_msg_writer() << "Enote ownership proof sender failed." << std::endl;
        return true;
    }
}
//----------------------------------------------------------------------------------------------------
bool wallet3::get_enote_ownership_proof_receiver_cmd(const std::vector<std::string> &args)
{
    // note: it may be better to include the tx_id and onetime_address in the proof
    // so the checker can check only the file against a reliable ledger

    // 1. check arguments
    std::vector<std::string> local_args = args;
    crypto::key_image key_image;

    if ((local_args.size() != 1))
    {
        PRINT_USAGE(USAGE_GET_ENOTE_OWNERSHIP_PROOF_RECEIVER);
        return true;
    }

    SCOPED_WALLET_UNLOCK();

    try
    {
        // 2. get key_image
        epee::string_tools::hex_to_pod(local_args[0], key_image);
        SpContextualEnoteRecordV1 contextual_enote_record;

        // 3. get contextual enote record from key_image
        m_enote_store.try_get_sp_enote_record(key_image, contextual_enote_record);

        // 4. make proof
        boost::optional<std::string> filename{"tx_enote_ownership_proof_receiver"};
        boost::optional<std::string> str_proof;
        str_proof = get_enote_ownership_proof_receiver(contextual_enote_record.record, m_key_container.get_sp_keys().K_1_base, m_key_container.get_sp_keys().k_vb,contextual_enote_record.origin_context.transaction_id, filename);

        tools::success_msg_writer() << "Enote ownership proof receiver generated." << std::endl;
        return true;
    }
    catch (...)
    {
        tools::fail_msg_writer() << "Enote ownership proof receiver failed." << std::endl;
        return true;
    }
}
//----------------------------------------------------------------------------------------------------
bool wallet3::check_enote_ownership_proof_cmd(const std::vector<std::string> &args)
{
    // note: it may be better to include the tx_id in the proof
    // so the checker can check only the file against a reliable ledger

    // 1. check arguments
    std::vector<std::string> local_args = args;
    boost::optional<std::string> filename{"tx_enote_ownership_proof"};
    boost::optional<std::string> str_proof;
    rct::key expected_amount_commitment, expected_onetime_address;

    if (local_args.size() > 1)
    {
        PRINT_USAGE(USAGE_CHECK_ENOTE_OWNERSHIP_PROOF);
        return true;
    }

    if (local_args.size() > 0)
    {
        filename = local_args[0];
    }

    // 2. read proof from file or string
    EnoteOwnershipProofV1 enote_ownership_proof{};
    try
    {
        ser_EnoteOwnershipProofV1 ser_enote_ownership_proof{
            str_to_proof<ser_EnoteOwnershipProofV1>("SpEnoteOwnershipProofV1", filename, str_proof)};
        recover_enote_ownership_proof_v1(ser_enote_ownership_proof, enote_ownership_proof);
    }
    catch (...)
    {
        tools::fail_msg_writer() << "Failed to retrieve enote ownership proof." << std::endl;
        return true;
    }

    // 3. from tx_id get all output enotes of a tx by querying node.
    std::vector<SpEnoteVariant> vec_enotes = m_ledger_context.get_sp_enotes_out_from_tx(enote_ownership_proof.tx_id);

    // 4. get amount commitment
    expected_onetime_address = enote_ownership_proof.Ko;
    get_amount_commitment_from_tx_id(vec_enotes,expected_onetime_address, expected_amount_commitment);

    // 5. verify proof
    if(verify_enote_ownership_proof_v1(enote_ownership_proof, expected_amount_commitment ,expected_onetime_address))
        tools::success_msg_writer() << "Enote ownership proof is valid." << std::endl;
    else
        tools::fail_msg_writer() << "Enote ownership proof is not valid." << std::endl;

    return true;
}
//----------------------------------------------------------------------------------------------------
// Keys locker
//----------------------------------------------------------------------------------------------------
boost::mutex wallet_keys_unlocker::lockers_lock;
unsigned int wallet_keys_unlocker::lockers = 0;
//----------------------------------------------------------------------------------------------------
wallet_keys_unlocker::wallet_keys_unlocker(wallet3 &w, const boost::optional<tools::password_container> &password) :
    m_wallet3(w),
    m_locked(password != boost::none)
{
    boost::lock_guard<boost::mutex> lock(lockers_lock);
    if (lockers++ > 0)
        m_locked = false;
    if (!m_locked)
    {
        m_locked = false;
        return;
    }
    const epee::wipeable_string pass = password->password();
    w.generate_chacha_key_from_password(pass, m_chacha_key);
    w.decrypt_keys(m_chacha_key);
}
//----------------------------------------------------------------------------------------------------
wallet_keys_unlocker::wallet_keys_unlocker(wallet3 &w, bool locked, const epee::wipeable_string &password) :
    m_wallet3(w),
    m_locked(locked)
{
    boost::lock_guard<boost::mutex> lock(lockers_lock);
    if (lockers++ > 0)
        locked = false;
    if (!locked)
        return;
    w.generate_chacha_key_from_password(password, m_chacha_key);
    w.decrypt_keys(m_chacha_key);
}
//----------------------------------------------------------------------------------------------------
wallet_keys_unlocker::~wallet_keys_unlocker()
{
    try
    {
        boost::lock_guard<boost::mutex> lock(lockers_lock);
        if (lockers == 0)
        {
            MERROR("There are no lockers in wallet_keys_unlocker dtor");
            return;
        }
        --lockers;
        if (!m_locked)
            return;
        m_wallet3.encrypt_keys(m_chacha_key);
    }
    catch (...)
    {
        MERROR("Failed to re-encrypt wallet keys");
    }
}

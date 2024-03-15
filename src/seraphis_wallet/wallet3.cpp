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

// local headers
#include "address_utils.h"
#include "common/command_line.h"
#include "common/i18n.h"
#include "common/password.h"
#include "common/scoped_message_writer.h"
#include "console_handler.h"
#include "crypto/chacha.h"
#include "cryptonote_basic/account.h"
#include "key_container.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "send_receive.h"
#include "seraphis_core/binned_reference_set_utils.h"
#include "seraphis_impl/enote_store_utils.h"
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
#define DEFAULT_INACTIVITY_LOCK_TIMEOUT 90  // seconds

#define PRINT_USAGE(usage_help) fail_msg_writer() << boost::format(tr("usage: %s")) % usage_help;

const char *USAGE_SHOW_BALANCE("balance [detail]");
const char *USAGE_SHOW_TRANSFER("transfer <address> <amount>");
const char *USAGE_SHOW_VIEWALL("save_viewall");
const char *USAGE_SHOW_VIEWRECEIVED("save_viewreceived");
const char *USAGE_SHOW_FINDRECEIVED("save_findreceived");
const char *USAGE_SHOW_ADDRGEN("save_addrgen");

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
    m_ledger_context({0, 10000})
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
    m_cmd_binder.set_handler("create_money",
        boost::bind(&wallet3::on_command, this, &wallet3::create_money, _1),
        tr("Create fake enotes for wallets."));

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

    // 2. terminates idle thread
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
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::create_new_wallet(const epee::wipeable_string &password)
{
    // 1. get chacha_key from password
    crypto::chacha_key chacha_key;
    crypto::generate_chacha_key(password.data(), password.length(), chacha_key, m_kdf_rounds);

    // 2. generate new keys considering a master wallet
    m_key_container.generate_keys();
    if (m_key_container.write_master(m_keys_file, chacha_key))
    {
        m_current_address = m_key_container.get_address_zero(JamtisAddressVersion::V1, JamtisAddressNetwork::MAINNET);
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
    WalletType type = m_key_container.get_wallet_type();
    if (type != WalletType::Master)
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
    WalletType type = m_key_container.get_wallet_type();
    if (type != WalletType::Master && type != WalletType::ViewAll)
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
    WalletType type = m_key_container.get_wallet_type();
    if (type != WalletType::Master && type != WalletType::ViewAll)
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
    WalletType type = m_key_container.get_wallet_type();
    if (type != WalletType::Master && type != WalletType::ViewAll)
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
void wallet3::get_current_address(const epee::wipeable_string &password)
{
    crypto::chacha_key chacha_key;
    crypto::generate_chacha_key(password.data(), password.length(), chacha_key, m_kdf_rounds);

    m_key_container.decrypt(chacha_key);

    m_current_address = m_key_container.get_address_zero(JamtisAddressVersion::V1, JamtisAddressNetwork::MAINNET);

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
        case WalletType::Master:
            tools::msg_writer() << tr("Master wallet loaded.");
            break;
        case WalletType::ViewAll:
            tools::msg_writer() << tr("View-all wallet loaded.");
            break;
        case WalletType::ViewReceived:
            tools::msg_writer() << tr("View-received wallet loaded.");
            break;
        case WalletType::FindReceived:
            tools::msg_writer() << tr("Find-received wallet loaded.");
            break;
        case WalletType::AddrGen:
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
        message_writer() << tr("\"help <command>\" - Show a command's documentation.");
        message_writer() << tr("\"save_viewall\" - Save view-all wallet.");
        message_writer() << tr("\"save_viewreceived\" - Save view-received wallet.");
        message_writer() << tr("\"save_findreceived\" - Save find-received wallet.");
        message_writer() << tr("\"save_addrgen\" - Save address-generator wallet.");
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
bool wallet3::create_money(const std::vector<std::string> &args)
{
    SCOPED_WALLET_UNLOCK();

    std::vector<std::string> local_args = args;

    JamtisDestinationV1 destination_address;
    if (local_args.size() == 0)
    {
        // JamtisDestinationV1 destination_address_random;
        m_key_container.get_random_destination(destination_address);
    }
    else
    {
        get_destination_from_str(local_args[0], destination_address);
    }

    const scanning::ScanMachineConfig refresh_config{
        .reorg_avoidance_increment = 1, .max_chunk_size_hint = 1, .max_partialscan_attempts = 0};

    send_sp_coinbase_amounts_to_user({1000, 1000, 1000, 1000, 1000}, destination_address, m_ledger_context);

    refresh_user_enote_store(m_key_container.get_sp_keys(), refresh_config, m_ledger_context, m_enote_store);

    tools::success_msg_writer() << tr("Five enotes of 1000 each were created to this wallet.");

    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::show_balance(const std::vector<std::string> &args)
{

    SCOPED_WALLET_UNLOCK();

    const scanning::ScanMachineConfig refresh_config{
        .reorg_avoidance_increment = 1, .max_chunk_size_hint = 1, .max_partialscan_attempts = 0};

    refresh_user_enote_store(m_key_container.get_sp_keys(), refresh_config, m_ledger_context, m_enote_store);

    auto balance = get_balance(m_enote_store, {SpEnoteOriginStatus::ONCHAIN}, {SpEnoteSpentStatus::SPENT_ONCHAIN});
    tools::msg_writer() << tr("Wallet balance: ");
    tools::msg_writer() << boost::format(tr("%15s")) % balance;

    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::transfer(const std::vector<std::string> &args)
{

    std::vector<std::string> local_args = args;

    JamtisDestinationV1 destination_address;
    if (local_args.size() != 2)
    {
        tools::fail_msg_writer() << tr("Invalid number of arguments");
        return true;
    }

    SCOPED_WALLET_UNLOCK();

    get_destination_from_str(local_args[0], destination_address);
    rct::xmr_amount amount{std::stoull(local_args[1])};

    // Data for transfer
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
    //  make seraphis membership proofs
    std::vector<rct::xmr_amount> fake_sp_enote_amounts(
        static_cast<std::size_t>(compute_bin_width(bin_config.bin_radius)), 0);

    SpTxSquashedV1 single_tx;
    construct_tx_for_mock_ledger_v1(m_key_container.get_legacy_keys(),
        m_key_container.get_sp_keys(),
        input_selector,
        fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        {{amount, destination_address, TxExtra{}}},
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        m_ledger_context,
        single_tx);

    // validate and submit to the mock ledger
    const sp::mocks::TxValidationContextMock tx_validation_context{m_ledger_context};
    CHECK_AND_ASSERT_THROW_MES(
        validate_tx(single_tx, tx_validation_context), "transfer funds single mock: validating tx failed.");
    CHECK_AND_ASSERT_THROW_MES(try_add_tx_to_ledger(single_tx, m_ledger_context),
        "transfer funds single mock: adding tx to mock ledger failed.");

    refresh_user_enote_store(m_key_container.get_sp_keys(), refresh_config, m_ledger_context, m_enote_store);

    rct::key tx_id;
    get_sp_tx_squashed_v1_txid(single_tx, tx_id);

    tools::msg_writer() << tr("Transaction ") << epee::string_tools::pod_to_hex(tx_id) << tr(" submitted to network.");

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
        // do not propagate through dtor, we'd crash
    }
}

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
#include "common/command_line.h"
#include "common/i18n.h"
#include "common/password.h"
#include "common/scoped_message_writer.h"
#include "console_handler.h"
#include "crypto/chacha.h"
#include "key_container.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "seraphis_wallet/address_utils.h"
#include "string_tools.h"

// seraphis lib
#include "seraphis_impl/enote_store.h"

#include "wallet/wallet2_basic/wallet2_storage.h"

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

// #define REFRESH_PERIOD 90                   // seconds
#define DEFAULT_INACTIVITY_LOCK_TIMEOUT 90  // seconds

#define PRINT_USAGE(usage_help) fail_msg_writer() << boost::format(tr("usage: %s")) % usage_help;

const char *USAGE_SHOW_BALANCE("balance [detail]");
const char *USAGE_SHOW_TRANSFER("transfer <address> <amount>");
const char *USAGE_SHOW_VIEWBALANCE("save_viewbalance");

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
    m_locked(false),
    m_in_command(false),
    m_inactivity_lock_timeout(DEFAULT_INACTIVITY_LOCK_TIMEOUT),
    m_enote_store({0, 0, 0}),
    m_kdf_rounds(1),
    m_load_legacy_wallet(false)
{
    // 1. set commands
    m_cmd_binder.set_handler("help",
        boost::bind(&wallet3::on_command, this, &wallet3::help, _1),
        tr(USAGE_SHOW_VIEWBALANCE),
        tr("Show help."));
    m_cmd_binder.set_handler("save_viewbalance",
        boost::bind(&wallet3::on_command, this, &wallet3::save_viewbalance, _1),
        tr(USAGE_SHOW_VIEWBALANCE),
        tr("Create a viewbalance wallet from a master wallet."));

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
    std::string wallet_path, confirm_creation, confirm_password;   // default empty
    bool keys_file_exists, wallet_file_exists, wallet_name_valid;  // default false

    // 2. loop to load or create new wallet
    do
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
        CHECK_AND_ASSERT_THROW_MES(check_wallet_filenames(wallet_path, keys_file_exists, wallet_file_exists),
            "create_or_open_wallet: failed checking filenames.");

        // 3. if wallet keys exist
        if (keys_file_exists)
        {
            tools::success_msg_writer() << tr("Wallet found");
            auto pw = password_prompter(tr("Enter your wallet password"), false);
            if (m_wallet_version == WalletVersion::Seraphis)
            {
                // 3.1 Seraphis wallet keys found
                try
                {
                    // 3.1.1 try to load wallet from password
                    if (load_wallet(pw.get()))
                    {
                        wallet_name_valid = true;
                    }
                    else
                    {
                        // 3.1.2 wrong password entered
                        tools::fail_msg_writer() << tr("Wrong password.");
                    }
                }
                catch (...)
                {
                }
            }
            else if (m_wallet_version == WalletVersion::Legacy)
            {
                // 3.2 Legacy wallet keys found
                // 3.2.1 Load legacy wallet
                wallet2_basic::load_keys_and_cache_from_file(
                    m_wallet_file, pw.get().password(), m_legacy_cache, m_legacy_keys);
            }
            else
            {
                // Should never get here. Version Unknow.
            }
        }
        // 4. if wallet keys dont exist, try to create a new one
        else
        {
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
                auto pw = password_prompter(tr("Enter a new password for the wallet"), false);

                create_new_wallet(pw.get());

                wallet_name_valid = true;
            }
        }
    }
    while (!wallet_name_valid);

    LOG_ERROR("Failed out of do-while loop in create_or_open_wallet()");
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::load_wallet(const tools::password_container &password)
{
    // 1. get chacha_key from password
    crypto::chacha_key chacha_key;
    crypto::generate_chacha_key(password.password().data(), password.password().length(), chacha_key, m_kdf_rounds);

    // 2. load wallet keys
    unlock_keys_file();
    CHECK_AND_ASSERT_THROW_MES(
        m_key_container.load_from_keys_file(m_keys_file, chacha_key, false), "load_wallet: Error loading wallet.");
    lock_keys_file();

    // TODO
    // 3. load wallet file
    m_current_address =
        m_key_container.get_address_zero(JamtisAddressVersion::V0, JamtisAddressNetwork::MAINNET, chacha_key);
    tools::msg_writer() << "Wallet default address: " + m_current_address;

    print_wallet_type(chacha_key);
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::create_new_wallet(const tools::password_container &password)
{
    // 1. get chacha_key from password
    crypto::chacha_key chacha_key;
    crypto::generate_chacha_key(password.password().data(), password.password().length(), chacha_key, m_kdf_rounds);

    // 2. generate new keys considering a master wallet
    m_key_container.generate_keys(chacha_key);
    m_key_container.write_all(m_keys_file, chacha_key);

    // 3. lock wallet file
    lock_keys_file();

    // 4. show wallet address for index 0
    m_current_address =
        m_key_container.get_address_zero(JamtisAddressVersion::V0, JamtisAddressNetwork::MAINNET, chacha_key);
    tools::msg_writer() << "Wallet default address: " + m_current_address;

    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::create_viewbalance(const tools::password_container &password)
{
    // 1. get chacha_key from password
    crypto::chacha_key chacha_key;
    crypto::generate_chacha_key(password.password().data(), password.password().length(), chacha_key, m_kdf_rounds);

    // 2. check if it is not already a viewbalance wallet
    std::string viewbalance_keys{m_wallet_file + "_viewbalance"};
    THROW_WALLET_EXCEPTION_IF(m_key_container.get_wallet_type(chacha_key) != WalletType::Master,
        tools::error::file_save_error,
        viewbalance_keys);

    // 3. write view balance wallet
    m_key_container.write_view_balance(viewbalance_keys + ".spkeys", chacha_key);

    // 3. lock wallet file
    lock_keys_file();

    // 4. show wallet address for index 0
    m_current_address =
        m_key_container.get_address_zero(JamtisAddressVersion::V0, JamtisAddressNetwork::MAINNET, chacha_key);
    tools::msg_writer() << "Wallet default address: " + m_current_address;

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
void wallet3::prepare_file_names(const std::string &file_path, std::string &keys_file, std::string &wallet_file) {}
//----------------------------------------------------------------------------------------------------
bool wallet3::check_wallet_filenames(const std::string &file_path, bool &keys_file_exists, bool &wallet_file_exists)
{
    std::string keys_file, wallet_file;
    bool legacy_keys;
    WalletVersion version{WalletVersion::Legacy};

    boost::system::error_code ignore;

    // provided name with extension
    if (string_tools::get_extension(file_path) == "spkeys")
    {
        wallet_file = string_tools::cut_off_extension(file_path);
        keys_file   = file_path;
        version     = WalletVersion::Seraphis;
    }
    else if (string_tools::get_extension(file_path) == "keys")
    {
        wallet_file = string_tools::cut_off_extension(file_path);
        keys_file   = file_path;
        version     = WalletVersion::Legacy;
    }
    else if (string_tools::get_extension(file_path) == "spcache")
    {
        wallet_file = string_tools::cut_off_extension(file_path);
        keys_file   = wallet_file + ".spkeys";
        version     = WalletVersion::Seraphis;
    }
    // provided wallet name without extension
    else
    {
        wallet_file = file_path;

        // if legacy wallet exists and we want to load it, then set keys_file to legacy extension
        legacy_keys = boost::filesystem::exists(file_path + ".keys", ignore);
        if (legacy_keys & m_load_legacy_wallet)
        {
            keys_file = wallet_file + ".keys";
            version   = WalletVersion::Legacy;
        }
        // otherwise load or create a seraphis wallet
        else
        {
            keys_file = wallet_file + ".spkeys";
            version   = WalletVersion::Seraphis;
        }
    }

    m_wallet_version = version;
    m_keys_file      = keys_file;
    m_wallet_file    = wallet_file;

    keys_file_exists = boost::filesystem::exists(keys_file, ignore);

    if (m_wallet_version == WalletVersion::Legacy)
        wallet_file_exists = boost::filesystem::exists(wallet_file, ignore);
    else
        wallet_file_exists = boost::filesystem::exists(wallet_file + ".spcache", ignore);

    return true;
}
//----------------------------------------------------------------------------------------------------
void wallet3::print_wallet_type(const crypto::chacha_key &chacha_key)
{
    switch (m_key_container.get_wallet_type(chacha_key))
    {
        case WalletType::Master:
            tools::msg_writer() << tr("Master wallet loaded.");
            break;
        case WalletType::ViewOnly:
            tools::msg_writer() << tr("View-only wallet loaded.");
            break;
        case WalletType::ViewBalance:
            tools::msg_writer() << tr("View-balance wallet loaded.");
            break;
        default:
            tools::fail_msg_writer() << tr("Failed loading wallet type.");
    }
}
//----------------------------------------------------------------------------------------------------
bool wallet3::verify_password(const tools::password_container &pwd_container)
{
    // 1. generate chacha key from password data
    crypto::chacha_key chacha_key;
    crypto::generate_chacha_key(
        pwd_container.password().data(), pwd_container.password().length(), chacha_key, m_kdf_rounds);

    // 2. load and verify keys with provided password
    if (!m_key_container.load_from_keys_file(m_keys_file, chacha_key, true))
    {
        tools::fail_msg_writer() << tr("invalid password");
        return false;
    }

    return true;
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
        return std::string("[") + tr("locked due to inactivity") + "]";

    // 2. show wallet address in use
    std::string prompt = std::string("[") + tr("wallet ") + m_current_address.substr(0, 16);
    prompt += "]: ";
    return prompt;
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
                if (verify_password(pwd_container.get()))
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
        message_writer() << "";
        message_writer() << tr("\"help <command>\" - Show a command's documentation.");
        message_writer() << "";
        message_writer() << tr("\"save_viewonly\" - Save view-only wallet.");
    }
    return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet3::save_viewbalance(const std::vector<std::string> &args)
{
    try
    {
        // 1. get password
        auto pwd_container = default_password_prompter(false);
        CHECK_AND_ASSERT_THROW_MES(pwd_container, "save_viewbalance: failed reading password.");

        // 2. if password entered is correct, create viewbalance wallet
        if (verify_password(pwd_container.get()))
        {
            create_viewbalance(pwd_container->password());
            tools::success_msg_writer() << tr("View-balance wallet saved.");
        }
        else
        {
            tools::fail_msg_writer() << tr("Wrong password.");
        }
    }
    catch (const std::exception &e)
    {
        tools::fail_msg_writer() << tr("Failed to save view-balance wallet. ");
        return true;
    }
    return true;
}

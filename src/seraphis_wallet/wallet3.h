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

// local headers
#include "common/password.h"
#include "common/scoped_message_writer.h"
#include "common/util.h"
#include "console_handler.h"
#include "crypto/chacha.h"
#include "key_container.h"
#include "math_helper.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_wallet/address_utils.h"
#include "seraphis_wallet/transaction_history.h"
#include "wallet/wallet2_basic/wallet2_storage.h"

// mocks - to be deleted
#include "seraphis_mocks/mock_ledger_context.h"

// standard headers
#include <boost/program_options/variables_map.hpp>
#include <string>
#include <vector>

// forward declarations

using namespace sp;
using namespace jamtis;
using namespace seraphis_wallet;

class wallet3;

enum class WalletDerivation
{
    Legacy,
    Seraphis
};

class wallet_keys_unlocker
{
   public:
    wallet_keys_unlocker(wallet3 &w, const boost::optional<tools::password_container> &password);
    wallet_keys_unlocker(wallet3 &w, bool locked, const epee::wipeable_string &password);
    ~wallet_keys_unlocker();

   private:
    wallet3 &m_wallet3;
    bool m_locked;
    crypto::chacha_key m_chacha_key;
    static boost::mutex lockers_lock;
    static unsigned int lockers;
};

class wallet3
{
    /// member functions
   public:
    wallet3();
    bool init();
    bool run();
    void stop();

   private:
    // load, create and close wallet
    bool create_or_open_wallet();
    bool ask_wallet_name(std::string &wallet_path, bool &keys_file_exists, bool &wallet_file_exists);
    bool try_to_load_wallet(bool &wallet_name_valid);
    bool try_to_create_wallet(const std::string &wallet_path, bool &wallet_name_valid);
    bool load_keys_and_cache_from_file_sp(const epee::wipeable_string& password);
    bool create_new_wallet(const epee::wipeable_string& password);
    bool handle_legacy_keys(const cryptonote::account_base &legacy_keys, const epee::wipeable_string& password);
    bool close_wallet();

    // save/load enote_store and tx_history
    bool save_enote_and_tx_store(const crypto::chacha_key &key);
    bool load_enote_and_tx_store(const crypto::chacha_key &key);


    // wallet tiers
    bool create_view_all(const epee::wipeable_string& password);
    bool create_view_received(const epee::wipeable_string &password);
    bool create_find_received(const epee::wipeable_string &password);
    bool create_address_generator(const epee::wipeable_string &password);

    // wallet file manipulation
    void prepare_file_names(const std::string &file_path, std::string &keys_file, std::string &wallet_file);
    bool check_wallet_filenames(const std::string &file_path, bool &keys_file_exists, bool &wallet_file_exists);

    // wallet info
    void print_wallet_type();
    void get_current_address(const epee::wipeable_string& password);

    // manipulate password
    bool verify_password(const epee::wipeable_string& password);
    boost::optional<tools::password_container> get_and_verify_password();
    boost::optional<tools::password_container> password_prompter(const char *prompt, bool verify);
    boost::optional<tools::password_container> default_password_prompter(bool creation);
    void generate_chacha_key_from_password(const epee::wipeable_string &pass, crypto::chacha_key &key);

    // lock/unlock key file
    bool is_keys_file_locked() const;
    bool lock_keys_file();
    bool unlock_keys_file();

    // encrypt/decrypt keys in memory
    bool is_password_expected() const {return m_password_expected;}
    void encrypt_keys(const crypto::chacha_key &key);
    void decrypt_keys(const crypto::chacha_key &key);

    // console handler
    bool on_unknown_command(const std::vector<std::string> &args);
    bool on_empty_command();
    bool on_cancelled_command();
    bool on_command(bool (wallet3::*cmd)(const std::vector<std::string> &), const std::vector<std::string> &args);
    std::string get_prompt() const;
    bool get_command();
    std::string input_line(const std::string &prompt, bool yesno);
    tools::scoped_message_writer message_writer(epee::console_colors color = epee::console_color_default,
        bool bright                                                        = false);

    // inactivity check and idle thread
    uint32_t inactivity_lock_timeout() const { return m_inactivity_lock_timeout; }
    void inactivity_lock_timeout(uint32_t seconds) { m_inactivity_lock_timeout = seconds; }
    void check_for_inactivity_lock(bool user);
    void wallet_idle_thread();
    bool check_inactivity();

    // commands and help
    bool help(const std::vector<std::string> &args);
    bool save_viewall(const std::vector<std::string> &args);
    bool save_viewreceived(const std::vector<std::string> &args);
    bool save_findreceived(const std::vector<std::string> &args);
    bool save_addrgen(const std::vector<std::string> &args);

    // Experimental testing functions
    bool create_money(const std::vector<std::string> &args);
    bool show_address(const std::vector<std::string> &args);
    bool show_balance(const std::vector<std::string> &args);
    bool transfer(const std::vector<std::string> &args);
    bool show_enotes_cmd(const std::vector<std::string> &args);
    bool show_specific_enote_cmd(const std::vector<std::string> &args);
    bool get_enote_ownership_proof_sender_cmd(const std::vector<std::string> &args);
    bool check_enote_ownership_proof_cmd(const std::vector<std::string> &args);

    /// member variables

    // legacy wallet
    wallet2_basic::keys_data m_legacy_keys;
    wallet2_basic::cache m_legacy_cache;

    // wallet file and address
    std::string m_current_address;
    std::string m_keys_file;
    std::string m_wallet_file;
    WalletDerivation m_wallet_derivation;
    std::unique_ptr<tools::file_locker> m_keys_file_locker;
    address_index_t m_current_index{make_address_index(0, 0)};
    WalletType m_wallet_type;
    uint64_t m_kdf_rounds;
    JamtisAddressNetwork m_address_network;
    JamtisAddressVersion m_address_version;

    // keys, enotes storage and tx_history
    KeyContainer m_key_container;
    SpEnoteStore m_enote_store{0, 0, 0};
    SpTransactionHistory m_transaction_history;

    // ledger context
    // (TEMPORARY)
    sp::mocks::MockLedgerContext m_ledger_context{0, 10000};

    // multithreading and console handler
    std::atomic<time_t> m_last_activity_time;
    std::atomic<bool> m_locked;
    std::atomic<bool> m_in_command;
    epee::console_handlers_binder m_cmd_binder;
    uint32_t m_inactivity_lock_timeout;
    epee::math_helper::once_a_time_seconds<1> m_inactivity_checker;
    std::atomic<bool> m_idle_run;
    boost::thread m_idle_thread;
    boost::mutex m_idle_mutex;
    boost::condition_variable m_idle_cond;
    bool m_password_expected;
    std::atomic<bool> m_auto_refresh_enabled;
    bool m_auto_refresh_refreshing;

    friend class wallet_keys_unlocker;
};

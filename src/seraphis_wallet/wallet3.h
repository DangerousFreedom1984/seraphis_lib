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
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_impl/enote_store.h"
#include "wallet/wallet2_basic/wallet2_storage.h"

// standard headers
#include <string>
#include <vector>

// forward declarations

using namespace sp;
using namespace jamtis;
using namespace seraphis_wallet;

enum class WalletVersion
{
    Legacy,
    Seraphis
};
class wallet3
{
// member functions
   public:
    wallet3();
    bool init();
    bool run();
    void stop();

   private:
    // load, create and close wallet
    bool create_or_open_wallet();
    bool load_wallet(const tools::password_container &password);
    bool create_new_wallet(const tools::password_container &password);
    bool create_viewbalance(const tools::password_container &password);
    bool close_wallet();

    // wallet file manipulation
    void prepare_file_names(const std::string &file_path, std::string &keys_file, std::string &wallet_file);
    bool check_wallet_filenames(const std::string &file_path, bool &keys_file_exists, bool &wallet_file_exists);

    // wallet info
    void print_wallet_type(const crypto::chacha_key &chacha_key);

    // manipulate password
    bool verify_password(const tools::password_container &password);
    boost::optional<tools::password_container> password_prompter(const char *prompt, bool verify);
    boost::optional<tools::password_container> default_password_prompter(bool verify);

    // lock/unlock key file
    bool is_keys_file_locked() const;
    bool lock_keys_file();
    bool unlock_keys_file();

    // console handler
    bool on_unknown_command(const std::vector<std::string> &args);
    bool on_empty_command();
    bool on_cancelled_command();
    bool on_command(bool (wallet3::*cmd)(const std::vector<std::string> &), const std::vector<std::string> &args);
    std::string get_prompt() const;
    bool get_command();
    std::string input_line(const std::string &prompt, bool yesno);
    tools::scoped_message_writer message_writer(epee::console_colors color = epee::console_color_default, bool bright = false);

    // inactivity check and idle thread
    uint32_t inactivity_lock_timeout() const { return m_inactivity_lock_timeout; }
    void inactivity_lock_timeout(uint32_t seconds) { m_inactivity_lock_timeout = seconds; }
    void check_for_inactivity_lock(bool user);
    void wallet_idle_thread();
    bool check_inactivity();

    // commands and help
    bool help(const std::vector<std::string> &args);
    bool save_viewbalance(const std::vector<std::string> &args);

// member variables
    // legacy wallet
    wallet2_basic::keys_data m_legacy_keys;
    wallet2_basic::cache m_legacy_cache;

    // wallet file and address
    std::string m_current_address;
    std::string m_keys_file;
    std::string m_wallet_file;
    WalletVersion m_wallet_version;
    bool m_load_legacy_wallet;
    std::unique_ptr<tools::file_locker> m_keys_file_locker;
    address_index_t m_current_index{make_address_index(0, 0)};
    WalletType m_wallet_type;
    uint64_t m_kdf_rounds;

    // keys and enotes storage
    KeyContainer m_key_container;
    SpEnoteStore m_enote_store{0, 0, 0};

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
};

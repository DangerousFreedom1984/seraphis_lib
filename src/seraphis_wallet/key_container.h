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

#pragma once

// local headers
#include "crypto/chacha.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/account.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_wallet/address_utils.h"
#include "seraphis_wallet/jamtis_keys.h"
#include "serialization/serialization.h"

// third party headers

// standard headers
#include <string>

// forward declarations

using namespace sp::jamtis;

// NOTE: I don't think this is a good idea.
struct ser_JamtisKeys
{
    crypto::secret_key k_s_legacy;    //legacy spend-key
    crypto::secret_key k_v_legacy;    //legacy view-key
    crypto::secret_key k_m;          // master
    crypto::secret_key k_vb;         // view-balance
    crypto::x25519_secret_key xk_ua; // unlock-amounts
    crypto::x25519_secret_key xk_fr; // find-received
    crypto::secret_key s_ga;         // generate-address
    crypto::secret_key s_ct;         // cipher-tag
    rct::key K_1_base;               // jamtis spend base     = k_vb X + k_m U
    crypto::x25519_pubkey xK_ua;     // unlock-amounts pubkey = xk_ua xG
    crypto::x25519_pubkey xK_fr;     // find-received pubkey  = xk_fr xk_ua xG

    BEGIN_SERIALIZE()
    FIELD(k_s_legacy)
    FIELD(k_v_legacy)
    FIELD(k_m)
    FIELD(k_vb)
    FIELD(xk_ua)
    FIELD(xk_fr)
    FIELD(s_ga)
    FIELD(s_ct)
    FIELD(K_1_base)
    FIELD(xK_ua)
    FIELD(xK_fr)
    END_SERIALIZE()
};

struct ser_KeyContainer
{
    crypto::chacha_iv encryption_iv;
    ser_JamtisKeys keys;
    bool encrypted;

    BEGIN_SERIALIZE()
    FIELD(keys)
    FIELD(encryption_iv)
    FIELD(encrypted)
    END_SERIALIZE()
};

BLOB_SERIALIZER(ser_JamtisKeys);
BLOB_SERIALIZER(ser_KeyContainer);

namespace seraphis_wallet
{

enum class WalletType
{
    Master,
    ViewAll,
    ViewReceived,
    FindReceived,
    AddrGen,
};

/// KeyContainer
// - it handles (store, load, generate, etc) the private keys.
///
class KeyContainer
{
public:
    KeyContainer(JamtisKeys &&sp_keys, LegacyKeys &&legacy_keys, const crypto::chacha_key &key);

    KeyContainer() : m_sp_keys{}, m_legacy_keys{}, m_encryption_iv{}, m_encrypted{false} {}

    KeyContainer(JamtisKeys &&sp_keys,
        LegacyKeys &&legacy_keys,
        bool encrypted,
        const crypto::chacha_iv encryption_iv);

    // member functions

    /// verify if is encrypted
    bool is_encrypted() const {return m_encrypted; }

    /// load keys from a file and ensure their validity
    bool load_from_keys_file(const std::string &path, const crypto::chacha_key &chacha_key, bool check);

    /// verify if password is valid
    bool verify_password(const crypto::chacha_key &chacha_key);

    /// check if keys are valid 
    bool jamtis_keys_valid(const JamtisKeys &keys, const crypto::chacha_key &chacha_key);

    /// encrypt keys in-memory
    bool encrypt(const crypto::chacha_key &chacha_key);

    /// decrypt keys in-memory
    bool decrypt(const crypto::chacha_key &chacha_key);

    /// convert legacy keys format into new legacy keys struct
    void convert_legacy_keys(const cryptonote::account_base &legacy_keys);

    /// derive seraphis_keys from legacy
    void derive_seraphis_keys_from_legacy();

    /// generate new keys
    void generate_keys();

    /// write wallet tiers
    bool write_master(const std::string &path, crypto::chacha_key const &chacha_key);
    bool write_view_all(const std::string &path, const crypto::chacha_key &chacha_key);
    bool write_view_received(const std::string &path, const crypto::chacha_key &chacha_key);
    bool write_find_received(const std::string &path, const crypto::chacha_key &chacha_key);
    bool write_address_generator(const std::string &path, const crypto::chacha_key &chacha_key);

    /// get the wallet type of the loaded keys
    WalletType get_wallet_type();
    WalletType get_wallet_type(const JamtisKeys sp_keys);

    /// get a random address for loaded wallet
    std::string get_address_random(const JamtisAddressVersion address_version, const JamtisAddressNetwork address_network);
    void get_random_destination(JamtisDestinationV1 &dest_out);

    /// get the zero address for loaded wallet
    std::string get_address_zero(const JamtisAddressVersion address_version, const JamtisAddressNetwork address_network);

    /// make jamtis_keys serializable
    void make_serializable_jamtis_keys(ser_JamtisKeys &serializable_keys);

    /// recover keys from serializable
    void recover_jamtis_keys(const ser_JamtisKeys &ser_keys, JamtisKeys &keys_out);

    /// compare the keys of two containers that have the same chacha_key
    bool compare_keys(KeyContainer &other, const crypto::chacha_key &chacha_key);

    /// return keys
    const JamtisKeys& get_sp_keys() const {return m_sp_keys;}
    const LegacyKeys& get_legacy_keys() const {return m_legacy_keys;}


private:
    /// initialization vector
    crypto::chacha_iv m_encryption_iv;

    /// struct that contains the seraphis private keys 
    epee::mlocked<JamtisKeys> m_sp_keys;

    /// struct that contains the legacy private keys 
    epee::mlocked<LegacyKeys> m_legacy_keys;

    /// true if keys are encrypted in memory
    bool m_encrypted;
};

class KeyGuard
{
public:
    KeyGuard(KeyContainer &, const crypto::chacha_key &);

    KeyGuard(const KeyGuard &other);

    ~KeyGuard();

private:
    const crypto::chacha_key &m_key;
    int m_ref;
    KeyContainer &m_container;
};

} // namespace seraphis_wallet

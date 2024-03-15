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
#include "key_container.h"

// local headers
#include "crypto/chacha.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "cryptonote_basic/account.h"
#include "ringct/rctOps.h"
#include "seraphis_core/jamtis_core_utils.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "seraphis_wallet/address_utils.h"
#include "seraphis_wallet/encrypted_file.h"
#include "seraphis_wallet/jamtis_keys.h"

// standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_wallet"

namespace seraphis_wallet
{
//-------------------------------------------------------------------------------------------------------------------
KeyContainer::KeyContainer(JamtisKeys &&sp_keys, LegacyKeys &&legacy_keys, const crypto::chacha_key &key) :
    m_sp_keys{sp_keys},
    m_legacy_keys{legacy_keys},
    m_encrypted{false},
    m_encryption_iv{}
{
    encrypt(key);
}
//-------------------------------------------------------------------------------------------------------------------
KeyContainer::KeyContainer(JamtisKeys &&sp_keys,
    LegacyKeys &&legacy_keys,
    bool encrypted,
    const crypto::chacha_iv encryption_iv) :
    m_sp_keys{sp_keys},
    m_legacy_keys{legacy_keys},
    m_encrypted{encrypted},
    m_encryption_iv{encryption_iv}
{
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::load_from_keys_file(const std::string &path, const crypto::chacha_key &chacha_key, bool check)
{
    // 1. define serializable
    ser_JamtisKeys ser_keys;

    // 2. get the keys in the encrypted file into the serializable
    if (!read_encrypted_file(path, chacha_key, ser_keys))
    {
        // write in log: "load_from_keys_file: failed reading encrypted file.";
        return false;
    }

    // 3. recover jamtis keys
    JamtisKeys recovered_keys{};
    recover_jamtis_keys(ser_keys, recovered_keys);

    // 4. check if keys are valid and move to m_keys if not verifying password
    if (!jamtis_keys_valid(recovered_keys, chacha_key))
    {
        // write in log: "load_from_keys_file: failed validating jamtis keys.";
        return false;
    }

    if (check)
        return true;

    // 5. store keys in m_sp_keys
    m_sp_keys = std::move(recovered_keys);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::verify_password(const crypto::chacha_key &chacha_key)
{
    // 1. decrypt keys if they are encrypted in memory
    if (m_encrypted)
        decrypt(chacha_key);

    // 2. test if keys are valid
    bool r = jamtis_keys_valid(m_sp_keys, chacha_key);

    // 3. encrypt keys if they are decrypted
    if (!m_encrypted)
        encrypt(chacha_key);

    return r;
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::jamtis_keys_valid(const JamtisKeys &keys, const crypto::chacha_key &chacha_key)
{
    // 1. make test_keys = keys
    JamtisKeys test_keys{keys};

    // 2. derive keys
    switch (get_wallet_type(keys))
    {
        case WalletType::Master:
        {
            sp::jamtis::make_jamtis_unlockamounts_key(test_keys.k_vb, test_keys.xk_ua);
            sp::jamtis::make_jamtis_findreceived_key(test_keys.k_vb, test_keys.xk_fr);
            sp::jamtis::make_jamtis_generateaddress_secret(test_keys.k_vb, test_keys.s_ga);
            sp::jamtis::make_jamtis_ciphertag_secret(test_keys.s_ga, test_keys.s_ct);
            sp::make_seraphis_spendkey(test_keys.k_vb, test_keys.k_m, test_keys.K_1_base);
            sp::jamtis::make_jamtis_unlockamounts_pubkey(test_keys.xk_ua, test_keys.xK_ua);
            sp::jamtis::make_jamtis_findreceived_pubkey(test_keys.xk_fr, test_keys.xK_ua, test_keys.xK_fr);
            break;
        }
        case WalletType::ViewAll:
        {
            sp::jamtis::make_jamtis_unlockamounts_key(test_keys.k_vb, test_keys.xk_ua);
            sp::jamtis::make_jamtis_findreceived_key(test_keys.k_vb, test_keys.xk_fr);
            sp::jamtis::make_jamtis_generateaddress_secret(test_keys.k_vb, test_keys.s_ga);
            sp::jamtis::make_jamtis_ciphertag_secret(test_keys.s_ga, test_keys.s_ct);
            sp::jamtis::make_jamtis_unlockamounts_pubkey(test_keys.xk_ua, test_keys.xK_ua);
            sp::jamtis::make_jamtis_findreceived_pubkey(test_keys.xk_fr, test_keys.xK_ua, test_keys.xK_fr);
            break;
        }
        case WalletType::ViewReceived:
        {
            sp::jamtis::make_jamtis_ciphertag_secret(test_keys.s_ga, test_keys.s_ct);
            sp::jamtis::make_jamtis_unlockamounts_pubkey(test_keys.xk_ua, test_keys.xK_ua);
            sp::jamtis::make_jamtis_findreceived_pubkey(test_keys.xk_fr, test_keys.xK_ua, test_keys.xK_fr);
            break;
        }
        case WalletType::FindReceived:
        {
            sp::jamtis::make_jamtis_findreceived_pubkey(test_keys.xk_fr, test_keys.xK_ua, test_keys.xK_fr);
            break;
        }
        case WalletType::AddrGen:
        {
            sp::jamtis::make_jamtis_ciphertag_secret(test_keys.s_ga, test_keys.s_ct);
            break;
        }
        default:
        {
            return false;
        }
    }

    // 3. check if derived keys are correct
    return test_keys == keys;
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::encrypt(const crypto::chacha_key &chacha_key)
{
    // 1. return false if already encrypted
    if (m_encrypted)
        return false;

    // 2. generate new iv
    m_encryption_iv = crypto::rand<crypto::chacha_iv>();

    // 3. encrypt keys with chacha_key and iv
    m_sp_keys.encrypt(chacha_key, m_encryption_iv);

    // 4. set encrypted flag true
    m_encrypted = true;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::decrypt(const crypto::chacha_key &chacha_key)
{
    // 1. return false if already decrypted
    if (!m_encrypted)
        return false;

    // 2. decrypt keys with chacha_key and iv
    m_sp_keys.decrypt(chacha_key, m_encryption_iv);

    // 3. set encrypted flag false
    m_encrypted = false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void KeyContainer::convert_legacy_keys(const cryptonote::account_base &legacy_keys)
{
    m_sp_keys.k_s_legacy = legacy_keys.get_keys().m_spend_secret_key;
    m_sp_keys.k_v_legacy = legacy_keys.get_keys().m_view_secret_key;
    m_legacy_keys.k_s    = legacy_keys.get_keys().m_spend_secret_key;
    m_legacy_keys.k_v    = legacy_keys.get_keys().m_view_secret_key;
    m_legacy_keys.Ks     = rct::pk2rct(legacy_keys.get_keys().m_account_address.m_spend_public_key);
    m_legacy_keys.Kv     = rct::pk2rct(legacy_keys.get_keys().m_account_address.m_view_public_key);
}
//-------------------------------------------------------------------------------------------------------------------
void KeyContainer::derive_seraphis_keys_from_legacy()
{
    // Spec: https://gist.github.com/tevador/50160d160d24cfc6c52ae02eb3d17024#33-elliptic-curves

    m_sp_keys.k_m = m_legacy_keys.k_s;
    make_jamtis_viewbalance_key(m_sp_keys.k_m, m_sp_keys.k_vb);
    make_jamtis_unlockamounts_key(m_sp_keys.k_vb, m_sp_keys.xk_ua);
    make_jamtis_findreceived_key(m_sp_keys.k_vb, m_sp_keys.xk_fr);
    make_jamtis_generateaddress_secret(m_sp_keys.k_vb, m_sp_keys.s_ga);
    make_jamtis_ciphertag_secret(m_sp_keys.s_ga, m_sp_keys.s_ct);
    make_seraphis_spendkey(m_sp_keys.k_vb, m_sp_keys.k_m, m_sp_keys.K_1_base);
    make_jamtis_unlockamounts_pubkey(m_sp_keys.xk_ua, m_sp_keys.xK_ua);
    make_jamtis_findreceived_pubkey(m_sp_keys.xk_fr, m_sp_keys.xK_ua, m_sp_keys.xK_fr);
}
//-------------------------------------------------------------------------------------------------------------------
void KeyContainer::generate_keys()
{
    // 1. generate new keys and store to m_keys
    make_jamtis_keys(m_sp_keys);
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::write_master(const std::string &path, const crypto::chacha_key &chacha_key)
{
    // 1. decrypt keys if they are encrypted in memory
    if (m_encrypted)
        decrypt(chacha_key);

    // 2. copy keys to serializable
    // (the serializable with the decrypted private keys will
    // remain in memory only during the scope of the function)
    ser_JamtisKeys ser_keys = {
        .k_s_legacy = m_sp_keys.k_s_legacy,
        .k_v_legacy = m_sp_keys.k_v_legacy,
        .k_m        = m_sp_keys.k_m,
        .k_vb       = m_sp_keys.k_vb,
        .xk_ua      = m_sp_keys.xk_ua,
        .xk_fr      = m_sp_keys.xk_fr,
        .s_ga       = m_sp_keys.s_ga,
        .s_ct       = m_sp_keys.s_ct,
        .K_1_base   = m_sp_keys.K_1_base,
        .xK_ua      = m_sp_keys.xK_ua,
        .xK_fr      = m_sp_keys.xK_fr,
    };

    // 4. write serializable to file
    return write_encrypted_file(path, chacha_key, ser_keys);
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::write_view_all(const std::string &path, const crypto::chacha_key &chacha_key)
{
    // 1. decrypt keys if they are encrypted in memory
    if (m_encrypted)
        decrypt(chacha_key);

    // 2. copy keys to serializable
    // (the serializable with the decrypted private keys will
    // remain in memory only during the scope of the function)
    ser_JamtisKeys view_all{
        .k_s_legacy = {},
        .k_v_legacy = m_sp_keys.k_v_legacy,
        .k_m      = {},
        .k_vb     = m_sp_keys.k_vb,
        .xk_ua    = m_sp_keys.xk_ua,
        .xk_fr    = m_sp_keys.xk_fr,
        .s_ga     = m_sp_keys.s_ga,
        .s_ct     = m_sp_keys.s_ct,
        .K_1_base = m_sp_keys.K_1_base,
        .xK_ua    = m_sp_keys.xK_ua,
        .xK_fr    = m_sp_keys.xK_fr,
    };

    // 3. write serializable to file
    return write_encrypted_file(path, chacha_key, view_all);
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::write_view_received(const std::string &path, const crypto::chacha_key &chacha_key)
{
    // 1. decrypt keys if they are encrypted in memory
    if (m_encrypted)
        decrypt(chacha_key);

    // 2. copy keys to serializable
    // (the serializable with the decrypted private keys will
    // remain in memory only during the scope of the function)
    ser_JamtisKeys view_received{
        .k_s_legacy = {},
        .k_v_legacy = m_sp_keys.k_v_legacy,
        .k_m      = {},
        .k_vb     = {},
        .xk_ua    = m_sp_keys.xk_ua,
        .xk_fr    = m_sp_keys.xk_fr,
        .s_ga     = m_sp_keys.s_ga,
        .s_ct     = m_sp_keys.s_ct,
        .K_1_base = m_sp_keys.K_1_base,
        .xK_ua    = m_sp_keys.xK_ua,
        .xK_fr    = m_sp_keys.xK_fr,
    };

    // 3. write serializable to file
    return write_encrypted_file(path, chacha_key, view_received);
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::write_find_received(const std::string &path, const crypto::chacha_key &chacha_key)
{
    // 1. decrypt keys if they are encrypted in memory
    if (m_encrypted)
        decrypt(chacha_key);

    // 2. copy keys to serializable
    // (the serializable with the decrypted private keys will
    // remain in memory only during the scope of the function)
    ser_JamtisKeys find_received{
        .k_s_legacy = {},
        .k_v_legacy = m_sp_keys.k_v_legacy,
        .k_m      = {},
        .k_vb     = {},
        .xk_ua    = {},
        .xk_fr    = m_sp_keys.xk_fr,
        .s_ga     = {},
        .s_ct     = {},
        .K_1_base = m_sp_keys.K_1_base,
        .xK_ua    = m_sp_keys.xK_ua,
        .xK_fr    = m_sp_keys.xK_fr,
    };

    // 3. write serializable to file
    return write_encrypted_file(path, chacha_key, find_received);
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::write_address_generator(const std::string &path, const crypto::chacha_key &chacha_key)
{
    // 1. decrypt keys if they are encrypted in memory
    if (m_encrypted)
        decrypt(chacha_key);

    // 2. copy keys to serializable
    // (the serializable with the decrypted private keys will
    // remain in memory only during the scope of the function)
    ser_JamtisKeys address_generator{
        .k_s_legacy = {},
        .k_v_legacy = m_sp_keys.k_v_legacy,
        .k_m      = {},
        .k_vb     = {},
        .xk_ua    = {},
        .xk_fr    = {},
        .s_ga     = m_sp_keys.s_ga,
        .s_ct     = m_sp_keys.s_ct,
        .K_1_base = m_sp_keys.K_1_base,
        .xK_ua    = m_sp_keys.xK_ua,
        .xK_fr    = m_sp_keys.xK_fr,
    };

    // 3. write serializable to file
    return write_encrypted_file(path, chacha_key, address_generator);
}
//-------------------------------------------------------------------------------------------------------------------
WalletType KeyContainer::get_wallet_type()
{
    return get_wallet_type(m_sp_keys);
}
//-------------------------------------------------------------------------------------------------------------------
WalletType KeyContainer::get_wallet_type(const JamtisKeys sp_keys)
{
    // 1. check which keys are present
    if (sp_keys.k_m == rct::rct2sk(rct::zero()))
    {
        if (sp_keys.k_vb == rct::rct2sk(rct::zero()))
        {
            if (sp_keys.xk_ua == crypto::x25519_secret_key{})
            {
                if (sp_keys.xk_fr == crypto::x25519_secret_key{})
                    return WalletType::AddrGen;
                else
                    return WalletType::FindReceived;
            }
            return WalletType::ViewReceived;
        }
        else
            return WalletType::ViewAll;
    }
    return WalletType::Master;
}
//-------------------------------------------------------------------------------------------------------------------
std::string KeyContainer::get_address_random(const JamtisAddressVersion address_version,
    const JamtisAddressNetwork address_network)
{
    // 1. get a random destination address
    std::string str_address;
    JamtisDestinationV1 dest_address;
    make_destination_random(m_sp_keys, dest_address);
    get_str_from_destination(dest_address, address_version, address_network, str_address);

    // 2. return address
    return str_address;
}
//-------------------------------------------------------------------------------------------------------------------
void KeyContainer::get_random_destination(JamtisDestinationV1 &dest_out)
{
    make_destination_random(m_sp_keys, dest_out);
}
//-------------------------------------------------------------------------------------------------------------------
std::string KeyContainer::get_address_zero(const JamtisAddressVersion address_version,
    const JamtisAddressNetwork address_network)
{

    // 1. get destination address corresponding to index zero
    std::string str_address;
    JamtisDestinationV1 dest_address;
    make_destination_zero(m_sp_keys, dest_address);
    get_str_from_destination(dest_address, address_version, address_network, str_address);

    // 2. return address
    return str_address;
}
//-------------------------------------------------------------------------------------------------------------------
void KeyContainer::make_serializable_jamtis_keys(ser_JamtisKeys &serializable_keys)
{
    serializable_keys.k_s_legacy = m_sp_keys.k_s_legacy;
    serializable_keys.k_v_legacy = m_sp_keys.k_v_legacy;
    serializable_keys.k_m        = m_sp_keys.k_m;
    serializable_keys.k_vb       = m_sp_keys.k_vb;
    serializable_keys.xk_ua      = m_sp_keys.xk_ua;
    serializable_keys.xk_fr      = m_sp_keys.xk_fr;
    serializable_keys.s_ga       = m_sp_keys.s_ga;
    serializable_keys.s_ct       = m_sp_keys.s_ct;
    serializable_keys.K_1_base   = m_sp_keys.K_1_base;
    serializable_keys.xK_ua      = m_sp_keys.xK_ua;
    serializable_keys.xK_fr      = m_sp_keys.xK_fr;
}
//-------------------------------------------------------------------------------------------------------------------
void KeyContainer::recover_jamtis_keys(const ser_JamtisKeys &ser_keys, JamtisKeys &keys_out)
{
    keys_out.k_s_legacy = ser_keys.k_s_legacy;
    keys_out.k_v_legacy = ser_keys.k_v_legacy;
    keys_out.k_m        = ser_keys.k_m;
    keys_out.k_vb       = ser_keys.k_vb;
    keys_out.xk_ua      = ser_keys.xk_ua;
    keys_out.xk_fr      = ser_keys.xk_fr;
    keys_out.s_ga       = ser_keys.s_ga;
    keys_out.s_ct       = ser_keys.s_ct;
    keys_out.K_1_base   = ser_keys.K_1_base;
    keys_out.xK_ua      = ser_keys.xK_ua;
    keys_out.xK_fr      = ser_keys.xK_fr;
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::compare_keys(KeyContainer &other, const crypto::chacha_key &chacha_key)
{

    bool r = other.m_sp_keys.k_s_legacy == m_sp_keys.k_s_legacy &&
        other.m_sp_keys.k_v_legacy == m_sp_keys.k_v_legacy &&
        other.m_sp_keys.k_m == m_sp_keys.k_m && other.m_sp_keys.k_vb == m_sp_keys.k_vb &&
        other.m_sp_keys.xk_ua == m_sp_keys.xk_ua && other.m_sp_keys.xk_fr == m_sp_keys.xk_fr &&
        other.m_sp_keys.s_ga == m_sp_keys.s_ga && other.m_sp_keys.s_ct == m_sp_keys.s_ct &&
        other.m_sp_keys.K_1_base == m_sp_keys.K_1_base && other.m_sp_keys.xK_ua == m_sp_keys.xK_ua &&
        other.m_sp_keys.xK_fr == m_sp_keys.xK_fr;

    // 5. return result of comparison
    return r;
}
//-------------------------------------------------------------------------------------------------------------------
// KeyGuard
//-------------------------------------------------------------------------------------------------------------------
KeyGuard::KeyGuard(const KeyGuard &other) :
    m_ref{other.m_ref + 1},
    m_container{other.m_container},
    m_key{other.m_key}
{
}
//-------------------------------------------------------------------------------------------------------------------
KeyGuard::KeyGuard(KeyContainer &container, const crypto::chacha_key &key) :
    m_container{container},
    m_ref{1},
    m_key{key}
{
    m_container.encrypt(key);
}
//-------------------------------------------------------------------------------------------------------------------
KeyGuard::~KeyGuard()
{
    if (m_ref == 1)
    {
        m_container.encrypt(m_key);
    }
}
//-------------------------------------------------------------------------------------------------------------------
}  // namespace seraphis_wallet

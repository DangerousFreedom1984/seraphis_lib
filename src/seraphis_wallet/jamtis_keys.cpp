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

// NOT FOR PRODUCTION

// paired header
#include "jamtis_keys.h"

// local headers
#include "crypto/chacha.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "device/device.hpp"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_core_utils.h"
#include "seraphis_core/legacy_core_utils.h"
#include "seraphis_core/sp_core_enote_utils.h"

// third party headers

// standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_wallet"

namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
void make_legacy_keys(LegacyKeys &keys_out)
{
    keys_out.k_s = rct::rct2sk(rct::skGen());
    keys_out.k_v = rct::rct2sk(rct::skGen());
    keys_out.Ks  = rct::scalarmultBase(rct::sk2rct(keys_out.k_s));
    keys_out.Kv  = rct::scalarmultBase(rct::sk2rct(keys_out.k_v));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_keys(JamtisKeys &keys_out)
{
    keys_out.k_m        = rct::rct2sk(rct::skGen());
    keys_out.k_vb       = rct::rct2sk(rct::skGen());
    make_jamtis_unlockamounts_key(keys_out.k_vb, keys_out.xk_ua);
    make_jamtis_findreceived_key(keys_out.k_vb, keys_out.xk_fr);
    make_jamtis_generateaddress_secret(keys_out.k_vb, keys_out.s_ga);
    make_jamtis_ciphertag_secret(keys_out.s_ga, keys_out.s_ct);
    make_seraphis_spendkey(keys_out.k_vb, keys_out.k_m, keys_out.K_1_base);
    make_jamtis_unlockamounts_pubkey(keys_out.xk_ua, keys_out.xK_ua);
    make_jamtis_findreceived_pubkey(keys_out.xk_fr, keys_out.xK_ua, keys_out.xK_fr);
}
//-------------------------------------------------------------------------------------------------------------------
void make_destination_random(const JamtisKeys &user_keys, JamtisDestinationV1 &user_destination_out)
{
    address_index_t address_index;
    address_index = gen_address_index();

    make_jamtis_destination_v1(
        user_keys.K_1_base, user_keys.xK_ua, user_keys.xK_fr, user_keys.s_ga, address_index, user_destination_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_destination_zero(const JamtisKeys &user_keys, JamtisDestinationV1 &user_destination_out)
{
    address_index_t address_index{};

    make_jamtis_destination_v1(
        user_keys.K_1_base, user_keys.xK_ua, user_keys.xK_fr, user_keys.s_ga, address_index, user_destination_out);
}
//-------------------------------------------------------------------------------------------------------------------
void JamtisKeys::encrypt(const crypto::chacha_key &key, const crypto::chacha_iv &iv)
{
    crypto::chacha20(k_m.data, sizeof(k_m), key, iv, k_m.data);
    crypto::chacha20(k_vb.data, sizeof(k_vb), key, iv, k_vb.data);
    crypto::chacha20(xk_ua.data, sizeof(xk_ua), key, iv, (char *)xk_ua.data);
    crypto::chacha20(xk_fr.data, sizeof(xk_fr), key, iv, (char *)xk_fr.data);
    crypto::chacha20(s_ga.data, sizeof(s_ga), key, iv, s_ga.data);
    crypto::chacha20(s_ct.data, sizeof(s_ct), key, iv, s_ct.data);
}
//-------------------------------------------------------------------------------------------------------------------
void JamtisKeys::decrypt(const crypto::chacha_key &key, const crypto::chacha_iv &iv) { encrypt(key, iv); }
//-------------------------------------------------------------------------------------------------------------------
void gen_legacy_subaddress(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    rct::key &subaddr_spendkey_out,
    rct::key &subaddr_viewkey_out,
    cryptonote::subaddress_index &subaddr_index_out)
{
    // random subaddress index: i
    crypto::rand(sizeof(subaddr_index_out.minor), reinterpret_cast<unsigned char*>(&subaddr_index_out.minor));
    crypto::rand(sizeof(subaddr_index_out.major), reinterpret_cast<unsigned char*>(&subaddr_index_out.major));

    // subaddress spendkey: (Hn(k^v, i) + k^s) G
    make_legacy_subaddress_spendkey(legacy_base_spend_pubkey,
        legacy_view_privkey,
        subaddr_index_out,
        hw::get_device("default"),
        subaddr_spendkey_out);

    // subaddress viewkey: k^v * K^{s,i}
    rct::scalarmultKey(subaddr_viewkey_out, subaddr_spendkey_out, rct::sk2rct(legacy_view_privkey));
}
//-------------------------------------------------------------------------------------------------------------------
}  // namespace jamtis
}  // namespace sp

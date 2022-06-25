// Copyright (c) 2021, The Monero Project
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

//paired header
#include "jamtis_enote_utils.h"

//local headers
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "seraphis_config_temp.h"
#include "device/device.hpp"
#include "int-util.h"
#include "jamtis_support_types.h"
#include "misc_language.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_core_enote_utils.h"
#include "sp_crypto_utils.h"
#include "sp_hash_functions.h"
#include "sp_transcript.h"
#include "tx_misc_utils.h"

//third party headers

//standard headers
#include <algorithm>
#include <string>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
// derivation = 8 * privkey * DH_key
//-------------------------------------------------------------------------------------------------------------------
static auto make_derivation_with_wiper(const crypto::secret_key &privkey,
    const rct::key &DH_key,
    hw::device &hwdev,
    crypto::key_derivation &derivation_out)
{
    auto a_wiper = epee::misc_utils::create_scope_leave_handler(
            [&derivation_out]()
            {
                memwipe(&derivation_out, sizeof(crypto::key_derivation));
            }
        );

    hwdev.generate_key_derivation(rct::rct2pk(DH_key), privkey, derivation_out);

    return a_wiper;
}
//-------------------------------------------------------------------------------------------------------------------
// a = a_enc XOR H_8(q, 8 r G)
// a_enc = a XOR H_8(q, 8 r G)
//-------------------------------------------------------------------------------------------------------------------
static rct::xmr_amount enc_dec_jamtis_amount_plain(const rct::xmr_amount original,
    const rct::key &sender_receiver_secret,
    const crypto::key_derivation &baked_key)
{
    static_assert(sizeof(rct::xmr_amount) == 8, "");

    static const std::string domain_separator{config::HASH_KEY_JAMTIS_AMOUNT_BLINDING_FACTOR_PLAIN};

    // ret = H_8(q, 8 r G) XOR_64 original
    SpTranscript transcript{domain_separator, 2*sizeof(rct::key)};
    transcript.append(sender_receiver_secret);
    transcript.append(baked_key);

    crypto::secret_key hash_result;
    sp_hash_to_8(transcript, to_bytes(hash_result));

    rct::xmr_amount mask;
    memcpy(&mask, &hash_result, 8);

    return original ^ mask;
}
//-------------------------------------------------------------------------------------------------------------------
// a = a_enc XOR H_8(q)
// a_enc = a XOR H_8(q)
//-------------------------------------------------------------------------------------------------------------------
static rct::xmr_amount enc_dec_jamtis_amount_selfsend(const rct::xmr_amount original,
    const rct::key &sender_receiver_secret)
{
    static_assert(sizeof(rct::xmr_amount) == 8, "");

    static const std::string domain_separator{config::HASH_KEY_JAMTIS_AMOUNT_BLINDING_FACTOR_SELF};

    // ret = H_8(q) XOR_64 original
    SpTranscript transcript{domain_separator, sizeof(sender_receiver_secret)};
    transcript.append(sender_receiver_secret);

    crypto::secret_key hash_result;
    sp_hash_to_8(transcript, to_bytes(hash_result));

    rct::xmr_amount mask;
    memcpy(&mask, &hash_result, 8);

    return original ^ mask;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_enote_ephemeral_pubkey(const crypto::secret_key &enote_privkey,
    const rct::key &DH_base,
    rct::key &enote_ephemeral_pubkey_out)
{
    // K_e = r K_3
    rct::scalarmultKey(enote_ephemeral_pubkey_out, DH_base, rct::sk2rct(enote_privkey));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_view_tag(const crypto::key_derivation &sender_receiver_DH_derivation,
    const rct::key &onetime_address,
    view_tag_t &view_tag_out)
{
    static_assert(sizeof(view_tag_t) == 1, "");

    static const std::string domain_separator{config::HASH_KEY_JAMTIS_VIEW_TAG};

    // view_tag = H_1(K_d, Ko)
    SpTranscript transcript{domain_separator, 2*sizeof(rct::key)};
    transcript.append(sender_receiver_DH_derivation);
    transcript.append(onetime_address);

    sp_hash_to_1(transcript, &view_tag_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_view_tag(const crypto::secret_key &privkey,
    const rct::key &DH_key,
    hw::device &hwdev,
    const rct::key &onetime_address,
    view_tag_t &view_tag_out)
{
    // K_d = 8 * privkey * DH_key
    //TODO: consider using curve25519/x25519 variable-scalar-mult to get the derivation instead (faster?)
    crypto::key_derivation derivation;
    auto a_wiper = make_derivation_with_wiper(privkey, DH_key, hwdev, derivation);

    // view_tag = H_1(K_d, Ko)
    make_jamtis_view_tag(derivation, onetime_address, view_tag_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_input_context_coinbase(const std::uint64_t block_height, rct::key &input_context_out)
{
    static const std::string domain_separator{config::HASH_KEY_JAMTIS_INPUT_CONTEXT_COINBASE};

    // block height as varint
    SpTranscript transcript{domain_separator, 4};
    transcript.append(block_height);

    // input_context (coinbase) = H_32(block height)
    sp_hash_to_32(transcript, input_context_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_input_context_standard(const std::vector<crypto::key_image> &input_key_images,
    rct::key &input_context_out)
{
    static const std::string domain_separator{config::HASH_KEY_JAMTIS_INPUT_CONTEXT_STANDARD};

    CHECK_AND_ASSERT_THROW_MES(std::is_sorted(input_key_images.begin(), input_key_images.end()),
        "jamtis input context (standard): key images are not sorted.");

    // {KI}
    SpTranscript transcript{domain_separator, input_key_images.size()*sizeof(crypto::key_image)};
    transcript.append(input_key_images);

    // input_context (standard) = H_32({KI})
    sp_hash_to_32(transcript, input_context_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_sender_receiver_secret_plain(const crypto::key_derivation &sender_receiver_DH_derivation,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &input_context,
    rct::key &sender_receiver_secret_out)
{
    static const std::string domain_separator{config::HASH_KEY_JAMTIS_SENDER_RECEIVER_SECRET_PLAIN};

    // q = H_32(DH_derivation, K_e, input_context)
    SpTranscript transcript{domain_separator, 3*sizeof(rct::key)};
    transcript.append(sender_receiver_DH_derivation);
    transcript.append(enote_ephemeral_pubkey);
    transcript.append(input_context);

    sp_hash_to_32(transcript, sender_receiver_secret_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_sender_receiver_secret_plain(const crypto::secret_key &privkey,
    const rct::key &DH_key,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &input_context,
    hw::device &hwdev,
    rct::key &sender_receiver_secret_out)
{
    // 8 * privkey * DH_key
    crypto::key_derivation derivation;
    auto a_wiper = make_derivation_with_wiper(privkey, DH_key, hwdev, derivation);

    // q = H_32(DH_derivation, K_e, input_context)
    make_jamtis_sender_receiver_secret_plain(derivation,
        enote_ephemeral_pubkey,
        input_context,
        sender_receiver_secret_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_sender_receiver_secret_selfsend(const crypto::secret_key &k_view_balance,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const jamtis::JamtisSelfSendType self_send_type,
    rct::key &sender_receiver_secret_out)
{
    static const std::string dummy_separator{
            config::HASH_KEY_JAMTIS_SENDER_RECEIVER_SECRET_SELF_SEND_ENOTE_DUMMY
        };
    static const std::string change_separator{
            config::HASH_KEY_JAMTIS_SENDER_RECEIVER_SECRET_SELF_SEND_ENOTE_CHANGE
        };
    static const std::string self_spend_separator{
            config::HASH_KEY_JAMTIS_SENDER_RECEIVER_SECRET_SELF_SEND_ENOTE_SELF_SPEND
        };

    CHECK_AND_ASSERT_THROW_MES(self_send_type <= jamtis::JamtisSelfSendType::MAX,
        "jamtis self-send sender-receiver secret: unknown self-send type.");

    const std::string &domain_separator{
            [&]() -> const std::string&
            {
                if (self_send_type == jamtis::JamtisSelfSendType::DUMMY)
                    return dummy_separator;
                else if (self_send_type == jamtis::JamtisSelfSendType::CHANGE)
                    return change_separator;
                else if (self_send_type == jamtis::JamtisSelfSendType::SELF_SPEND)
                    return self_spend_separator;
                else
                {
                    CHECK_AND_ASSERT_THROW_MES(false, "jamtis self-send sender-receiver secret domain separator error");
                    return dummy_separator;
                }
            }()
        };

    // q = H_32[k_vb](K_e, input_context)
    SpTranscript transcript{domain_separator, 2*sizeof(rct::key)};
    transcript.append(enote_ephemeral_pubkey);
    transcript.append(input_context);

    sp_derive_secret(to_bytes(k_view_balance), transcript, sender_receiver_secret_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_onetime_address_extension(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &sender_extension_out)
{
    static const std::string domain_separator{config::HASH_KEY_JAMTIS_SENDER_ONETIME_ADDRESS_EXTENSION};

    // k_{a, sender} = H_n(q, C)
    SpTranscript transcript{domain_separator, 2*sizeof(rct::key)};
    transcript.append(sender_receiver_secret);
    transcript.append(amount_commitment);

    sp_hash_to_scalar(transcript, to_bytes(sender_extension_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_onetime_address(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::key &recipient_spend_key,
    rct::key &onetime_address_out)
{
    // Ko = H_n(q, C) X + K_1
    crypto::secret_key extension;
    make_jamtis_onetime_address_extension(sender_receiver_secret, amount_commitment, extension);  //H_n(q, C)

    onetime_address_out = recipient_spend_key;
    extend_seraphis_spendkey(extension, onetime_address_out);  //H_n(q, C) X + K_1
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_amount_baked_key_plain_sender(const crypto::secret_key &enote_privkey,
    crypto::key_derivation &baked_key_out)
{
    // 8 r G
    crypto::generate_key_derivation(rct::rct2pk(rct::G), enote_privkey, baked_key_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_amount_baked_key_plain_recipient(const crypto::secret_key &address_privkey,
    const crypto::secret_key &k_unlock_amounts,
    const rct::key &enote_ephemeral_pubkey,
    crypto::key_derivation &baked_key_out)
{
    // 8 * (1/(k^j_a * k_ua)) * K_e = 8 r G
    //TODO: does this create a temporary that isn't properly memwiped?
    crypto::secret_key unlock_key_inverted;
    sc_mul(to_bytes(unlock_key_inverted), to_bytes(address_privkey), to_bytes(k_unlock_amounts));  //k^j_a * k_ua
    unlock_key_inverted = rct::rct2sk(invert(rct::sk2rct(unlock_key_inverted)));  //(1/(k^j_a * k_ua))

    crypto::generate_key_derivation(rct::rct2pk(enote_ephemeral_pubkey), unlock_key_inverted, baked_key_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_amount_blinding_factor_plain(const rct::key &sender_receiver_secret,
    const crypto::key_derivation &baked_key,
    crypto::secret_key &mask_out)
{
    static const std::string domain_separator{config::HASH_KEY_JAMTIS_AMOUNT_BLINDING_FACTOR_PLAIN};

    // x = H_n(q, 8 r G)
    SpTranscript transcript{domain_separator, 2*sizeof(rct::key)};
    transcript.append(sender_receiver_secret);
    transcript.append(baked_key);  //q || 8 r G

    sp_hash_to_scalar(transcript, to_bytes(mask_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_amount_blinding_factor_selfsend(const rct::key &sender_receiver_secret,
    crypto::secret_key &mask_out)
{
    static const std::string domain_separator{config::HASH_KEY_JAMTIS_AMOUNT_BLINDING_FACTOR_SELF};

    // x = H_n(q)
    SpTranscript transcript{domain_separator, sizeof(rct::key)};
    transcript.append(sender_receiver_secret);

    sp_hash_to_scalar(transcript, to_bytes(mask_out));
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount encode_jamtis_amount_plain(const rct::xmr_amount amount,
    const rct::key &sender_receiver_secret,
    const crypto::key_derivation &baked_key)
{
    // a_enc = little_endian(a) XOR H_8(q, 8 r G)
    return enc_dec_jamtis_amount_plain(SWAP64LE(amount), sender_receiver_secret, baked_key);
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount decode_jamtis_amount_plain(const rct::xmr_amount encoded_amount,
    const rct::key &sender_receiver_secret,
    const crypto::key_derivation &baked_key)
{
    // a = system_endian( a_enc XOR H_8(q, 8 r G) )
    return SWAP64LE(enc_dec_jamtis_amount_plain(encoded_amount, sender_receiver_secret, baked_key));
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount encode_jamtis_amount_selfsend(const rct::xmr_amount amount,
    const rct::key &sender_receiver_secret)
{
    // a_enc = little_endian(a) XOR H_8(q)
    return enc_dec_jamtis_amount_selfsend(SWAP64LE(amount), sender_receiver_secret);
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount decode_jamtis_amount_selfsend(const rct::xmr_amount encoded_amount,
    const rct::key &sender_receiver_secret)
{
    // a = system_endian( a_enc XOR H_8(q) )
    return SWAP64LE(enc_dec_jamtis_amount_selfsend(encoded_amount, sender_receiver_secret));
}
//-------------------------------------------------------------------------------------------------------------------
void make_jamtis_nominal_spend_key(const rct::key &sender_receiver_secret,
    const rct::key &onetime_address,
    const rct::key &amount_commitment,
    rct::key &nominal_spend_key_out)
{
    // K'_1 = Ko - H_n(q, C) X
    crypto::secret_key extension;
    make_jamtis_onetime_address_extension(sender_receiver_secret, amount_commitment, extension);  //H_n(q, C)
    nominal_spend_key_out = onetime_address;  //Ko_t
    reduce_seraphis_spendkey(extension, nominal_spend_key_out);  //(-H_n(q, C)) X + Ko_t
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_jamtis_sender_receiver_secret_plain(const crypto::key_derivation &sender_receiver_DH_derivation,
    const rct::key &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &onetime_address,
    const view_tag_t view_tag,
    rct::key &sender_receiver_secret_out)
{
    // recompute view tag and check that it matches; short-circuit on failure
    view_tag_t recomputed_view_tag;
    make_jamtis_view_tag(sender_receiver_DH_derivation, onetime_address, recomputed_view_tag);

    if (recomputed_view_tag != view_tag)
        return false;

    // q (normal derivation path)
    make_jamtis_sender_receiver_secret_plain(sender_receiver_DH_derivation,
        enote_ephemeral_pubkey,
        input_context,
        sender_receiver_secret_out);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_jamtis_amount_plain(const rct::key &sender_receiver_secret,
    const crypto::key_derivation &baked_key,
    const rct::key &amount_commitment,
    const rct::xmr_amount encoded_amount,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out)
{
    // a' = dec(enc_a)
    const rct::xmr_amount nominal_amount{decode_jamtis_amount_plain(encoded_amount, sender_receiver_secret, baked_key)};

    // C' = x' G + a' H
    make_jamtis_amount_blinding_factor_plain(sender_receiver_secret, baked_key, amount_blinding_factor_out);  // x'
    const rct::key nominal_amount_commitment{rct::commit(nominal_amount, rct::sk2rct(amount_blinding_factor_out))};

    // check that recomputed commitment matches original commitment
    if (!(nominal_amount_commitment == amount_commitment))
        return false;

    // success
    amount_out = nominal_amount;
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_jamtis_amount_selfsend(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::xmr_amount encoded_amount,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out)
{
    // a' = dec(enc_a)
    const rct::xmr_amount nominal_amount{decode_jamtis_amount_selfsend(encoded_amount, sender_receiver_secret)};

    // C' = x' G + a' H
    make_jamtis_amount_blinding_factor_selfsend(sender_receiver_secret, amount_blinding_factor_out);  // x'
    const rct::key nominal_amount_commitment{rct::commit(nominal_amount, rct::sk2rct(amount_blinding_factor_out))};

    // check that recomputed commitment matches original commitment
    if (!(nominal_amount_commitment == amount_commitment))
        return false;

    // success
    amount_out = nominal_amount;
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp

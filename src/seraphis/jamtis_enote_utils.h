// Copyright (c) 2022, The Monero Project
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

// Utilities for making and handling enotes with Jamtis.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "jamtis_support_types.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers

//forward declarations


namespace sp
{
namespace jamtis
{

/**
* brief: make_jamtis_enote_ephemeral_pubkey - enote ephemeral pubkey xK_e
*   xK_e = xr xK_3
* param: enote_ephemeral_privkey - xr
* param: DH_base - xK_3
* outparam: enote_ephemeral_pubkey_out - xK_e
*/
void make_jamtis_enote_ephemeral_pubkey(const crypto::x25519_secret_key &enote_ephemeral_privkey,
    const crypto::x25519_pubkey &DH_base,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out);
/**
* brief: make_jamtis_view_tag - view tag for optimized identification of owned enotes
*    view_tag = H_1(xK_d, Ko)
* param: sender_receiver_DH_derivation - xK_d
* param: onetime_address - Ko
* outparam: view_tag_out - view_tag
*/
void make_jamtis_view_tag(const crypto::x25519_pubkey &sender_receiver_DH_derivation,
    const rct::key &onetime_address,
    view_tag_t &view_tag_out);
/**
* brief: make_jamtis_view_tag - view tag for optimized identification of owned enotes
*    view_tag = H_1(privkey * DH_key, Ko)
* param: privkey - [sender: xr] [recipient: xk_fr]
* param: DH_key - [sender: xK_2] [sender-selfsend-2out: xk_fr * xK_3_other] [recipient: xK_e = xr xK_3]
* param: onetime_address - Ko
* outparam: view_tag_out - view_tag
*/
void make_jamtis_view_tag(const crypto::x25519_secret_key &privkey,
    const crypto::x25519_pubkey &DH_key,
    const rct::key &onetime_address,
    view_tag_t &view_tag_out);
/**
* brief: make_jamtis_input_context_coinbase - input context for a sender-receiver secret (coinbase txs)
*    input_context = H_32(block_height)
* param: block_height - block height of the coinbase tx
* outparam: input_context_out - H_32(block height)
*/
void make_jamtis_input_context_coinbase(const std::uint64_t block_height, rct::key &input_context_out);
/**
* brief: make_jamtis_input_context_standard - input context for a sender-receiver secret (standard txs)
*    input_context = H_32({legacy KI}, {seraphis KI})
* param: legacy_input_key_images - {KI} from the legacy inputs of a tx (sorted)
* param: sp_input_key_images - {KI} from the seraphis inputs of a tx (sorted)
* outparam: input_context_out - H_32({legacy KI}, {seraphis KI}})
*/
void make_jamtis_input_context_standard(const std::vector<crypto::key_image> &legacy_input_key_images,
    const std::vector<crypto::key_image> &sp_input_key_images,
    rct::key &input_context_out);
/**
* brief: make_jamtis_sender_receiver_secret_plain - sender-receiver secret q for a normal enote
*    q = H_32(xK_d, xK_e, input_context)
* param: sender_receiver_DH_derivation - xK_d = xr xK_2 = k_fr xK_e
* param: enote_ephemeral_pubkey - xK_e
* param: input_context - [normal: H_32({legacy KI}, {seraphis KI}); coinbase: H_32(block height)]
* outparam: sender_receiver_secret_out - q
*   - note: this is 'rct::key' instead of 'crypto::secret_key' for better performance in multithreaded environments
*/
void make_jamtis_sender_receiver_secret_plain(const crypto::x25519_pubkey &sender_receiver_DH_derivation,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    rct::key &sender_receiver_secret_out);
/**
* brief: make_jamtis_sender_receiver_secret_plain - sender-receiver secret q for a normal enote
*    q = H_32(xr * xk_fr * xG, input_context) => H_32(privkey * DH_key, input_context)
* param: privkey - [sender: xr] [recipient: xk_fr]
* param: DH_key - [sender: xK_2] [sender-selfsend-2out: xk_fr * xK_3_other] [recipient: xK_e = xr xK_3]
* param: enote_ephemeral_pubkey - xK_e
* param: input_context - [normal: H_32({legacy KI}, {seraphis KI}); coinbase: H_32(block height)]
* outparam: sender_receiver_secret_out - q
*   - note: this is 'rct::key' instead of 'crypto::secret_key' for better performance in multithreaded environments
*/
void make_jamtis_sender_receiver_secret_plain(const crypto::x25519_secret_key &privkey,
    const crypto::x25519_pubkey &DH_key,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    rct::key &sender_receiver_secret_out);
/**
* brief: make_jamtis_sender_receiver_secret_selfsend - sender-receiver secret q for a self-send enote of a specific type
*    q = H_32[k_vb](xK_e, input_context)
* param: k_view_balance - k_vb
* param: enote_ephemeral_pubkey - xK_e
* param: input_context - [normal: H_32({legacy KI}, {seraphis KI}); coinbase: H_32(block height)]
* param: self_send_type - type of the self-send enote, used to select the domain separator
* outparam: sender_receiver_secret_out - q
*   - note: this is 'rct::key' instead of 'crypto::secret_key' for better performance in multithreaded environments
*/
void make_jamtis_sender_receiver_secret_selfsend(const crypto::secret_key &k_view_balance,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const jamtis::JamtisSelfSendType self_send_type,
    rct::key &sender_receiver_secret_out);
/**
* brief: make_jamtis_onetime_address_extension_g - extension for transforming a recipient spendkey into an
*        enote one-time address
*    k_{g, sender} = H_n("..g..", q, C)
* param: sender_receiver_secret - q
* param: amount_commitment - C
* outparam: sender_extension_out - k_{g, sender}
*/
void make_jamtis_onetime_address_extension_g(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &sender_extension_out);
/**
* brief: make_jamtis_onetime_address_extension_x - extension for transforming a recipient spendkey into an
*        enote one-time address
*    k_{x, sender} = H_n("..x..", q, C)
* param: sender_receiver_secret - q
* param: amount_commitment - C
* outparam: sender_extension_out - k_{x, sender}
*/
void make_jamtis_onetime_address_extension_x(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &sender_extension_out);
/**
* brief: make_jamtis_onetime_address_extension_u - extension for transforming a recipient spendkey into an
*        enote one-time address
*    k_{u, sender} = H_n("..u..", q, C)
* param: sender_receiver_secret - q
* param: amount_commitment - C
* outparam: sender_extension_out - k_{u, sender}
*/
void make_jamtis_onetime_address_extension_u(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    crypto::secret_key &sender_extension_out);
/**
* brief: make_jamtis_onetime_address - create a onetime address
*    Ko = H_n("..g..", q, C) G + H_n("..x..", q, C) X + H_n("..u..", q, C) U + K_1
* param: sender_receiver_secret - q
* param: amount_commitment - C
* param: recipient_address_spend_key - K_1
* outparam: onetime_address_out - Ko
*/
void make_jamtis_onetime_address(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::key &recipient_address_spend_key,
    rct::key &onetime_address_out);
/**
* brief: make_jamtis_amount_baked_key_plain_sender - key baked into amount encodings of plain enotes, to provide
*        fine-tuned control over read rights to the amount
*    [sender] baked_key = xr xG
* param: enote_ephemeral_privkey - xr
* outparam: baked_key_out - xr xG
*/
void make_jamtis_amount_baked_key_plain_sender(const crypto::x25519_secret_key &enote_ephemeral_privkey,
    crypto::x25519_pubkey &baked_key_out);
/**
* brief: make_jamtis_amount_baked_key_plain_recipient - key baked into amount encodings of plain enotes, to provide
*        fine-tuned control over read rights to the amount
*    [recipient] baked_key = (1/(xk^j_a * xk_ua)) * xK_e
* param: address_privkey - xk^j_a
* param: xk_unlock_amounts - xk_ua
* param: enote_ephemeral_pubkey - xK_e
* outparam: baked_key_out - (1/(k^j_a * k_ua)) * xK_e
*/
void make_jamtis_amount_baked_key_plain_recipient(const crypto::x25519_secret_key &address_privkey,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    crypto::x25519_pubkey &baked_key_out);
/**
* brief: make_jamtis_amount_blinding_factor_plain - x for a normal enote's amount commitment C = x G + a H
*   x = H_n(q, xr xG)
* param: sender_receiver_secret - q
* param: baked_key - xr xG
* outparam: mask_out - x
*/
void make_jamtis_amount_blinding_factor_plain(const rct::key &sender_receiver_secret,
    const crypto::x25519_pubkey &baked_key,
    crypto::secret_key &mask_out);
/**
* brief: make_jamtis_amount_blinding_factor_selfsend - x for a self-spend enote's amount commitment C = x G + a H
*   x = H_n(q)
* param: sender_receiver_secret - q
* outparam: mask_out - x
*/
void make_jamtis_amount_blinding_factor_selfsend(const rct::key &sender_receiver_secret, crypto::secret_key &mask_out);
/**
* brief: encode_jamtis_amount_plain - encode an amount for a normal enote
*   a_enc = a XOR H_8(q, xr xG)
* param: amount - a
* param: sender_receiver_secret - q
* param: baked_key - xr xG
* return: a_enc
*/
rct::xmr_amount encode_jamtis_amount_plain(const rct::xmr_amount amount,
    const rct::key &sender_receiver_secret,
    const crypto::x25519_pubkey &baked_key);
/**
* brief: decode_jamtis_amount_plain - decode an amount from a normal enote
*   a = a_enc XOR H_8(q, xr xG)
* param: encoded_amount - a_enc
* param: sender_receiver_secret - q
* param: baked_key - xr xG
* return: a
*/
rct::xmr_amount decode_jamtis_amount_plain(const rct::xmr_amount encoded_amount,
    const rct::key &sender_receiver_secret,
    const crypto::x25519_pubkey &baked_key);
/**
* brief: encode_jamtis_amount_selfsend - encode an amount for a self-send enote
*   a_enc = a XOR H_8(q)
* param: amount - a
* param: sender_receiver_secret - q
* return: a_enc
*/
rct::xmr_amount encode_jamtis_amount_selfsend(const rct::xmr_amount amount, const rct::key &sender_receiver_secret);
/**
* brief: decode_jamtis_amount_selfsend - decode an amount from a self-send enote
*   a = a_enc XOR H_8(q)
* param: encoded_amount - a_enc
* param: sender_receiver_secret - q
* return: a
*/
rct::xmr_amount decode_jamtis_amount_selfsend(const rct::xmr_amount encoded_amount,
    const rct::key &sender_receiver_secret);
/**
* brief: make_jamtis_nominal_spend_key - make a nominal spend key from a onetime address
*   K'_1 = Ko - H_n("..g..", q, C) G - H_n("..x..", q, C) X - H_n("..u..", q, C) U
* param: onetime_address - Ko
* param: sender_receiver_secret - q
* param: amount_commitment - C
* outparam: nominal_spend_key_out - K'_1
*/
void make_jamtis_nominal_spend_key(const rct::key &onetime_address,
    const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    rct::key &nominal_spend_key_out);
/**
* brief: try_get_jamtis_sender_receiver_secret_plain - test view tag; if it passes, get the nominal sender-receiver secret
*        (for a normal enote)
* param: sender_receiver_DH_derivation - privkey * DH_key
* param: enote_ephemeral_pubkey - xK_e
* param: input_context - [normal: H_32({legacy KI}, {seraphis KI}); coinbase: H_32(block height)]
* param: onetime_address - Ko
* param: view_tag - view_tag
* outparam: sender_receiver_secret_out - q
* return: true if successfully recomputed the view tag
*/
bool try_get_jamtis_sender_receiver_secret_plain(const crypto::x25519_pubkey &sender_receiver_DH_derivation,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &onetime_address,
    const view_tag_t view_tag,
    rct::key &sender_receiver_secret_out);
/**
* brief: try_get_jamtis_amount_plain - test recreating the amount commitment; if it is recreate-able, return the amount
*        (for a normal enote)
* param: sender_receiver_secret - q
* param: baked_key - xr xG
* param: amount_commitment - C = x G + a H
* param: encoded_amount - enc_a
* outparam: amount_out - a' = dec(enc_a)
* outparam: amount_blinding_factor_out - x'
* return: true if successfully recomputed the amount commitment (C' = x' G + a' H ?= C)
*/
bool try_get_jamtis_amount_plain(const rct::key &sender_receiver_secret,
    const crypto::x25519_pubkey &baked_key,
    const rct::key &amount_commitment,
    const rct::xmr_amount encoded_amount,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out);
/**
* brief: try_get_jamtis_amount_selfsend - test recreating the amount commitment; if it is recreate-able, return the amount
*        (for a self-send enote)
* param: sender_receiver_secret - q
* param: amount_commitment - C = x G + a H
* param: encoded_amount - enc_a
* outparam: amount_out - a' = dec(enc_a)
* outparam: amount_blinding_factor_out - x'
* return: true if successfully recomputed the amount commitment (C' = x' G + a' H ?= C)
*/
bool try_get_jamtis_amount_selfsend(const rct::key &sender_receiver_secret,
    const rct::key &amount_commitment,
    const rct::xmr_amount encoded_amount,
    rct::xmr_amount &amount_out,
    crypto::secret_key &amount_blinding_factor_out);

} //namespace jamtis
} //namespace sp

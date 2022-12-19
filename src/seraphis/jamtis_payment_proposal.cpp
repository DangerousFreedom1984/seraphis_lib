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

//paired header
#include "jamtis_payment_proposal.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "jamtis_address_tag_utils.h"
#include "jamtis_address_utils.h"
#include "jamtis_core_utils.h"
#include "jamtis_enote_utils.h"
#include "jamtis_support_types.h"
#include "memwipe.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "tx_builder_types.h"
#include "tx_enote_record_types.h"
#include "tx_enote_record_utils.h"
#include "tx_extra.h"

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
namespace jamtis
{
//-------------------------------------------------------------------------------------------------------------------
void get_enote_ephemeral_pubkey(const JamtisPaymentProposalV1 &proposal,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out)
{
    // sanity checks
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(proposal.m_enote_ephemeral_privkey.data),
        "jamtis payment proposal: invalid enote ephemeral privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(x25519_scalar_is_canonical(proposal.m_enote_ephemeral_privkey),
        "jamtis payment proposal: invalid enote ephemeral privkey (not canonical).");

    // enote ephemeral pubkey: xK_e = xr xK_3
    make_jamtis_enote_ephemeral_pubkey(proposal.m_enote_ephemeral_privkey,
        proposal.m_destination.m_addr_K3,
        enote_ephemeral_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void get_enote_ephemeral_pubkey(const JamtisPaymentProposalSelfSendV1 &proposal,
    crypto::x25519_pubkey &enote_ephemeral_pubkey_out)
{
    // sanity checks
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(proposal.m_enote_ephemeral_privkey.data),
        "jamtis payment proposal self-send: invalid enote ephemeral privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(x25519_scalar_is_canonical(proposal.m_enote_ephemeral_privkey),
        "jamtis payment proposal self-send: invalid enote ephemeral privkey (not canonical).");

    // enote ephemeral pubkey: xK_e = xr xK_3
    make_jamtis_enote_ephemeral_pubkey(proposal.m_enote_ephemeral_privkey,
        proposal.m_destination.m_addr_K3,
        enote_ephemeral_pubkey_out);
}
//-------------------------------------------------------------------------------------------------------------------
void get_coinbase_output_proposal_v1(const JamtisPaymentProposalV1 &proposal,
    const std::uint64_t block_height,
    SpCoinbaseOutputProposalV1 &output_proposal_out)
{
    // 1. sanity checks
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(proposal.m_enote_ephemeral_privkey.data),
        "jamtis payment proposal: invalid enote ephemeral privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(x25519_scalar_is_canonical(proposal.m_enote_ephemeral_privkey),
        "jamtis payment proposal: invalid enote ephemeral privkey (not canonical).");

    // 2. enote ephemeral pubkey: xK_e = xr xK_3
    get_enote_ephemeral_pubkey(proposal, output_proposal_out.m_enote_ephemeral_pubkey);

    // 3. derived key: xK_d = xr * xK_2
    crypto::x25519_pubkey xK_d;
    auto xKd_wiper = epee::misc_utils::create_scope_leave_handler([&]{ memwipe(&xK_d, sizeof(xK_d)); });

    crypto::x25519_scmul_key(proposal.m_enote_ephemeral_privkey, proposal.m_destination.m_addr_K2, xK_d);

    // 4. coinbase input context
    rct::key input_context;
    make_jamtis_input_context_coinbase(block_height, input_context);

    // 5. sender-receiver shared secret: q = H_32(xK_d, xK_e, input_context)
    rct::key q;
    auto q_wiper = epee::misc_utils::create_scope_leave_handler([&]{ memwipe(&q, sizeof(q)); });
    make_jamtis_sender_receiver_secret_plain(xK_d, output_proposal_out.m_enote_ephemeral_pubkey, input_context, q);

    // 6. amount: a
    output_proposal_out.m_enote.m_core.m_amount = proposal.m_amount;

    // 7. amount commitment (temporary): C = 1 G + a H
    const rct::key temp_amount_commitment{rct::commit(proposal.m_amount, rct::I)};

    // 8. onetime address: Ko = H_n("..g..", q, C) G + H_n("..x..", q, C) X + H_n("..u..", q, C) U + K_1
    make_jamtis_onetime_address(q,
        temp_amount_commitment,
        proposal.m_destination.m_addr_K1,
        output_proposal_out.m_enote.m_core.m_onetime_address);

    // 9. encrypt address tag: addr_tag_enc = addr_tag ^ H(q, Ko)
    output_proposal_out.m_enote.m_addr_tag_enc =
        encrypt_address_tag(q, output_proposal_out.m_enote.m_core.m_onetime_address, proposal.m_destination.m_addr_tag);

    // 10. view tag: view_tag = H_1(xK_d, Ko)
    make_jamtis_view_tag(xK_d,
        output_proposal_out.m_enote.m_core.m_onetime_address,
        output_proposal_out.m_enote.m_view_tag);

    // 11. memo elements
    output_proposal_out.m_partial_memo = proposal.m_partial_memo;
}
//-------------------------------------------------------------------------------------------------------------------
void get_output_proposal_v1(const JamtisPaymentProposalV1 &proposal,
    const rct::key &input_context,
    SpOutputProposalV1 &output_proposal_out)
{
    // 1. sanity checks
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(proposal.m_enote_ephemeral_privkey.data),
        "jamtis payment proposal: invalid enote ephemeral privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(x25519_scalar_is_canonical(proposal.m_enote_ephemeral_privkey),
        "jamtis payment proposal: invalid enote ephemeral privkey (not canonical).");

    // 2. enote ephemeral pubkey: xK_e = xr xK_3
    get_enote_ephemeral_pubkey(proposal, output_proposal_out.m_enote_ephemeral_pubkey);

    // 3. derived key: xK_d = xr * xK_2
    crypto::x25519_pubkey xK_d;
    auto xKd_wiper = epee::misc_utils::create_scope_leave_handler([&]{ memwipe(&xK_d, sizeof(xK_d)); });

    crypto::x25519_scmul_key(proposal.m_enote_ephemeral_privkey, proposal.m_destination.m_addr_K2, xK_d);

    // 4. sender-receiver shared secret: q = H_32(xK_d, xK_e, input_context)
    rct::key q;
    auto q_wiper = epee::misc_utils::create_scope_leave_handler([&]{ memwipe(&q, sizeof(q)); });
    make_jamtis_sender_receiver_secret_plain(xK_d, output_proposal_out.m_enote_ephemeral_pubkey, input_context, q);

    // 5. enote amount baked key: xr xG
    crypto::x25519_pubkey amount_baked_key;
    auto bk_wiper = epee::misc_utils::create_scope_leave_handler(
            [&]{ memwipe(&amount_baked_key, sizeof(crypto::x25519_pubkey)); }
        );
    make_jamtis_amount_baked_key_plain_sender(proposal.m_enote_ephemeral_privkey, amount_baked_key);

    // 6. amount blinding factor: y = H_n(q, xr xG)
    make_jamtis_amount_blinding_factor_plain(q, amount_baked_key, output_proposal_out.m_core.m_amount_blinding_factor);

    // 7. amount: a
    output_proposal_out.m_core.m_amount = proposal.m_amount;

    // 8. encrypted amount: enc_amount = a ^ H_8(q, xr xG)
    output_proposal_out.m_encoded_amount = encode_jamtis_amount_plain(proposal.m_amount, q, amount_baked_key);

    // 9. amount commitment (temporary)
    const rct::key temp_amount_commitment{
            rct::commit(proposal.m_amount, rct::sk2rct(output_proposal_out.m_core.m_amount_blinding_factor))
        };

    // 10. onetime address: Ko = H_n("..g..", q, C) G + H_n("..x..", q, C) X + H_n("..u..", q, C) U + K_1
    make_jamtis_onetime_address(q,
        temp_amount_commitment,
        proposal.m_destination.m_addr_K1,
        output_proposal_out.m_core.m_onetime_address);

    // 11. encrypt address tag: addr_tag_enc = addr_tag ^ H(q, Ko)
    output_proposal_out.m_addr_tag_enc =
        encrypt_address_tag(q, output_proposal_out.m_core.m_onetime_address, proposal.m_destination.m_addr_tag);

    // 12. view tag: view_tag = H_1(xK_d, Ko)
    make_jamtis_view_tag(xK_d, output_proposal_out.m_core.m_onetime_address, output_proposal_out.m_view_tag);

    // 13. memo elements
    output_proposal_out.m_partial_memo = proposal.m_partial_memo;
}
//-------------------------------------------------------------------------------------------------------------------
void get_output_proposal_v1(const JamtisPaymentProposalSelfSendV1 &proposal,
    const crypto::secret_key &k_view_balance,
    const rct::key &input_context,
    SpOutputProposalV1 &output_proposal_out)
{
    // 1. sanity checks
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(proposal.m_enote_ephemeral_privkey.data),
        "jamtis payment proposal self-send: invalid enote ephemeral privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(x25519_scalar_is_canonical(proposal.m_enote_ephemeral_privkey),
        "jamtis payment proposal self-send: invalid enote ephemeral privkey (not canonical).");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(k_view_balance)),
        "jamtis payment proposal self-send: invalid view-balance privkey (zero).");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(k_view_balance)) == 0,
        "jamtis payment proposal self-send: invalid view-balance privkey (not canonical).");
    CHECK_AND_ASSERT_THROW_MES(proposal.m_type <= JamtisSelfSendType::MAX,
        "jamtis payment proposal self-send: unknown self-send type.");

    // 2. enote ephemeral pubkey: xK_e = xr xK_3
    get_enote_ephemeral_pubkey(proposal, output_proposal_out.m_enote_ephemeral_pubkey);

    // 3. sender-receiver shared secret: q = H_32[k_vb](xK_e, input_context)  //note: xK_e not xK_d
    rct::key q;
    auto q_wiper = epee::misc_utils::create_scope_leave_handler([&]{ memwipe(&q, sizeof(q)); });
    make_jamtis_sender_receiver_secret_selfsend(k_view_balance,
        output_proposal_out.m_enote_ephemeral_pubkey,
        input_context,
        proposal.m_type,
        q);

    // 4. amount blinding factor: y = H_n(q)  //note: no baked key
    make_jamtis_amount_blinding_factor_selfsend(q, output_proposal_out.m_core.m_amount_blinding_factor);

    // 5. amount: a
    output_proposal_out.m_core.m_amount = proposal.m_amount;

    // 6. encrypted amount: enc_amount = a ^ H_8(q)  //note: no baked key
    output_proposal_out.m_encoded_amount = encode_jamtis_amount_selfsend(proposal.m_amount, q);

    // 7. amount commitment (temporary)
    const rct::key temp_amount_commitment{
            rct::commit(proposal.m_amount, rct::sk2rct(output_proposal_out.m_core.m_amount_blinding_factor))
        };

    // 8. onetime address: Ko = H_n("..g..", q, C) G + H_n("..x..", q, C) X + H_n("..u..", q, C) U + K_1
    make_jamtis_onetime_address(q,
        temp_amount_commitment,
        proposal.m_destination.m_addr_K1,
        output_proposal_out.m_core.m_onetime_address);

    // 9. encrypt address index: addr_tag_enc = addr_tag{j || hint} ^ H(q, Ko)
    // a. extract the address index from the destination address's address tag
    crypto::secret_key s_generate_address;
    crypto::secret_key s_cipher_tag;
    make_jamtis_generateaddress_secret(k_view_balance, s_generate_address);
    make_jamtis_ciphertag_secret(s_generate_address, s_cipher_tag);
    address_index_t j;
    CHECK_AND_ASSERT_THROW_MES(try_decipher_address_index(s_cipher_tag, proposal.m_destination.m_addr_tag, j),
        "Failed to create a self-send-type output proposal: could not decipher the destination's address tag.");

    // b. make a raw address tag (not ciphered)
    const address_tag_t raw_address_tag{j, address_tag_hint_t{}};

    // c. encrypt the raw address tag: addr_tag_enc = addr_tag{j || hint} ^ H(q, Ko)
    output_proposal_out.m_addr_tag_enc =
        encrypt_address_tag(q, output_proposal_out.m_core.m_onetime_address, raw_address_tag);

    // 10. derived key: xK_d = xr * xK_2
    crypto::x25519_pubkey xK_d;
    crypto::x25519_scmul_key(proposal.m_enote_ephemeral_privkey, proposal.m_destination.m_addr_K2, xK_d);

    // 11. view tag: view_tag = H_1(xK_d, Ko)
    make_jamtis_view_tag(xK_d, output_proposal_out.m_core.m_onetime_address, output_proposal_out.m_view_tag);

    // 12. memo elements
    output_proposal_out.m_partial_memo = proposal.m_partial_memo;
}
//-------------------------------------------------------------------------------------------------------------------
void check_jamtis_payment_proposal_selfsend_semantics_v1(const JamtisPaymentProposalSelfSendV1 &selfsend_payment_proposal,
    const rct::key &input_context,
    const rct::key &spend_pubkey,
    const crypto::secret_key &k_view_balance)
{
    // 1. convert to an output proposal
    SpOutputProposalV1 output_proposal;
    get_output_proposal_v1(selfsend_payment_proposal, k_view_balance, input_context, output_proposal);

    // 2. extract enote from output proposal
    SpEnoteV1 temp_enote;
    output_proposal.get_enote_v1(temp_enote);

    // 3. try to get an enote record from the enote (via selfsend path)
    SpEnoteRecordV1 temp_enote_record;
    CHECK_AND_ASSERT_THROW_MES(try_get_enote_record_v1_selfsend(temp_enote,
            output_proposal.m_enote_ephemeral_pubkey,
            input_context,
            spend_pubkey,
            k_view_balance,
            temp_enote_record),
        "semantics check jamtis self-send payment proposal: failed to extract enote record from the proposal.");

    // 4. extract the self-send type
    JamtisSelfSendType dummy_type;
    CHECK_AND_ASSERT_THROW_MES(try_get_jamtis_self_send_type(temp_enote_record.m_type, dummy_type),
        "semantics check jamtis self-send payment proposal: failed to convert enote type to self-send type (bug).");
}
//-------------------------------------------------------------------------------------------------------------------
JamtisPaymentProposalV1 gen_jamtis_payment_proposal_v1(const rct::xmr_amount amount,
    const std::size_t num_random_memo_elements)
{
    JamtisPaymentProposalV1 temp;

    temp.m_destination = gen_jamtis_destination_v1();
    temp.m_amount = amount;
    temp.m_enote_ephemeral_privkey = crypto::x25519_secret_key_gen();

    std::vector<ExtraFieldElement> memo_elements;
    memo_elements.resize(num_random_memo_elements);
    for (ExtraFieldElement &element: memo_elements)
        element.gen();
    make_tx_extra(std::move(memo_elements), temp.m_partial_memo);

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
JamtisPaymentProposalSelfSendV1 gen_jamtis_selfsend_payment_proposal_v1(const rct::xmr_amount amount,
    const JamtisSelfSendType type,
    const std::size_t num_random_memo_elements)
{
    JamtisPaymentProposalSelfSendV1 temp;

    temp.m_destination = gen_jamtis_destination_v1();
    temp.m_amount = amount;
    temp.m_type = type;
    temp.m_enote_ephemeral_privkey = crypto::x25519_secret_key_gen();

    std::vector<ExtraFieldElement> memo_elements;
    memo_elements.resize(num_random_memo_elements);
    for (ExtraFieldElement &element: memo_elements)
        element.gen();
    make_tx_extra(std::move(memo_elements), temp.m_partial_memo);

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp

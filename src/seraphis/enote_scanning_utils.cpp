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

// NOT FOR PRODUCTION

//paired header
#include "enote_scanning_utils.h"

//local headers
#include "contextual_enote_record_types.h"
#include "contextual_enote_record_utils.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "cryptonote_basic/subaddress_index.h"
#include "device/device.hpp"
#include "enote_finding_context.h"
#include "enote_record_types.h"
#include "enote_record_utils.h"
#include "enote_record_utils_legacy.h"
#include "enote_scanning.h"
#include "enote_scanning_context.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_core_utils.h"
#include "seraphis_core/legacy_core_utils.h"
#include "seraphis_core/legacy_enote_utils.h"
#include "seraphis_core/sp_tx_extra.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "tx_component_types.h"

//third party headers

//standard headers
#include <algorithm>
#include <functional>
#include <list>
#include <unordered_map>
#include <unordered_set>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void process_chunk_new_intermediate_record_update_legacy(const LegacyIntermediateEnoteRecord &new_enote_record,
    const SpEnoteOriginContextV1 &new_record_origin_context,
    std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records_inout)
{
    // 1. add new legacy record to found enotes (or refresh if already there)
    rct::key new_record_identifier;
    get_legacy_enote_identifier(onetime_address_ref(new_enote_record.m_enote),
        new_enote_record.m_amount,
        new_record_identifier);

    found_enote_records_inout[new_record_identifier].m_record = new_enote_record;

    // 2. update the contextual enote record's origin context
    try_update_enote_origin_context_v1(new_record_origin_context,
        found_enote_records_inout[new_record_identifier].m_origin_context);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void process_chunk_new_intermediate_record_update_sp(const SpIntermediateEnoteRecordV1 &new_enote_record,
    const SpEnoteOriginContextV1 &new_record_origin_context,
    std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records_inout)
{
    // 1. add new record to found enotes (or refresh if already there)
    const rct::key &new_record_onetime_address{onetime_address_ref(new_enote_record.m_enote)};

    found_enote_records_inout[new_record_onetime_address].m_record = new_enote_record;

    // 2. update the contextual enote record's origin context
    try_update_enote_origin_context_v1(new_record_origin_context,
        found_enote_records_inout[new_record_onetime_address].m_origin_context);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void process_chunk_new_record_update_legacy(const LegacyEnoteRecord &new_enote_record,
    const SpEnoteOriginContextV1 &new_record_origin_context,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout)
{
    // 1. add new legacy record to found enotes (or refresh if already there)
    rct::key new_record_identifier;
    get_legacy_enote_identifier(onetime_address_ref(new_enote_record.m_enote),
        new_enote_record.m_amount,
        new_record_identifier);

    found_enote_records_inout[new_record_identifier].m_record = new_enote_record;

    // 2. handle if this enote record is spent in this chunk
    const crypto::key_image &new_record_key_image{new_enote_record.m_key_image};
    SpEnoteSpentContextV1 spent_context_update{};

    auto contextual_key_images_of_record_spent_in_this_chunk =
        std::find_if(
            chunk_contextual_key_images.begin(),
            chunk_contextual_key_images.end(),
            [&](const SpContextualKeyImageSetV1 &contextual_key_image_set) -> bool
            {
                return has_key_image(contextual_key_image_set, new_record_key_image);
            }
        );

    if (contextual_key_images_of_record_spent_in_this_chunk != chunk_contextual_key_images.end())
    {
        // a. record that the enote is spent in this chunk
        found_spent_key_images_inout[new_record_key_image];

        // b. update its spent context (update instead of assignment in case of duplicates)
        try_update_enote_spent_context_v1(contextual_key_images_of_record_spent_in_this_chunk->m_spent_context,
            found_spent_key_images_inout[new_record_key_image]);

        // c. get the record's current spent context
        spent_context_update = found_spent_key_images_inout[new_record_key_image];
    }

    // 3. update the contextual enote record's contexts
    // note: multiple legacy enotes can have the same key image but different amounts; only one of those can be spent,
    //       so we should expect all of them to reference the same spent context
    update_contextual_enote_record_contexts_v1(new_record_origin_context,
        spent_context_update,
        found_enote_records_inout[new_record_identifier].m_origin_context,
        found_enote_records_inout[new_record_identifier].m_spent_context);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void process_chunk_new_record_update_sp(const SpEnoteRecordV1 &new_enote_record,
    const SpEnoteOriginContextV1 &new_record_origin_context,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout,
    std::unordered_set<rct::key> &txs_have_spent_enotes_inout)
{
    // 1. add new record to found enotes (or refresh if already there)
    const crypto::key_image &new_record_key_image{new_enote_record.m_key_image};

    found_enote_records_inout[new_record_key_image].m_record = new_enote_record;

    // 2. handle if this enote record is spent in this chunk
    SpEnoteSpentContextV1 spent_context_update{};

    auto contextual_key_images_of_record_spent_in_this_chunk =
        std::find_if(
            chunk_contextual_key_images.begin(),
            chunk_contextual_key_images.end(),
            [&](const SpContextualKeyImageSetV1 &contextual_key_image_set) -> bool
            {
                return has_key_image(contextual_key_image_set, new_record_key_image);
            }
        );

    if (contextual_key_images_of_record_spent_in_this_chunk != chunk_contextual_key_images.end())
    {
        // a. record that the enote is spent in this chunk
        found_spent_key_images_inout[new_record_key_image];

        // b. update its spent context (update instead of assignment in case of duplicates)
        try_update_enote_spent_context_v1(contextual_key_images_of_record_spent_in_this_chunk->m_spent_context,
            found_spent_key_images_inout[new_record_key_image]);

        // c. get the record's current spent context
        spent_context_update = found_spent_key_images_inout[new_record_key_image];

        // d. save the tx id of the tx in this chunk where this enote was spent
        // note: use spent context of contextual key images instead of the spent context update in case the update did
        //       not resolve to a tx in this chunk (probably a bug, but better safe than sorry here)
        txs_have_spent_enotes_inout.insert(
                contextual_key_images_of_record_spent_in_this_chunk->m_spent_context.m_transaction_id
            );
    }

    // 3. update the contextual enote record's contexts
    update_contextual_enote_record_contexts_v1(new_record_origin_context,
        spent_context_update,
        found_enote_records_inout[new_record_key_image].m_origin_context,
        found_enote_records_inout[new_record_key_image].m_spent_context);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void collect_legacy_key_images_from_tx(const rct::key &requested_tx_id,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_tx_inout)
{
    // find key images of requested tx
    auto contextual_key_images_of_requested_tx =
        std::find_if(
            chunk_contextual_key_images.begin(),
            chunk_contextual_key_images.end(),
            [&](const SpContextualKeyImageSetV1 &contextual_key_image_set) -> bool
            {
                return contextual_key_image_set.m_spent_context.m_transaction_id == requested_tx_id;
            }
        );

    CHECK_AND_ASSERT_THROW_MES(contextual_key_images_of_requested_tx != chunk_contextual_key_images.end(),
        "enote scanning (collect legacy key images from tx): could not find tx's key images.");

    // record legacy key images
    for (const crypto::key_image &legacy_key_image : contextual_key_images_of_requested_tx->m_legacy_key_images)
    {
        try_update_enote_spent_context_v1(contextual_key_images_of_requested_tx->m_spent_context,
            legacy_key_images_in_tx_inout[legacy_key_image]);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static std::unordered_set<rct::key> process_chunk_full_sp_selfsend_pass(
    const std::unordered_set<rct::key> &txs_have_spent_enotes,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &s_generate_address,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfspends_inout)
{
    // for each tx in this chunk that spends one of our enotes, check if any of the basic records attached to that
    //   tx contains a self-send enote owned by us
    // if any self-send enotes identified here are also spent in txs in this chunk, return those tx's ids so this function
    //   can be called in a loop (those txs will contain self-send enotes that need to be scanned, and may in turn be spent
    //   in this chunk)
    std::unordered_set<rct::key> txs_have_spent_enotes_fresh;
    SpEnoteRecordV1 new_enote_record;

    for (const rct::key &tx_with_spent_enotes : txs_have_spent_enotes)
    {
        CHECK_AND_ASSERT_THROW_MES(chunk_basic_records_per_tx.find(tx_with_spent_enotes) !=
                chunk_basic_records_per_tx.end(),
            "enote scan process chunk (self-send passthroughs): tx with spent enotes not found in records map (bug).");

        for (const ContextualBasicRecordVariant &contextual_basic_record :
            chunk_basic_records_per_tx.at(tx_with_spent_enotes))
        {
            if (!contextual_basic_record.is_type<SpContextualBasicEnoteRecordV1>())
                continue;

            try
            {
                // check if the enote is owned by attempting to convert it to a full enote record (selfsend conversion)
                if (!try_get_enote_record_v1_selfsend(
                        contextual_basic_record.unwrap<SpContextualBasicEnoteRecordV1>().m_record.m_enote,
                        contextual_basic_record.unwrap<SpContextualBasicEnoteRecordV1>().m_record
                            .m_enote_ephemeral_pubkey,
                        contextual_basic_record.unwrap<SpContextualBasicEnoteRecordV1>().m_record
                            .m_input_context,
                        jamtis_spend_pubkey,
                        k_view_balance,
                        s_generate_address,
                        new_enote_record))
                    continue;

                // we found an owned enote, so handle it
                // - this will check if the enote was also spent in this chunk, and update 'txs_have_spent_enotes_fresh'
                //   accordingly
                process_chunk_new_record_update_sp(new_enote_record,
                    origin_context_ref(contextual_basic_record),
                    chunk_contextual_key_images,
                    found_enote_records_inout,
                    found_spent_key_images_inout,
                    txs_have_spent_enotes_fresh);

                // record all legacy key images attached to this selfsend for the caller to deal with
                // - all legacy key images of owned legacy enotes spent in seraphis txs will be attached to seraphis
                //   txs with selfsend outputs, but during seraphis scanning it isn't guaranteed that we will be able
                //   to check if legacy key images attached to selfsend owned enotes are associated with owned legacy
                //   enotes; therefore we cache those legacy key images so they can be handled outside this scan process
                collect_legacy_key_images_from_tx(origin_context_ref(contextual_basic_record).m_transaction_id,
                    chunk_contextual_key_images,
                    legacy_key_images_in_sp_selfspends_inout);
            } catch (...) {}
        }
    }

    return txs_have_spent_enotes_fresh;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool try_find_legacy_enotes_in_tx(const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const std::uint64_t block_height,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    const std::uint64_t total_enotes_before_tx,
    const std::uint64_t unlock_time,
    const TxExtra &tx_memo,
    const std::vector<LegacyEnoteVariant> &enotes_in_tx,
    const SpEnoteOriginStatus origin_status,
    hw::device &hwdev,
    std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &basic_records_per_tx_inout)
{
    // extract enote ephemeral pubkeys from memo
    std::vector<crypto::public_key> legacy_enote_ephemeral_pubkeys;
    extract_legacy_enote_ephemeral_pubkeys_from_tx_extra(tx_memo, legacy_enote_ephemeral_pubkeys);

    if (legacy_enote_ephemeral_pubkeys.size() == 0)
        return false;

    // scan each enote in the tx
    std::size_t ephemeral_pubkey_index{0};
    crypto::key_derivation temp_DH_derivation;
    LegacyContextualBasicEnoteRecordV1 temp_contextual_record{};
    bool found_an_enote{false};

    for (std::size_t enote_index{0}; enote_index < enotes_in_tx.size(); ++enote_index)
    {
        // there can be fewer ephemeral pubkeys than enotes
        // - when we get to the end, keep using the last one
        if (enote_index < legacy_enote_ephemeral_pubkeys.size())
        {
            ephemeral_pubkey_index = enote_index;
            hwdev.generate_key_derivation(
                legacy_enote_ephemeral_pubkeys[ephemeral_pubkey_index],
                legacy_view_privkey,
                temp_DH_derivation);
        }

        // view scan the enote (in try block in case enote is malformed)
        try
        {
            if (!try_get_legacy_basic_enote_record(enotes_in_tx[enote_index],
                    rct::pk2rct(legacy_enote_ephemeral_pubkeys[ephemeral_pubkey_index]),
                    enote_index,
                    unlock_time,
                    temp_DH_derivation,
                    legacy_base_spend_pubkey,
                    legacy_subaddress_map,
                    hwdev,
                    temp_contextual_record.m_record))
                continue;

            temp_contextual_record.m_origin_context =
                SpEnoteOriginContextV1{
                        .m_block_height = block_height,
                        .m_block_timestamp = block_timestamp,
                        .m_transaction_id = transaction_id,
                        .m_enote_tx_index = enote_index,
                        .m_enote_ledger_index = total_enotes_before_tx + enote_index,
                        .m_origin_status = origin_status,
                        .m_memo = tx_memo
                    };

            // note: it is possible for enotes with duplicate onetime addresses to be added here; it is assumed the
            //       upstream caller will be able to handle those without problems
            basic_records_per_tx_inout[transaction_id].emplace_back(temp_contextual_record);

            found_an_enote = true;
        } catch (...) {}
    }

    return found_an_enote;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_find_sp_enotes_in_tx(const crypto::x25519_secret_key &xk_find_received,
    const std::uint64_t block_height,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    const std::uint64_t total_enotes_before_tx,
    const rct::key &input_context,
    const SpTxSupplementV1 &tx_supplement,
    const std::vector<SpEnoteVariant> &enotes_in_tx,
    const SpEnoteOriginStatus origin_status,
    std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &basic_records_per_tx_inout)
{
    if (tx_supplement.m_output_enote_ephemeral_pubkeys.size() == 0)
        return false;

    // scan each enote in the tx
    std::size_t ephemeral_pubkey_index{0};
    crypto::x25519_pubkey temp_DH_derivation;
    SpContextualBasicEnoteRecordV1 temp_contextual_record{};
    bool found_an_enote{false};

    for (std::size_t enote_index{0}; enote_index < enotes_in_tx.size(); ++enote_index)
    {
        // there can be fewer ephemeral pubkeys than enotes
        // - when we get to the end, keep using the last one
        if (enote_index < tx_supplement.m_output_enote_ephemeral_pubkeys.size())
        {
            ephemeral_pubkey_index = enote_index;
            crypto::x25519_scmul_key(xk_find_received,
                tx_supplement.m_output_enote_ephemeral_pubkeys[ephemeral_pubkey_index],
                temp_DH_derivation);
        }

        // find-receive scan the enote (in try block in case enote is malformed)
        try
        {
            if (!try_get_basic_enote_record_v1(enotes_in_tx[enote_index],
                    tx_supplement.m_output_enote_ephemeral_pubkeys[ephemeral_pubkey_index],
                    input_context,
                    temp_DH_derivation,
                    temp_contextual_record.m_record))
                continue;

            temp_contextual_record.m_origin_context =
                SpEnoteOriginContextV1{
                        .m_block_height = block_height,
                        .m_block_timestamp = block_timestamp,
                        .m_transaction_id = transaction_id,
                        .m_enote_tx_index = enote_index,
                        .m_enote_ledger_index = total_enotes_before_tx + enote_index,
                        .m_origin_status = origin_status,
                        .m_memo = tx_supplement.m_tx_extra
                    };

            // note: it is possible for enotes with duplicate onetime addresses to be added here; it is assumed the
            //       upstream caller will be able to handle those without problems
            basic_records_per_tx_inout[transaction_id].emplace_back(temp_contextual_record);

            found_an_enote = true;
        } catch (...) {}
    }

    return found_an_enote;
}
//-------------------------------------------------------------------------------------------------------------------
void collect_key_images_from_tx(const std::uint64_t block_height,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    const std::vector<crypto::key_image> &legacy_key_images_in_tx,
    const std::vector<crypto::key_image> &sp_key_images_in_tx,
    const SpEnoteSpentStatus spent_status,
    std::list<SpContextualKeyImageSetV1> &contextual_key_images_inout)
{
    if (legacy_key_images_in_tx.size() == 0 &&
        sp_key_images_in_tx.size() == 0)
        return;

    contextual_key_images_inout.emplace_back(
            SpContextualKeyImageSetV1{
                .m_legacy_key_images = legacy_key_images_in_tx,
                .m_sp_key_images = sp_key_images_in_tx,
                .m_spent_context =
                    SpEnoteSpentContextV1{
                        .m_block_height = block_height,
                        .m_block_timestamp = block_timestamp,
                        .m_transaction_id = transaction_id,
                        .m_spent_status = spent_status
                    }
            }
        );
}
//-------------------------------------------------------------------------------------------------------------------
void process_chunk_intermediate_legacy(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    const std::function<bool(const crypto::key_image&)> &check_key_image_is_known_func,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<rct::key, LegacyContextualIntermediateEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout)
{
    // 1. check if any legacy owned enotes have been spent in this chunk (key image matches)
    auto key_image_handler =
        [&](const SpEnoteSpentContextV1 &spent_context, const crypto::key_image &key_image)
        {
            // ask callback if key image is known (i.e. if the key image is attached to an owned enote acquired before
            //    the current scan process)
            // note: we cannot detect if enotes owned in this scan are also spent in this scan, because in intermediate
            //       scanning only the legacy viewkey is available so key images of new legacy
            //       enotes can't be computed
            if (check_key_image_is_known_func(key_image))
            {
                // record the found spent key image
                found_spent_key_images_inout[key_image];

                // update its spent context (use update instead of assignment in case of duplicates)
                try_update_enote_spent_context_v1(spent_context, found_spent_key_images_inout[key_image]);
            }
        };

    for (const SpContextualKeyImageSetV1 &contextual_key_image_set : chunk_contextual_key_images)
    {
        // invoke the key image handler for legacy key images in the chunk
        for (const crypto::key_image &key_image : contextual_key_image_set.m_legacy_key_images)
            key_image_handler(contextual_key_image_set.m_spent_context, key_image);
    }

    // 2. check for legacy owned enotes in this chunk
    LegacyIntermediateEnoteRecord new_enote_record;

    for (const auto &tx_basic_records : chunk_basic_records_per_tx)
    {
        for (const ContextualBasicRecordVariant &contextual_basic_record : tx_basic_records.second)
        {
            if (!contextual_basic_record.is_type<LegacyContextualBasicEnoteRecordV1>())
                continue;

            try
            {
                // check if we own the enote by attempting to convert it to an intermediate enote record
                if (!try_get_legacy_intermediate_enote_record(
                        contextual_basic_record.unwrap<LegacyContextualBasicEnoteRecordV1>().m_record,
                        legacy_base_spend_pubkey,
                        legacy_view_privkey,
                        new_enote_record))
                    continue;

                // we found an owned enote, so handle it
                process_chunk_new_intermediate_record_update_legacy(new_enote_record,
                    origin_context_ref(contextual_basic_record),
                    found_enote_records_inout);
            } catch (...) {}
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void process_chunk_intermediate_sp(const rct::key &jamtis_spend_pubkey,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_secret_key &xk_find_received,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    std::unordered_map<rct::key, SpContextualIntermediateEnoteRecordV1> &found_enote_records_inout)
{
    // check for owned enotes in this chunk (non-self-send intermediate scanning pass)
    SpIntermediateEnoteRecordV1 new_enote_record;

    for (const auto &tx_basic_records : chunk_basic_records_per_tx)
    {
        for (const ContextualBasicRecordVariant &contextual_basic_record : tx_basic_records.second)
        {
            if (!contextual_basic_record.is_type<SpContextualBasicEnoteRecordV1>())
                continue;

            try
            {
                // check if we own the enote by attempting to convert it to an intermediate enote record
                if (!try_get_intermediate_enote_record_v1(
                        contextual_basic_record.unwrap<SpContextualBasicEnoteRecordV1>().m_record,
                        jamtis_spend_pubkey,
                        xk_unlock_amounts,
                        xk_find_received,
                        s_generate_address,
                        cipher_context,
                        new_enote_record))
                    continue;

                // we found an owned enote, so handle it
                process_chunk_new_intermediate_record_update_sp(new_enote_record,
                    origin_context_ref(contextual_basic_record),
                    found_enote_records_inout);
            } catch (...) {}
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void process_chunk_full_legacy(const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &legacy_view_privkey,
    const std::function<bool(const crypto::key_image&)> &check_key_image_is_known_func,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<rct::key, LegacyContextualEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout)
{
    // 1. check if any legacy owned enotes acquired before this chunk were spent in this chunk (key image matches)
    auto key_image_handler =
        [&](const SpEnoteSpentContextV1 &spent_context, const crypto::key_image &key_image)
        {
            // a. ask callback if key image is known (i.e. if the key image is attached to an owned enote acquired before
            //    the current scan process)
            // b. check if owned enotes acquired earlier in this scan process (before this chunk) have this key image
            if (check_key_image_is_known_func(key_image) ||
                std::find_if(found_enote_records_inout.begin(), found_enote_records_inout.end(),
                    [&key_image](const auto &mapped_legacy_record) -> bool
                    {
                        return mapped_legacy_record.second.m_record.m_key_image == key_image;
                    }) != found_enote_records_inout.end()
                )
            {
                // record the found spent key image
                found_spent_key_images_inout[key_image];

                // update its spent context (use update instead of assignment in case of duplicates)
                try_update_enote_spent_context_v1(spent_context, found_spent_key_images_inout[key_image]);
            }
        };

    for (const SpContextualKeyImageSetV1 &contextual_key_image_set : chunk_contextual_key_images)
    {
        // invoke the key image handler for legacy key images in the chunk
        for (const crypto::key_image &key_image : contextual_key_image_set.m_legacy_key_images)
            key_image_handler(contextual_key_image_set.m_spent_context, key_image);
    }

    // 2. check for legacy owned enotes in this chunk
    LegacyEnoteRecord new_enote_record;

    for (const auto &tx_basic_records : chunk_basic_records_per_tx)
    {
        for (const ContextualBasicRecordVariant &contextual_basic_record : tx_basic_records.second)
        {
            if (!contextual_basic_record.is_type<LegacyContextualBasicEnoteRecordV1>())
                continue;

            try
            {
                // check if we own the enote by attempting to convert it to a full enote record
                if (!try_get_legacy_enote_record(
                        contextual_basic_record.unwrap<LegacyContextualBasicEnoteRecordV1>().m_record,
                        legacy_base_spend_pubkey,
                        legacy_spend_privkey,
                        legacy_view_privkey,
                        new_enote_record))
                    continue;

                // we found an owned enote, so handle it
                process_chunk_new_record_update_legacy(new_enote_record,
                    origin_context_ref(contextual_basic_record),
                    chunk_contextual_key_images,
                    found_enote_records_inout,
                    found_spent_key_images_inout);
            } catch (...) {}
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
void process_chunk_full_sp(const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::x25519_secret_key &xk_unlock_amounts,
    const crypto::x25519_secret_key &xk_find_received,
    const crypto::secret_key &s_generate_address,
    const jamtis::jamtis_address_tag_cipher_context &cipher_context,
    const std::function<bool(const crypto::key_image&)> &check_key_image_is_known_func,
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    std::unordered_map<crypto::key_image, SpContextualEnoteRecordV1> &found_enote_records_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &found_spent_key_images_inout,
    std::unordered_map<crypto::key_image, SpEnoteSpentContextV1> &legacy_key_images_in_sp_selfspends_inout)
{
    std::unordered_set<rct::key> txs_have_spent_enotes;

    // 1. check if any owned enotes acquired before this chunk were spent in this chunk (key image matches)
    auto key_image_handler =
        [&](const SpEnoteSpentContextV1 &spent_context, const crypto::key_image &key_image)
        {
            // a. ask callback if key image is known (i.e. if the key image is attached to an owned enote acquired before
            //    the current scan process)
            // b. check if owned enotes acquired earlier in this scan process (before this chunk) have this key image
            if (check_key_image_is_known_func(key_image) ||
                found_enote_records_inout.find(key_image) != found_enote_records_inout.end())
            {
                // record the found spent key image
                found_spent_key_images_inout[key_image];

                // update its spent context (use update instead of assignment in case of duplicates)
                try_update_enote_spent_context_v1(spent_context, found_spent_key_images_inout[key_image]);

                // record tx id of the tx that contains this key image (this tx spent one of our owned enotes acquired
                //   before this chunk)
                txs_have_spent_enotes.insert(spent_context.m_transaction_id);
            }
        };

    for (const SpContextualKeyImageSetV1 &contextual_key_image_set : chunk_contextual_key_images)
    {
        // invoke the key image handler for legacy key images in the chunk
        for (const crypto::key_image &key_image : contextual_key_image_set.m_legacy_key_images)
            key_image_handler(contextual_key_image_set.m_spent_context, key_image);

        // invoke the key image handler for seraphis key images in the chunk
        for (const crypto::key_image &key_image : contextual_key_image_set.m_sp_key_images)
            key_image_handler(contextual_key_image_set.m_spent_context, key_image);

        // save tx id of txs that contain at least one legacy key image, so they can be examined by the selfsend pass
        // - Checking if a legacy key image is known before this chunk may fail during a view-only scan because legacy
        //   key images are not computable by the legacy view key. Txs with legacy key images may or may not contain
        //   seraphis selfsend outputs, so we always need to check them.
        if (contextual_key_image_set.m_legacy_key_images.size() > 0)
            txs_have_spent_enotes.insert(contextual_key_image_set.m_spent_context.m_transaction_id);
    }

    // 2. check if this chunk contains owned enotes (non-self-send pass)
    SpEnoteRecordV1 new_enote_record;

    for (const auto &tx_basic_records : chunk_basic_records_per_tx)
    {
        for (const ContextualBasicRecordVariant &contextual_basic_record : tx_basic_records.second)
        {
            if (!contextual_basic_record.is_type<SpContextualBasicEnoteRecordV1>())
                continue;

            try
            {
                // check if we own the enote by attempting to convert it to a full enote record
                if (!try_get_enote_record_v1_plain(
                        contextual_basic_record.unwrap<SpContextualBasicEnoteRecordV1>().m_record,
                        jamtis_spend_pubkey,
                        k_view_balance,
                        xk_unlock_amounts,
                        xk_find_received,
                        s_generate_address,
                        cipher_context,
                        new_enote_record))
                    continue;

                // we found an owned enote, so handle it
                // - this will check if the enote was also spent in this chunk, and update 'txs_have_spent_enotes'
                //   accordingly
                process_chunk_new_record_update_sp(new_enote_record,
                    origin_context_ref(contextual_basic_record),
                    chunk_contextual_key_images,
                    found_enote_records_inout,
                    found_spent_key_images_inout,
                    txs_have_spent_enotes);
            } catch (...) {}
        }
    }

    // 3. check for owned enotes in this chunk (self-send passes)
    // - a selfsend pass identifies owned selfsend enotes in txs that have been flagged, and then flags txs where
    //   those enotes have been spent in this chunk
    // - we loop through selfsend passes until no more txs are flagged
    std::unordered_set<rct::key> txs_have_spent_enotes_selfsend_passthrough{std::move(txs_have_spent_enotes)};

    while (txs_have_spent_enotes_selfsend_passthrough.size() > 0)
    {
        txs_have_spent_enotes_selfsend_passthrough =
            process_chunk_full_sp_selfsend_pass(txs_have_spent_enotes_selfsend_passthrough,
                jamtis_spend_pubkey,
                k_view_balance,
                s_generate_address,
                chunk_basic_records_per_tx,
                chunk_contextual_key_images,
                found_enote_records_inout,
                found_spent_key_images_inout,
                legacy_key_images_in_sp_selfspends_inout);
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp

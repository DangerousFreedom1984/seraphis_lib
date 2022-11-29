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
#include "mock_ledger_context.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "cryptonote_basic/subaddress_index.h"
#include "device/device.hpp"
#include "misc_log_ex.h"
#include "ringct/rctTypes.h"
#include "seraphis/jamtis_enote_utils.h"
#include "seraphis/legacy_enote_types.h"
#include "seraphis/sp_core_enote_utils.h"
#include "seraphis/tx_component_types.h"
#include "seraphis/tx_enote_scanning.h"
#include "seraphis/tx_enote_scanning_utils.h"
#include "seraphis/txtype_coinbase_v1.h"
#include "seraphis/txtype_squashed_v1.h"
#include "seraphis_crypto/sp_crypto_utils.h"

//third party headers
#include <boost/thread/locks.hpp>
#include <boost/thread/shared_mutex.hpp>

//standard headers
#include <algorithm>
#include <type_traits>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_mocks"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename MapT>
static void erase_ledger_cache_map_from_height(const std::uint64_t pop_height, MapT &map_inout)
{
    static_assert(std::is_same<typename MapT::key_type, std::uint64_t>::value, "erase ledger map key is not uint64_t");

    if (map_inout.size() == 0)
        return;

    // erase entire map if pop height is below first known height, otherwise erase from pop height directly
    const std::uint64_t height_to_erase_from =
        map_inout.begin()->first >= pop_height
        ? map_inout.begin()->first
        : pop_height;

    map_inout.erase(map_inout.find(height_to_erase_from), map_inout.end());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
MockLedgerContext::MockLedgerContext(const std::uint64_t first_seraphis_allowed_block,
    const std::uint64_t first_seraphis_only_block) :
        m_first_seraphis_allowed_block{first_seraphis_allowed_block},
        m_first_seraphis_only_block{first_seraphis_only_block}
{
    CHECK_AND_ASSERT_THROW_MES(m_first_seraphis_allowed_block <= m_first_seraphis_only_block,
        "mock ledger context (constructor): invalid seraphis tx era range.");
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::chain_height() const
{
    return m_block_infos.size() - 1;
}
//-------------------------------------------------------------------------------------------------------------------
bool MockLedgerContext::key_image_exists_unconfirmed_v1(const crypto::key_image &key_image) const
{
    boost::shared_lock<boost::shared_mutex> lock{m_context_mutex};

    return this->key_image_exists_unconfirmed_v1_impl(key_image);
}
//-------------------------------------------------------------------------------------------------------------------
bool MockLedgerContext::key_image_exists_onchain_v1(const crypto::key_image &key_image) const
{
    boost::shared_lock<boost::shared_mutex> lock{m_context_mutex};

    return this->key_image_exists_onchain_v1_impl(key_image);
}
//-------------------------------------------------------------------------------------------------------------------
void MockLedgerContext::get_reference_set_proof_elements_v1(const std::vector<std::uint64_t> &indices,
    rct::ctkeyV &proof_elements_out) const
{
    boost::shared_lock<boost::shared_mutex> lock{m_context_mutex};

    // get legacy enotes: {KI, C}
    proof_elements_out.clear();
    proof_elements_out.reserve(indices.size());

    for (const std::uint64_t index : indices)
    {
        CHECK_AND_ASSERT_THROW_MES(index < m_legacy_enote_references.size(),
            "Tried to get legacy enote that doesn't exist.");
        proof_elements_out.emplace_back(m_legacy_enote_references.at(index));
    }
}
//-------------------------------------------------------------------------------------------------------------------
void MockLedgerContext::get_reference_set_proof_elements_v2(const std::vector<std::uint64_t> &indices,
    rct::keyV &proof_elements_out) const
{
    boost::shared_lock<boost::shared_mutex> lock{m_context_mutex};

    // get squashed enotes
    proof_elements_out.clear();
    proof_elements_out.reserve(indices.size());

    for (const std::uint64_t index : indices)
    {
        CHECK_AND_ASSERT_THROW_MES(index < m_sp_squashed_enotes.size(), "Tried to get squashed enote that doesn't exist.");
        proof_elements_out.emplace_back(m_sp_squashed_enotes.at(index));
    }
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::max_legacy_enote_index() const
{
    return m_legacy_enote_references.size() - 1;
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::max_sp_enote_index() const
{
    return m_sp_squashed_enotes.size() - 1;
}
//-------------------------------------------------------------------------------------------------------------------
void MockLedgerContext::get_onchain_chunk_legacy(const std::uint64_t chunk_start_height,
    const std::uint64_t chunk_max_size,
    const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const LegacyScanMode legacy_scan_mode,
    EnoteScanningChunkLedgerV1 &chunk_out) const
{
    boost::shared_lock<boost::shared_mutex> lock{m_context_mutex};

    this->get_onchain_chunk_legacy_impl(chunk_start_height,
        chunk_max_size,
        legacy_base_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        legacy_scan_mode,
        chunk_out);
}
//-------------------------------------------------------------------------------------------------------------------
void MockLedgerContext::get_onchain_chunk_sp(const std::uint64_t chunk_start_height,
    const std::uint64_t chunk_max_size,
    const crypto::x25519_secret_key &xk_find_received,
    EnoteScanningChunkLedgerV1 &chunk_out) const
{
    boost::shared_lock<boost::shared_mutex> lock{m_context_mutex};

    this->get_onchain_chunk_sp_impl(chunk_start_height, chunk_max_size, xk_find_received, chunk_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool MockLedgerContext::try_get_unconfirmed_chunk_sp(const crypto::x25519_secret_key &xk_find_received,
    EnoteScanningChunkNonLedgerV1 &chunk_out) const
{
    boost::shared_lock<boost::shared_mutex> lock{m_context_mutex};

    return this->try_get_unconfirmed_chunk_sp_impl(xk_find_received, chunk_out);
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::add_legacy_coinbase(const rct::key &tx_id,
    const std::uint64_t unlock_time,
    TxExtra memo,
    std::vector<crypto::key_image> legacy_key_images_for_block,
    std::vector<LegacyEnoteVariant> output_enotes)
{
    boost::unique_lock<boost::shared_mutex> lock{m_context_mutex};

    return this->add_legacy_coinbase_impl(tx_id,
        unlock_time,
        std::move(memo),
        std::move(legacy_key_images_for_block),
        std::move(output_enotes));
}
//-------------------------------------------------------------------------------------------------------------------
bool MockLedgerContext::try_add_unconfirmed_tx_v1(const SpTxSquashedV1 &tx)
{
    boost::unique_lock<boost::shared_mutex> lock{m_context_mutex};

    return this->try_add_unconfirmed_tx_v1_impl(tx);
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::commit_unconfirmed_txs_v1(const SpTxCoinbaseV1 &coinbase_tx)
{
    boost::unique_lock<boost::shared_mutex> lock{m_context_mutex};

    return this->commit_unconfirmed_txs_v1_impl(coinbase_tx);
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::commit_unconfirmed_txs_v1(const rct::key &mock_coinbase_input_context,
    SpTxSupplementV1 mock_coinbase_tx_supplement,
    std::vector<SpEnoteVariant> mock_coinbase_output_enotes)
{
    boost::unique_lock<boost::shared_mutex> lock{m_context_mutex};

    return this->commit_unconfirmed_txs_v1_impl(rct::pkGen(),
        mock_coinbase_input_context,
        std::move(mock_coinbase_tx_supplement),
        std::move(mock_coinbase_output_enotes));
}
//-------------------------------------------------------------------------------------------------------------------
void MockLedgerContext::remove_tx_from_unconfirmed_cache(const rct::key &tx_id)
{
    boost::unique_lock<boost::shared_mutex> lock{m_context_mutex};

    this->remove_tx_from_unconfirmed_cache_impl(tx_id);
}
//-------------------------------------------------------------------------------------------------------------------
void MockLedgerContext::clear_unconfirmed_cache()
{
    boost::unique_lock<boost::shared_mutex> lock{m_context_mutex};

    this->clear_unconfirmed_cache_impl();
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::pop_chain_at_height(const std::uint64_t pop_height)
{
    boost::unique_lock<boost::shared_mutex> lock{m_context_mutex};

    return this->pop_chain_at_height_impl(pop_height);
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::pop_blocks(const std::size_t num_blocks)
{
    boost::unique_lock<boost::shared_mutex> lock{m_context_mutex};

    return this->pop_blocks_impl(num_blocks);
}
//-------------------------------------------------------------------------------------------------------------------
// internal implementation details
//-------------------------------------------------------------------------------------------------------------------
bool MockLedgerContext::key_image_exists_unconfirmed_v1_impl(const crypto::key_image &key_image) const
{
    return m_unconfirmed_legacy_key_images.find(key_image) != m_unconfirmed_legacy_key_images.end() ||
        m_unconfirmed_sp_key_images.find(key_image) != m_unconfirmed_sp_key_images.end();
}
//-------------------------------------------------------------------------------------------------------------------
bool MockLedgerContext::key_image_exists_onchain_v1_impl(const crypto::key_image &key_image) const
{
    return m_legacy_key_images.find(key_image) != m_legacy_key_images.end() ||
        m_sp_key_images.find(key_image) != m_sp_key_images.end();
}
//-------------------------------------------------------------------------------------------------------------------
void MockLedgerContext::get_onchain_chunk_legacy_impl(const std::uint64_t chunk_start_height,
    const std::uint64_t chunk_max_size,
    const rct::key &legacy_base_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const LegacyScanMode legacy_scan_mode,
    EnoteScanningChunkLedgerV1 &chunk_out) const
{
    chunk_out.m_basic_records_per_tx.clear();
    chunk_out.m_contextual_key_images.clear();
    chunk_out.m_block_ids.clear();

    /// 1. failure cases
    if (this->chain_height() + 1 == 0 ||
        chunk_start_height >= m_first_seraphis_only_block ||
        chunk_start_height > this->chain_height() ||
        chunk_max_size == 0)
    {
        // set empty chunk info: top of the legacy-enabled chain
        chunk_out.m_start_height = std::min(m_first_seraphis_only_block, this->chain_height() + 1);
        chunk_out.m_end_height = chunk_out.m_start_height;

        if (chunk_out.m_start_height > 0)
        {
            CHECK_AND_ASSERT_THROW_MES(m_block_infos.find(chunk_out.m_start_height - 1) != m_block_infos.end(),
                "onchain chunk legacy-view scanning (mock ledger context): block ids map incorrect indexing (bug).");

            chunk_out.m_prefix_block_id = std::get<rct::key>(m_block_infos.at(chunk_out.m_start_height - 1));
        }
        else
            chunk_out.m_prefix_block_id = rct::zero();

        return;
    }


    /// 2. set block information
    // a. block range (cap on the lowest of: chain height, seraphis-only range begins, chunk size)
    chunk_out.m_start_height = chunk_start_height;
    chunk_out.m_end_height =
        std::min({this->chain_height() + 1, m_first_seraphis_only_block, chunk_start_height + chunk_max_size});

    CHECK_AND_ASSERT_THROW_MES(chunk_out.m_end_height > chunk_out.m_start_height,
        "onchain chunk legacy-view scanning (mock ledger context): chunk has no blocks below failure tests (bug).");
    CHECK_AND_ASSERT_THROW_MES(m_block_infos.find(chunk_out.m_start_height) != m_block_infos.end() &&
            m_block_infos.find(chunk_out.m_end_height - 1) != m_block_infos.end(),
        "onchain chunk legacy-view scanning (mock ledger context): block range outside of block ids map (bug).");

    // b. prefix block id
    chunk_out.m_prefix_block_id =
        chunk_start_height > 0
        ? std::get<rct::key>(m_block_infos.at(chunk_start_height - 1))
        : rct::zero();

    // c. block ids in the range
    chunk_out.m_block_ids.reserve(chunk_out.m_end_height - chunk_out.m_start_height);

    std::for_each(
            m_block_infos.find(chunk_out.m_start_height),
            m_block_infos.find(chunk_out.m_end_height),
            [&](const auto &mapped_block_info)
            {
                chunk_out.m_block_ids.emplace_back(std::get<rct::key>(mapped_block_info.second));
            }
        );

    CHECK_AND_ASSERT_THROW_MES(chunk_out.m_block_ids.size() == chunk_out.m_end_height - chunk_out.m_start_height,
        "onchain chunk legacy-view scanning (mock ledger context): invalid number of block ids acquired (bug).");


    /// 3. scan blocks in the chunk range that may contain legacy enotes or key images
    // a. early return if chunk doesn't cover any legacy enabled blocks
    // - we did this in failure tests above

    // b. get adjusted chunk end
    // - we did this when defining the chunk end

    CHECK_AND_ASSERT_THROW_MES(m_blocks_of_legacy_tx_output_contents.find(chunk_out.m_start_height) !=
            m_blocks_of_legacy_tx_output_contents.end(),
        "onchain chunk legacy-view scanning (mock ledger context): start of chunk not known in tx outputs map (bug).");
    CHECK_AND_ASSERT_THROW_MES(m_blocks_of_legacy_tx_output_contents.find(chunk_out.m_end_height - 1) !=
            m_blocks_of_legacy_tx_output_contents.end(),
        "onchain chunk legacy-view scanning (mock ledger context): end of chunk not known in tx outputs map (bug).");
    CHECK_AND_ASSERT_THROW_MES(m_blocks_of_tx_key_images.find(chunk_out.m_start_height) !=
            m_blocks_of_tx_key_images.end(),
        "onchain chunk legacy-view scanning (mock ledger context): start of chunk not known in key images map (bug).");
    CHECK_AND_ASSERT_THROW_MES(m_blocks_of_tx_key_images.find(chunk_out.m_end_height - 1) !=
            m_blocks_of_tx_key_images.end(),
        "onchain chunk legacy-view scanning (mock ledger context): end of chunk not known in key images map (bug).");

    // a. initialize output count to the total number of legacy enotes in the ledger before the first block to scan
    std::uint64_t total_output_count_before_tx{0};

    if (chunk_out.m_start_height > 0)
    {
        CHECK_AND_ASSERT_THROW_MES(m_accumulated_legacy_output_counts.find(chunk_out.m_start_height - 1) !=
                m_accumulated_legacy_output_counts.end(),
            "onchain chunk legacy-view scanning (mock ledger context): output counts missing a block (bug).");

        total_output_count_before_tx = m_accumulated_legacy_output_counts.at(chunk_out.m_start_height - 1);
    }

    // b. legacy-view scan each block in the range
    std::for_each(
            m_blocks_of_legacy_tx_output_contents.find(chunk_out.m_start_height),
            m_blocks_of_legacy_tx_output_contents.find(chunk_out.m_end_height),
            [&](const auto &block_of_tx_output_contents)
            {
                CHECK_AND_ASSERT_THROW_MES(m_block_infos.find(block_of_tx_output_contents.first) != m_block_infos.end(),
                    "onchain chunk legacy-view scanning (mock ledger context): block infos map missing height (bug).");

                for (const auto &tx_with_output_contents : block_of_tx_output_contents.second)
                {
                    // legacy view-scan the tx if in scan mode
                    if (legacy_scan_mode == LegacyScanMode::SCAN)
                    {
                        try_find_legacy_enotes_in_tx(legacy_base_spend_pubkey,
                            legacy_subaddress_map,
                            legacy_view_privkey,
                            block_of_tx_output_contents.first,
                            std::get<std::uint64_t>(m_block_infos.at(block_of_tx_output_contents.first)),
                            sortable2rct(tx_with_output_contents.first),
                            total_output_count_before_tx,
                            std::get<std::uint64_t>(tx_with_output_contents.second),
                            std::get<TxExtra>(tx_with_output_contents.second),
                            std::get<std::vector<LegacyEnoteVariant>>(tx_with_output_contents.second),
                            SpEnoteOriginStatus::ONCHAIN,
                            hw::get_device("default"),
                            chunk_out.m_basic_records_per_tx);
                    }

                    // always add an entry for this tx in the basic records map (since we save key images for every tx)
                    chunk_out.m_basic_records_per_tx[sortable2rct(tx_with_output_contents.first)];

                    // collect key images from the tx (always do this for legacy txs)
                    CHECK_AND_ASSERT_THROW_MES(
                        m_blocks_of_tx_key_images
                            .at(block_of_tx_output_contents.first).find(tx_with_output_contents.first) !=
                        m_blocks_of_tx_key_images
                            .at(block_of_tx_output_contents.first).end(),
                        "onchain chunk legacy-view scanning (mock ledger context): key image map missing tx (bug).");

                    collect_key_images_from_tx(block_of_tx_output_contents.first,
                        std::get<std::uint64_t>(m_block_infos.at(block_of_tx_output_contents.first)),
                        sortable2rct(tx_with_output_contents.first),
                        std::get<0>(m_blocks_of_tx_key_images
                            .at(block_of_tx_output_contents.first)
                            .at(tx_with_output_contents.first)),
                        std::get<1>(m_blocks_of_tx_key_images
                            .at(block_of_tx_output_contents.first)
                            .at(tx_with_output_contents.first)),
                        SpEnoteSpentStatus::SPENT_ONCHAIN,
                        chunk_out.m_contextual_key_images);

                    // add this tx's number of outputs to the total output count
                    total_output_count_before_tx +=
                        std::get<std::vector<LegacyEnoteVariant>>(tx_with_output_contents.second).size();
                }
            }
        );

    for (const SpContextualKeyImageSetV1 &key_image_set : chunk_out.m_contextual_key_images)
    {
        CHECK_AND_ASSERT_THROW_MES(key_image_set.m_sp_key_images.size() == 0,
            "onchain chunk legacy-view scanning (mock ledger context): a legacy tx has sp key images (bug).");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void MockLedgerContext::get_onchain_chunk_sp_impl(const std::uint64_t chunk_start_height,
    const std::uint64_t chunk_max_size,
    const crypto::x25519_secret_key &xk_find_received,
    EnoteScanningChunkLedgerV1 &chunk_out) const
{
    chunk_out.m_basic_records_per_tx.clear();
    chunk_out.m_contextual_key_images.clear();
    chunk_out.m_block_ids.clear();

    /// 1. failure cases
    if (this->chain_height() + 1 == 0 ||
        chunk_start_height > this->chain_height() ||
        chunk_max_size == 0)
    {
        // set empty chunk info: top of the chain
        chunk_out.m_start_height = this->chain_height() + 1;
        chunk_out.m_end_height = chunk_out.m_start_height;

        if (chunk_out.m_start_height > 0)
        {
            CHECK_AND_ASSERT_THROW_MES(m_block_infos.find(chunk_out.m_start_height - 1) != m_block_infos.end(),
                "onchain chunk find-received scanning (mock ledger context): block ids map incorrect indexing (bug).");

            chunk_out.m_prefix_block_id = std::get<rct::key>(m_block_infos.at(chunk_out.m_start_height - 1));
        }
        else
            chunk_out.m_prefix_block_id = rct::zero();

        return;
    }


    /// 2. set block information
    // a. block range
    chunk_out.m_start_height = chunk_start_height;
    chunk_out.m_end_height = std::min(this->chain_height() + 1, chunk_start_height + chunk_max_size);

    CHECK_AND_ASSERT_THROW_MES(chunk_out.m_end_height > chunk_out.m_start_height,
        "onchain chunk find-received scanning (mock ledger context): chunk has no blocks below failure tests (bug).");
    CHECK_AND_ASSERT_THROW_MES(m_block_infos.find(chunk_out.m_start_height) != m_block_infos.end() &&
            m_block_infos.find(chunk_out.m_end_height - 1) != m_block_infos.end(),
        "onchain chunk find-received scanning (mock ledger context): block range outside of block ids map (bug).");

    // b. prefix block id
    chunk_out.m_prefix_block_id =
        chunk_start_height > 0
        ? std::get<rct::key>(m_block_infos.at(chunk_start_height - 1))
        : rct::zero();

    // c. block ids in the range
    chunk_out.m_block_ids.reserve(chunk_out.m_end_height - chunk_out.m_start_height);

    std::for_each(
            m_block_infos.find(chunk_out.m_start_height),
            m_block_infos.find(chunk_out.m_end_height),
            [&](const auto &mapped_block_info)
            {
                chunk_out.m_block_ids.emplace_back(std::get<rct::key>(mapped_block_info.second));
            }
        );

    CHECK_AND_ASSERT_THROW_MES(chunk_out.m_block_ids.size() == chunk_out.m_end_height - chunk_out.m_start_height,
        "onchain chunk find-received scanning (mock ledger context): invalid number of block ids acquired (bug).");


    /// 3. scan blocks in the chunk range that may contain seraphis enotes or key images
    // a. early return if chunk doesn't cover any seraphis enabled blocks
    if (chunk_out.m_end_height <= m_first_seraphis_allowed_block)
        return;

    // b. get adjusted chunk start
    const std::uint64_t chunk_start_adjusted{
            std::max(chunk_out.m_start_height + 1, m_first_seraphis_allowed_block + 1) - 1
        };

    CHECK_AND_ASSERT_THROW_MES(m_blocks_of_sp_tx_output_contents.find(chunk_start_adjusted) !=
            m_blocks_of_sp_tx_output_contents.end(),
        "onchain chunk find-received scanning (mock ledger context): start of chunk not known in tx outputs map (bug).");
    CHECK_AND_ASSERT_THROW_MES(m_blocks_of_sp_tx_output_contents.find(chunk_out.m_end_height - 1) !=
            m_blocks_of_sp_tx_output_contents.end(),
        "onchain chunk find-received scanning (mock ledger context): end of chunk not known in tx outputs map (bug).");
    CHECK_AND_ASSERT_THROW_MES(m_blocks_of_tx_key_images.find(chunk_start_adjusted) !=
            m_blocks_of_tx_key_images.end(),
        "onchain chunk find-received scanning (mock ledger context): start of chunk not known in key images map (bug).");
    CHECK_AND_ASSERT_THROW_MES(m_blocks_of_tx_key_images.find(chunk_out.m_end_height - 1) !=
            m_blocks_of_tx_key_images.end(),
        "onchain chunk find-received scanning (mock ledger context): end of chunk not known in key images map (bug).");

    // c. initialize output count to the total number of seraphis enotes in the ledger before the first block to scan
    std::uint64_t total_output_count_before_tx{0};

    if (chunk_start_adjusted > m_first_seraphis_allowed_block)
    {
        CHECK_AND_ASSERT_THROW_MES(m_accumulated_sp_output_counts.find(chunk_start_adjusted - 1) !=
                m_accumulated_sp_output_counts.end(),
            "onchain chunk find-received scanning (mock ledger context): output counts missing a block (bug).");

        total_output_count_before_tx = m_accumulated_sp_output_counts.at(chunk_start_adjusted - 1);
    }

    // d. find-received scan each block in the range
    std::for_each(
            m_blocks_of_sp_tx_output_contents.find(chunk_start_adjusted),
            m_blocks_of_sp_tx_output_contents.find(chunk_out.m_end_height),
            [&](const auto &block_of_tx_output_contents)
            {
                CHECK_AND_ASSERT_THROW_MES(m_block_infos.find(block_of_tx_output_contents.first) != m_block_infos.end(),
                    "onchain chunk find-received scanning (mock ledger context): block infos map missing height (bug).");

                for (const auto &tx_with_output_contents : block_of_tx_output_contents.second)
                {
                    // if this tx contains at least one view-tag match, then add the tx's key images to the chunk
                    if (try_find_sp_enotes_in_tx(xk_find_received,
                        block_of_tx_output_contents.first,
                        std::get<std::uint64_t>(m_block_infos.at(block_of_tx_output_contents.first)),
                        sortable2rct(tx_with_output_contents.first),
                        total_output_count_before_tx,
                        std::get<rct::key>(tx_with_output_contents.second),
                        std::get<SpTxSupplementV1>(tx_with_output_contents.second),
                        std::get<std::vector<SpEnoteVariant>>(tx_with_output_contents.second),
                        SpEnoteOriginStatus::ONCHAIN,
                        chunk_out.m_basic_records_per_tx))
                    {
                        CHECK_AND_ASSERT_THROW_MES(
                            m_blocks_of_tx_key_images
                                .at(block_of_tx_output_contents.first).find(tx_with_output_contents.first) !=
                            m_blocks_of_tx_key_images
                                .at(block_of_tx_output_contents.first).end(),
                            "onchain chunk find-received scanning (mock ledger context): key image map missing tx (bug).");

                        collect_key_images_from_tx(block_of_tx_output_contents.first,
                            std::get<std::uint64_t>(m_block_infos.at(block_of_tx_output_contents.first)),
                            sortable2rct(tx_with_output_contents.first),
                            std::get<0>(m_blocks_of_tx_key_images
                                .at(block_of_tx_output_contents.first)
                                .at(tx_with_output_contents.first)),
                            std::get<1>(m_blocks_of_tx_key_images
                                .at(block_of_tx_output_contents.first)
                                .at(tx_with_output_contents.first)),
                            SpEnoteSpentStatus::SPENT_ONCHAIN,
                            chunk_out.m_contextual_key_images);
                    }

                    // add this tx's number of outputs to the total output count
                    total_output_count_before_tx +=
                        std::get<std::vector<SpEnoteVariant>>(tx_with_output_contents.second).size();
                }
            }
        );
}
//-------------------------------------------------------------------------------------------------------------------
bool MockLedgerContext::try_get_unconfirmed_chunk_sp_impl(const crypto::x25519_secret_key &xk_find_received,
    EnoteScanningChunkNonLedgerV1 &chunk_out) const
{
    // no chunk if no txs to scan
    if (m_unconfirmed_tx_output_contents.size() == 0)
        return false;

    // find-received scan each tx in the unconfirmed chache
    chunk_out.m_basic_records_per_tx.clear();
    chunk_out.m_contextual_key_images.clear();

    for (const auto &tx_with_output_contents : m_unconfirmed_tx_output_contents)
    {
        // if this tx contains at least one view-tag match, then add the tx's key images to the chunk
        if (try_find_sp_enotes_in_tx(xk_find_received,
            -1,
            -1,
            sortable2rct(tx_with_output_contents.first),
            0,
            std::get<rct::key>(tx_with_output_contents.second),
            std::get<SpTxSupplementV1>(tx_with_output_contents.second),
            std::get<std::vector<SpEnoteVariant>>(tx_with_output_contents.second),
            SpEnoteOriginStatus::UNCONFIRMED,
            chunk_out.m_basic_records_per_tx))
        {
            CHECK_AND_ASSERT_THROW_MES(m_unconfirmed_tx_key_images.find(tx_with_output_contents.first) !=
                    m_unconfirmed_tx_key_images.end(),
                "unconfirmed chunk find-received scanning (mock ledger context): key image map missing tx (bug).");

            collect_key_images_from_tx(-1,
                -1,
                sortable2rct(tx_with_output_contents.first),
                std::get<0>(m_unconfirmed_tx_key_images.at(tx_with_output_contents.first)),
                std::get<1>(m_unconfirmed_tx_key_images.at(tx_with_output_contents.first)),
                SpEnoteSpentStatus::SPENT_UNCONFIRMED,
                chunk_out.m_contextual_key_images);
        }
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::add_legacy_coinbase_impl(const rct::key &tx_id,
    const std::uint64_t unlock_time,
    TxExtra memo,
    std::vector<crypto::key_image> legacy_key_images_for_block,
    std::vector<LegacyEnoteVariant> output_enotes)
{
    /// checks

    // a. can only add blocks with a mock legacy coinbase tx prior to first seraphis-enabled block
    CHECK_AND_ASSERT_THROW_MES(this->chain_height() + 1 < m_first_seraphis_only_block,
        "mock tx ledger (adding legacy coinbase tx): chain height is above last block that can have a legacy coinbase tx.");

    // b. accumulated output count is consistent
    const std::uint64_t accumulated_output_count =
        m_accumulated_legacy_output_counts.size()
        ? (m_accumulated_legacy_output_counts.rbegin())->second  //last block's accumulated legacy output count
        : 0;

    CHECK_AND_ASSERT_THROW_MES(accumulated_output_count == m_legacy_enote_references.size(),
        "mock tx ledger (adding legacy coinbase tx): inconsistent number of accumulated outputs (bug).");


    /// update state
    const std::uint64_t new_height{this->chain_height() + 1};

    // 1. add legacy key images (mockup: force key images into chain as part of coinbase tx)
    for (const crypto::key_image &legacy_key_image : legacy_key_images_for_block)
        m_legacy_key_images.insert(legacy_key_image);

    m_blocks_of_tx_key_images[new_height][tx_id] = {std::move(legacy_key_images_for_block), {}};

    // 2. add tx outputs

    // a. initialize with current total legacy output count
    std::uint64_t total_legacy_output_count{m_legacy_enote_references.size()};

    // b. insert all legacy enotes to the reference set
    for (const LegacyEnoteVariant &enote : output_enotes)
    {
        m_legacy_enote_references[total_legacy_output_count] = {onetime_address_ref(enote), amount_commitment_ref(enote)};

        ++total_legacy_output_count;
    }

    // c. add this block's accumulated output count
    m_accumulated_legacy_output_counts[new_height] = total_legacy_output_count;

    if (new_height >= m_first_seraphis_allowed_block)
        m_accumulated_sp_output_counts[new_height] = m_sp_squashed_enotes.size();

    // d. add this block's tx output contents
    m_blocks_of_legacy_tx_output_contents[new_height][tx_id] = {unlock_time, std::move(memo), std::move(output_enotes)};

    if (new_height >= m_first_seraphis_allowed_block)
        m_blocks_of_sp_tx_output_contents[new_height];

    // 3. add block info (random block ID and zero timestamp in mockup)
    m_block_infos[new_height] = {rct::pkGen(), 0};

    // 4. clear unconfirmed cache
    this->clear_unconfirmed_cache_impl();

    return new_height;
}
//-------------------------------------------------------------------------------------------------------------------
bool MockLedgerContext::try_add_unconfirmed_coinbase_v1_impl(const rct::key &coinbase_tx_id,
    const rct::key &input_context,
    SpTxSupplementV1 tx_supplement,
    std::vector<SpEnoteVariant> output_enotes)
{
    /// check failure modes

    // 1. fail if tx id is duplicated (bug since coinbase block height check should prevent this)
    CHECK_AND_ASSERT_THROW_MES(m_unconfirmed_tx_key_images.find(coinbase_tx_id) == m_unconfirmed_tx_key_images.end(),
        "mock tx ledger (adding unconfirmed coinbase tx): tx id already exists in key image map (bug).");
    CHECK_AND_ASSERT_THROW_MES(m_unconfirmed_tx_output_contents.find(coinbase_tx_id) ==
            m_unconfirmed_tx_output_contents.end(),
        "mock tx ledger (adding unconfirmed coinbase tx): tx id already exists in output contents map (bug).");


    /// update state

    // 1. add key images (there are none, but we want an entry in the map)
    m_unconfirmed_tx_key_images[coinbase_tx_id];

    // 2. add tx outputs
    m_unconfirmed_tx_output_contents[coinbase_tx_id] =
        {
            input_context,
            std::move(tx_supplement),
            std::move(output_enotes)
        };

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool MockLedgerContext::try_add_unconfirmed_tx_v1_impl(const SpTxSquashedV1 &tx)
{
    /// check failure modes

    // 1. fail if new tx overlaps with cached key images: unconfirmed, onchain
    std::vector<crypto::key_image> legacy_key_images_collected;
    std::vector<crypto::key_image> sp_key_images_collected;

    for (const LegacyEnoteImageV2 &legacy_enote_image : tx.m_legacy_input_images)
    {
        if (this->key_image_exists_unconfirmed_v1_impl(legacy_enote_image.m_key_image) ||
            this->key_image_exists_onchain_v1_impl(legacy_enote_image.m_key_image))
            return false;

        legacy_key_images_collected.emplace_back(legacy_enote_image.m_key_image);
    }

    for (const SpEnoteImageV1 &sp_enote_image : tx.m_sp_input_images)
    {
        if (this->key_image_exists_unconfirmed_v1_impl(sp_enote_image.m_core.m_key_image) ||
            this->key_image_exists_onchain_v1_impl(sp_enote_image.m_core.m_key_image))
            return false;

        sp_key_images_collected.emplace_back(sp_enote_image.m_core.m_key_image);
    }

    rct::key input_context;
    jamtis::make_jamtis_input_context_standard(legacy_key_images_collected, sp_key_images_collected, input_context);

    // 2. fail if tx id is duplicated (bug since key image check should prevent this)
    rct::key tx_id;
    tx.get_id(tx_id);

    CHECK_AND_ASSERT_THROW_MES(m_unconfirmed_tx_key_images.find(tx_id) == m_unconfirmed_tx_key_images.end(),
        "mock tx ledger (adding unconfirmed tx): tx id already exists in key image map (bug).");
    CHECK_AND_ASSERT_THROW_MES(m_unconfirmed_tx_output_contents.find(tx_id) == m_unconfirmed_tx_output_contents.end(),
        "mock tx ledger (adding unconfirmed tx): tx id already exists in output contents map (bug).");


    /// update state

    // 1. add key images
    for (const crypto::key_image &legacy_key_image : legacy_key_images_collected)
        m_unconfirmed_legacy_key_images.insert(legacy_key_image);

    for (const crypto::key_image &sp_key_image : sp_key_images_collected)
        m_unconfirmed_sp_key_images.insert(sp_key_image);

    m_unconfirmed_tx_key_images[tx_id] = {std::move(legacy_key_images_collected), std::move(sp_key_images_collected)};

    // 2. add tx outputs
    std::vector<SpEnoteVariant> output_enote_variants;
    output_enote_variants.reserve(tx.m_outputs.size());

    for (const SpEnoteV1 &enote : tx.m_outputs)
        output_enote_variants.emplace_back(enote);

    m_unconfirmed_tx_output_contents[tx_id] = {input_context, tx.m_tx_supplement, output_enote_variants};

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::commit_unconfirmed_txs_v1_impl(const SpTxCoinbaseV1 &coinbase_tx)
{
    /// checks
    CHECK_AND_ASSERT_THROW_MES(coinbase_tx.m_block_height == this->chain_height() + 1,
        "mock tx ledger (committing a coinbase tx): coinbase tx's block height does not match chain height.");


    /// commit a new block

    // 1. convert output enotes to type-erased enote variants
    std::vector<SpEnoteVariant> coinbase_output_enotes;
    coinbase_output_enotes.reserve(coinbase_tx.m_outputs.size());

    for (const SpCoinbaseEnoteV1 &coinbase_enote : coinbase_tx.m_outputs)
        coinbase_output_enotes.emplace_back(coinbase_enote);

    // 2. compute coinbase input context
    rct::key coinbase_input_context;
    jamtis::make_jamtis_input_context_coinbase(coinbase_tx.m_block_height, coinbase_input_context);

    // 3. coinbase tx id
    rct::key tx_id;
    coinbase_tx.get_id(tx_id);

    // 3. punt to mock commit function
    return this->commit_unconfirmed_txs_v1_impl(tx_id,
        coinbase_input_context,
        coinbase_tx.m_tx_supplement,
        std::move(coinbase_output_enotes));
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::commit_unconfirmed_txs_v1_impl(const rct::key &coinbase_tx_id,
    const rct::key &mock_coinbase_input_context,
    SpTxSupplementV1 mock_coinbase_tx_supplement,
    std::vector<SpEnoteVariant> mock_coinbase_output_enotes)
{
    /// sanity checks: check unconfirmed key images and txids
    for (const auto &tx_key_images : m_unconfirmed_tx_key_images)
    {
        // a. tx ids are present in both unconfirmed data maps
        CHECK_AND_ASSERT_THROW_MES(m_unconfirmed_tx_output_contents.find(tx_key_images.first) !=
                m_unconfirmed_tx_output_contents.end(),
            "mock tx ledger (committing unconfirmed txs): tx id not in all unconfirmed data maps (bug).");

        // b. tx ids are not present onchain
        for (const auto &block_tx_key_images : m_blocks_of_tx_key_images)
        {
            CHECK_AND_ASSERT_THROW_MES(block_tx_key_images.second.find(tx_key_images.first) ==
                    block_tx_key_images.second.end(),
                "mock tx ledger (committing unconfirmed txs): unconfirmed tx id found in ledger (bug).");
        }

        for (const auto &block_tx_outputs : m_blocks_of_sp_tx_output_contents)
        {
            CHECK_AND_ASSERT_THROW_MES(block_tx_outputs.second.find(tx_key_images.first) == block_tx_outputs.second.end(),
                "mock tx ledger (committing unconfirmed txs): unconfirmed tx id found in ledger (bug).");
        }

        // c. legacy key images are not present onchain
        for (const crypto::key_image &key_image : std::get<0>(tx_key_images.second))
        {
            CHECK_AND_ASSERT_THROW_MES(!this->key_image_exists_onchain_v1_impl(key_image),
                "mock tx ledger (committing unconfirmed txs): unconfirmed tx key image exists in ledger (bug).");
        }

        // d. Seraphis key images are not present onchain
        for (const crypto::key_image &key_image : std::get<1>(tx_key_images.second))
        {
            CHECK_AND_ASSERT_THROW_MES(!this->key_image_exists_onchain_v1_impl(key_image),
                "mock tx ledger (committing unconfirmed txs): unconfirmed tx key image exists in ledger (bug).");
        }
    }

    // d. unconfirmed maps line up
    CHECK_AND_ASSERT_THROW_MES(m_unconfirmed_tx_key_images.size() == m_unconfirmed_tx_output_contents.size(),
        "mock tx ledger (committing unconfirmed txs): unconfirmed data maps mismatch (bug).");

    // e. accumulated output count is consistent
    const std::uint64_t accumulated_output_count =
        m_accumulated_sp_output_counts.size()
        ? (m_accumulated_sp_output_counts.rbegin())->second  //last block's accumulated output count
        : 0;

    CHECK_AND_ASSERT_THROW_MES(accumulated_output_count == m_sp_squashed_enotes.size(),
        "mock tx ledger (committing unconfirmed txs): inconsistent number of accumulated outputs (bug).");

    // f. can only add blocks with seraphis txs at first seraphis-enabled block
    CHECK_AND_ASSERT_THROW_MES(this->chain_height() + 1 >= m_first_seraphis_allowed_block,
        "mock tx ledger (committing unconfirmed txs): cannot make seraphis block because block height is too low.");


    /// add mock coinbase tx to unconfirmed cache
    // note: this should not invalidate the result of any of the prior checks
    CHECK_AND_ASSERT_THROW_MES(this->try_add_unconfirmed_coinbase_v1_impl(coinbase_tx_id,
            mock_coinbase_input_context,
            std::move(mock_coinbase_tx_supplement),
            std::move(mock_coinbase_output_enotes)),
        "mock tx ledger (committing unconfirmed txs): unable to add mock coinbase tx to unconfirmed cache (bug).");


    /// update state
    const std::uint64_t new_height{this->chain_height() + 1};

    // 1. add key images
    m_legacy_key_images.insert(m_unconfirmed_legacy_key_images.begin(), m_unconfirmed_legacy_key_images.end());
    m_sp_key_images.insert(m_unconfirmed_sp_key_images.begin(), m_unconfirmed_sp_key_images.end());
    m_blocks_of_tx_key_images[new_height] = std::move(m_unconfirmed_tx_key_images);

    // 2. add tx outputs

    // a. initialize with current total output count
    std::uint64_t total_sp_output_count{m_sp_squashed_enotes.size()};

    // b. insert all squashed enotes to the reference set
    for (const auto &tx_info : m_unconfirmed_tx_output_contents)
    {
        const auto &tx_enotes = std::get<std::vector<SpEnoteVariant>>(tx_info.second);
        for (const SpEnoteVariant &enote : tx_enotes)
        {
            make_seraphis_squashed_enote_Q(onetime_address_ref(enote),
                amount_commitment_ref(enote),
                m_sp_squashed_enotes[total_sp_output_count]);

            ++total_sp_output_count;
        }
    }

    // c. add this block's accumulated output count
    m_accumulated_sp_output_counts[new_height] = total_sp_output_count;

    if (new_height < m_first_seraphis_only_block)
        m_accumulated_legacy_output_counts[new_height] = m_legacy_enote_references.size();

    // d. steal the unconfirmed cache's tx output contents
    m_blocks_of_sp_tx_output_contents[new_height] = std::move(m_unconfirmed_tx_output_contents);

    if (new_height < m_first_seraphis_only_block)
        m_blocks_of_legacy_tx_output_contents[new_height];

    // 3. add block info (random block ID and zero timestamp in mockup)
    m_block_infos[new_height] = {rct::pkGen(), 0};

    // 4. clear unconfirmed chache
    this->clear_unconfirmed_cache_impl();

    return new_height;
}
//-------------------------------------------------------------------------------------------------------------------
void MockLedgerContext::remove_tx_from_unconfirmed_cache_impl(const rct::key &tx_id)
{
    // clear key images
    if (m_unconfirmed_tx_key_images.find(tx_id) != m_unconfirmed_tx_key_images.end())
    {
        for (const crypto::key_image &key_image : std::get<0>(m_unconfirmed_tx_key_images[tx_id]))
            m_unconfirmed_legacy_key_images.erase(key_image);
        for (const crypto::key_image &key_image : std::get<1>(m_unconfirmed_tx_key_images[tx_id]))
            m_unconfirmed_sp_key_images.erase(key_image);

        m_unconfirmed_tx_key_images.erase(tx_id);
    }

    // clear output contents
    m_unconfirmed_tx_output_contents.erase(tx_id);
}
//-------------------------------------------------------------------------------------------------------------------
void MockLedgerContext::clear_unconfirmed_cache_impl()
{
    m_unconfirmed_legacy_key_images.clear();
    m_unconfirmed_sp_key_images.clear();
    m_unconfirmed_tx_key_images.clear();
    m_unconfirmed_tx_output_contents.clear();
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::pop_chain_at_height_impl(const std::uint64_t pop_height)
{
    if (pop_height > this->chain_height())
        return 0;

    const std::uint64_t num_blocks_to_pop{this->chain_height() - pop_height + 1};

    // 1. remove key images
    for (std::uint64_t height_to_pop{pop_height}; height_to_pop < pop_height + num_blocks_to_pop; ++height_to_pop)
    {
        if (m_blocks_of_tx_key_images.find(height_to_pop) != m_blocks_of_tx_key_images.end())
        {
            for (const auto &tx_key_images : m_blocks_of_tx_key_images[height_to_pop])
            {
                for (const crypto::key_image &key_image : std::get<0>(tx_key_images.second))
                    m_legacy_key_images.erase(key_image);
                for (const crypto::key_image &key_image : std::get<1>(tx_key_images.second))
                    m_sp_key_images.erase(key_image);
            }
        }
    }

    // 2. remove legacy enote references
    if (m_accumulated_legacy_output_counts.size() > 0)
    {
        // sanity check
        if (pop_height > 0)
        {
            CHECK_AND_ASSERT_THROW_MES(m_accumulated_legacy_output_counts.find(pop_height - 1) !=
                    m_accumulated_legacy_output_counts.end(),
                "mock ledger context (popping chain): accumulated legacy output counts has a hole (bug).");
        }

        // remove all outputs starting in the pop_height block
        const std::uint64_t first_output_to_remove =
            pop_height > 0
            ? m_accumulated_legacy_output_counts[pop_height - 1]
            : 0;

        m_legacy_enote_references.erase(m_legacy_enote_references.find(first_output_to_remove),
            m_legacy_enote_references.end());
    }

    // 3. remove squashed enotes
    if (m_accumulated_sp_output_counts.size() > 0)
    {
        // sanity check
        if (pop_height > m_first_seraphis_allowed_block)
        {
            CHECK_AND_ASSERT_THROW_MES(m_accumulated_sp_output_counts.find(pop_height - 1) !=
                    m_accumulated_sp_output_counts.end(),
                "mock ledger context (popping chain): accumulated seraphis output counts has a hole (bug).");
        }

        // remove all outputs starting in the pop_height block
        const std::uint64_t first_output_to_remove =
            pop_height > m_first_seraphis_allowed_block
            ? m_accumulated_sp_output_counts[pop_height - 1]
            : 0;

        m_sp_squashed_enotes.erase(m_sp_squashed_enotes.find(first_output_to_remove), m_sp_squashed_enotes.end());
    }

    // 4. clean up block maps
    erase_ledger_cache_map_from_height(pop_height, m_blocks_of_tx_key_images);
    erase_ledger_cache_map_from_height(pop_height, m_accumulated_legacy_output_counts);
    erase_ledger_cache_map_from_height(pop_height, m_accumulated_sp_output_counts);
    erase_ledger_cache_map_from_height(pop_height, m_blocks_of_legacy_tx_output_contents);
    erase_ledger_cache_map_from_height(pop_height, m_blocks_of_sp_tx_output_contents);
    erase_ledger_cache_map_from_height(pop_height, m_block_infos);

    return num_blocks_to_pop;
}
//-------------------------------------------------------------------------------------------------------------------
std::uint64_t MockLedgerContext::pop_blocks_impl(const std::size_t num_blocks)
{
    const std::uint64_t chain_height{this->chain_height()};
    return pop_chain_at_height_impl(chain_height + 1 >= num_blocks ? chain_height + 1 - num_blocks : 0);
}
//-------------------------------------------------------------------------------------------------------------------
// free functions
//-------------------------------------------------------------------------------------------------------------------
bool try_add_tx_to_ledger(const SpTxCoinbaseV1 &tx_to_add, MockLedgerContext &ledger_context_inout)
{
    return false;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_add_tx_to_ledger(const SpTxSquashedV1 &tx_to_add, MockLedgerContext &ledger_context_inout)
{
    if (!ledger_context_inout.try_add_unconfirmed_tx_v1(tx_to_add))
        return false;

    ledger_context_inout.commit_unconfirmed_txs_v1(rct::pkGen(), SpTxSupplementV1{}, std::vector<SpEnoteVariant>{});

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp

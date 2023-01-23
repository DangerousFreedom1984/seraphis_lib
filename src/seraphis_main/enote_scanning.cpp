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
#include "enote_scanning.h"

//local headers
#include "contextual_enote_record_types.h"
#include "enote_finding_context.h"
#include "enote_scanning_context.h"
#include "enote_store_updater.h"
#include "ringct/rctTypes.h"

//third party headers
#include <boost/optional/optional.hpp>

//standard headers
#include <iterator>
#include <list>
#include <unordered_map>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{

////
// EnoteScanProcessLedger
// - raii wrapper on an EnoteScanningContextLedger for a specific scanning process: begin ... terminate
///
class EnoteScanProcessLedger final
{
public:
//constructors
    /// normal constructor
    EnoteScanProcessLedger(const std::uint64_t initial_start_height,
        const std::uint64_t max_chunk_size,
        EnoteScanningContextLedger &enote_scan_context) :
            m_enote_scan_context{enote_scan_context}
    {
        m_enote_scan_context.begin_scanning_from_height(initial_start_height, max_chunk_size);
    }

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    EnoteScanProcessLedger& operator=(EnoteScanProcessLedger&&) = delete;

//destructor
    ~EnoteScanProcessLedger()
    {
        try { m_enote_scan_context.terminate_scanning(); }
        catch (...) { LOG_ERROR("seraphis enote scan process ledger (destructor): scan context termination failed."); }
    }

//member functions
    /// get the next available onchain chunk (must be contiguous with the last chunk acquired since starting to scan)
    /// note: when no more chunks to get, obtain an empty chunk representing the top of the current chain
    void get_onchain_chunk(EnoteScanningChunkLedgerV1 &chunk_out)
    {
        m_enote_scan_context.get_onchain_chunk(chunk_out);
    }
    /// try to get a scanning chunk for the unconfirmed txs that are pending inclusion in a ledger
    void get_unconfirmed_chunk(EnoteScanningChunkNonLedgerV1 &chunk_out)
    {
        m_enote_scan_context.get_unconfirmed_chunk(chunk_out);
    }

//member variables
private:
    /// reference to an enote scanning context
    EnoteScanningContextLedger &m_enote_scan_context;
};

////
// ScanStatus
// - helper enum for reporting the outcome of a scan process
///
enum class ScanStatus
{
    NEED_FULLSCAN,
    NEED_PARTIALSCAN,
    SUCCESS,
    FAIL
};

////
// ChainContiguityMarker
// - marks the end of a contiguous chain of blocks
// - if the contiguous chain is empty, then the block id will be unspecified and the block height will equal the 
//   initial height minus one
// - a 'contiguous chain' does not have to start at 'block 0', it can start at any predefined block height where you
//   want to start tracking contiguity
// - example: if your refresh height is 'block 101' and you haven't loaded/scanned any blocks, then your initial
//   contiguity marker will start at 'block 100' with an unspecified block id; if you scanned blocks [101, 120], then
//   your contiguity marker will be at block 120 with that block's block id
///
struct ChainContiguityMarker final
{
    /// height of the block
    std::uint64_t m_block_height;
    /// id of the block (optional)
    boost::optional<rct::key> m_block_id;
};

//-------------------------------------------------------------------------------------------------------------------
// - this is the number of extra blocks to scan below our desired start height in case there was a reorg lower
//   than that start height
// - we use an exponential back-off as a function of fullscan attempts because if a fullscan fails then
//   the true location of alignment divergence is unknown; moreover, the distance between the desired
//   start height and the enote store's refresh height may be very large; if a fixed back-off were
//   used, then it could take many fullscan attempts to find the point of divergence
//-------------------------------------------------------------------------------------------------------------------
static std::uint64_t get_reorg_avoidance_depth(const std::uint64_t default_reorg_avoidance_depth,
    const std::uint64_t completed_fullscan_attempts)
{
    // 1. start at the default depth for the first and second fullscan attempts
    // - back off the default depth twice to better support unit tests that study partial rescans
    if (completed_fullscan_attempts <= 1)
        return default_reorg_avoidance_depth;

    // 2. check that the default depth is not 0
    CHECK_AND_ASSERT_THROW_MES(default_reorg_avoidance_depth > 0,
        "refresh ledger for enote store: tried more than one fullscan with zero reorg avoidance depth.");

    // 3. 10 ^ (fullscan attempts) * default depth
    return static_cast<uint64_t>(std::pow(10, completed_fullscan_attempts - 1) * default_reorg_avoidance_depth);    
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void set_initial_contiguity_marker(const EnoteStoreUpdater &enote_store_updater,
    const std::uint64_t initial_refresh_height,
    ChainContiguityMarker &contiguity_marker_inout)
{
    // 1. set the block height
    contiguity_marker_inout.m_block_height = initial_refresh_height - 1;

    // 2. set the block id if we aren't at the unpdater's prefix block
    if (contiguity_marker_inout.m_block_height != enote_store_updater.refresh_height() - 1)
    {
        // getting a block id should always succeed if we are starting past the prefix block of the updater
        contiguity_marker_inout.m_block_id = rct::zero();
        CHECK_AND_ASSERT_THROW_MES(enote_store_updater.try_get_block_id(initial_refresh_height - 1,
                *(contiguity_marker_inout.m_block_id)),
            "refresh ledger for enote store: could not get block id for start of scanning but a block id was "
            "expected (bug).");
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void check_enote_scan_chunk_map_semantics_v1(
    const std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> &chunk_basic_records_per_tx,
    const std::list<SpContextualKeyImageSetV1> &chunk_contextual_key_images,
    const SpEnoteOriginStatus expected_origin_status,
    const SpEnoteSpentStatus expected_spent_status)
{
    // 1. check contextual basic records
    for (const auto &tx_basic_records : chunk_basic_records_per_tx)
    {
        for (const ContextualBasicRecordVariant &contextual_basic_record : tx_basic_records.second)
        {
            CHECK_AND_ASSERT_THROW_MES(origin_context_ref(contextual_basic_record).m_origin_status ==
                    expected_origin_status,
                "enote chunk semantics check: contextual basic record doesn't have expected origin status.");
            CHECK_AND_ASSERT_THROW_MES(origin_context_ref(contextual_basic_record).m_transaction_id ==
                    tx_basic_records.first,
                "enote chunk semantics check: contextual basic record doesn't have origin tx id matching mapped id.");
        }
    }

    // 2. check contextual key images
    for (const auto &contextual_key_image_set : chunk_contextual_key_images)
    {
        CHECK_AND_ASSERT_THROW_MES(contextual_key_image_set.m_spent_context.m_spent_status == expected_spent_status,
            "enote chunk semantics check: contextual key image doesn't have expected spent status.");

        // notes:
        // - in seraphis tx building, tx authors must always put a selfsend output enote in their txs; during balance
        //   recovery, the view tag check will pass for those selfsend enotes; this means to identify if your enotes are
        //   spent, you only need to look at key images in txs with view tag matches
        // - in support of that expectation, we enforce that the key images in a scanning chunk must come from txs
        //   recorded in the 'basic records per tx' map, which will contain only owned enote candidates (in seraphis
        //   scanning, that's all the enotes that passed the view tag check)
        // - if you want to include key images from txs that have no owned enote candidates, then you must add empty
        //   entries to the 'basic records per tx' map for those txs
        //   - when doing legacy scanning, you need to include all key images from the chain since legacy tx construction
        //     does/did not require all txs to have a self-send output
        CHECK_AND_ASSERT_THROW_MES(
                chunk_basic_records_per_tx.find(contextual_key_image_set.m_spent_context.m_transaction_id) !=
                chunk_basic_records_per_tx.end(),
            "enote chunk semantics check: contextual key image transaction id is not mirrored in basic records map.");
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool chunk_is_empty(const EnoteScanningChunkLedgerV1 &chunk)
{
    return chunk.m_start_height >= chunk.m_end_height;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool contiguity_check(const ChainContiguityMarker &marker_A, const ChainContiguityMarker &marker_B)
{
    // 1. a marker with unspecified block id is contiguous with all markers below and equal to its height (but not
    //    contiguous with markers above them)
    // note: this odd rule exists so that if the chain height is below our start height, we will be considered
    //       contiguous with it and won't erroneously think we have encountered a reorg (i.e. a broken contiguity);
    //       to explore that situation, change the '<=' to '==' then step through the unit tests that break
    if (!marker_A.m_block_id &&
        marker_B.m_block_height + 1 <= marker_A.m_block_height + 1)
        return true;

    if (!marker_B.m_block_id &&
        marker_A.m_block_height + 1 <= marker_B.m_block_height + 1)
        return true;

    // 2. otherwise, heights must match
    if (marker_A.m_block_height != marker_B.m_block_height)
        return false;

    // 3. specified block ids must match
    if (marker_A.m_block_id &&
        marker_B.m_block_id &&
        marker_A.m_block_id != marker_B.m_block_id)
        return false;

    // 4. unspecified block ids automatically match with specified and unspecified block ids
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static ScanStatus get_scan_status(const ChainContiguityMarker &contiguity_marker,
    const EnoteScanningChunkLedgerV1 &chunk,
    const std::uint64_t first_contiguity_height,
    const std::uint64_t full_discontinuity_test_height)
{
    // 1. success case: check if this chunk is contiguous with our marker
    if (contiguity_check(contiguity_marker, ChainContiguityMarker{chunk.m_start_height - 1, chunk.m_prefix_block_id}))
        return ScanStatus::SUCCESS;

    // 2. failure case: the chunk is not contiguous, check if we need to full scan
    // - there was a reorg that affects our first expected point of contiguity (i.e. we obtained no new chunks that were
    //   contiguous with our existing known contiguous chain)
    // note: +1 in case either height is '-1'
    if (first_contiguity_height + 1 >= full_discontinuity_test_height + 1)
        return ScanStatus::NEED_FULLSCAN;

    // 3. failure case: the chunk is not contiguous, but we don't need a full scan
    // - there was a reorg detected but there is new chunk data that wasn't affected
    return ScanStatus::NEED_PARTIALSCAN;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void update_alignment_marker(const EnoteStoreUpdater &enote_store_updater,
    const std::uint64_t start_height,
    const std::vector<rct::key> &block_ids,
    ChainContiguityMarker &alignment_marker_inout)
{
    // trace through the block ids to find the heighest one that matches with the enote store's recorded block ids
    rct::key next_block_id;
    for (std::size_t block_index{0}; block_index < block_ids.size(); ++block_index)
    {
        if (!enote_store_updater.try_get_block_id(start_height + block_index, next_block_id))
            return;

        if (!(next_block_id == block_ids[block_index]))
            return;

        alignment_marker_inout.m_block_height = start_height + block_index;
        alignment_marker_inout.m_block_id     = next_block_id;
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void align_block_ids(const EnoteStoreUpdater &enote_store_updater,
    const EnoteScanningChunkLedgerV1 &chunk,
    ChainContiguityMarker &alignment_marker_inout,
    std::vector<rct::key> &scanned_block_ids_cropped_inout)
{
    // 1. update the alignment marker
    update_alignment_marker(enote_store_updater, chunk.m_start_height, chunk.m_block_ids, alignment_marker_inout);

    // 2. sanity checks
    CHECK_AND_ASSERT_THROW_MES(alignment_marker_inout.m_block_height + 1 >= chunk.m_start_height,
        "enote scanning (align block ids): chunk start height exceeds the post-alignment block (bug).");
    CHECK_AND_ASSERT_THROW_MES(alignment_marker_inout.m_block_height + 1 - chunk.m_start_height <=
            chunk.m_block_ids.size(),
        "enote scanning (align block ids): the alignment range is larger than the chunk's block range (bug).");

    // 3. crop the chunk block ids
    scanned_block_ids_cropped_inout.clear();
    scanned_block_ids_cropped_inout.insert(scanned_block_ids_cropped_inout.end(),
        std::next(chunk.m_block_ids.begin(), alignment_marker_inout.m_block_height + 1 - chunk.m_start_height),
        chunk.m_block_ids.end());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static ScanStatus process_ledger_for_full_refresh_onchain_pass(const std::uint64_t first_contiguity_height,
    EnoteScanProcessLedger &scan_process_inout,
    EnoteStoreUpdater &enote_store_updater_inout,
    ChainContiguityMarker &contiguity_marker_inout)
{
    // 1. get new chunks until we encounter an empty chunk (or detect a reorg)
    EnoteScanningChunkLedgerV1 new_onchain_chunk;
    scan_process_inout.get_onchain_chunk(new_onchain_chunk);
    std::vector<rct::key> scanned_block_ids_cropped;

    while (!chunk_is_empty(new_onchain_chunk))
    {
        // a. set alignment marker for before the chunk has been processed (assume we always start aligned)
        // - alignment means a chunk's block id matches the enote store's block id at the alignment block height
        ChainContiguityMarker alignment_marker{contiguity_marker_inout};

        // b. validate chunk semantics (this should check all array bounds to prevent out-of-range accesses below)
        check_v1_enote_scan_chunk_ledger_semantics_v1(new_onchain_chunk, contiguity_marker_inout.m_block_height);

        // c. check if this chunk is contiguous with the contiguity marker
        // - if not contiguous, then there must have been a reorg, so we need to rescan
        const ScanStatus scan_status{
                get_scan_status(contiguity_marker_inout,
                    new_onchain_chunk,
                    first_contiguity_height,
                    contiguity_marker_inout.m_block_height)
            };

        if (scan_status != ScanStatus::SUCCESS)
            return scan_status;

        // d. align the chunk's block ids with the enote store
        // - update the point of alignment if this chunk overlaps with blocks known by the enote store
        // - crop the chunk's block ids to only include block ids unknown to the enote store
        align_block_ids(enote_store_updater_inout, new_onchain_chunk, alignment_marker, scanned_block_ids_cropped);

        // e. consume the chunk if it's not empty
        // - if the chunk is empty after aligning, that means our enote store already knows about the entire span
        //   of the chunk; we don't want to pass the chunk in, because there may be blocks in the NEXT chunk that
        //   our enote store also knows about; we don't want the enote store to think it needs to roll back its state
        //   to the top of this chunk
        if (scanned_block_ids_cropped.size() > 0)
        {
            enote_store_updater_inout.consume_onchain_chunk(new_onchain_chunk.m_basic_records_per_tx,
                new_onchain_chunk.m_contextual_key_images,
                alignment_marker.m_block_height + 1,
                alignment_marker.m_block_id ? *(alignment_marker.m_block_id) : rct::zero(),
                scanned_block_ids_cropped);
        }

        // f. set contiguity marker to last block of this chunk
        contiguity_marker_inout.m_block_height = new_onchain_chunk.m_end_height - 1;
        contiguity_marker_inout.m_block_id     = new_onchain_chunk.m_block_ids.back();

        // g. get next chunk
        scan_process_inout.get_onchain_chunk(new_onchain_chunk);
    }

    // 2. verify that the last chunk obtained is an empty chunk representing the top of the current blockchain
    CHECK_AND_ASSERT_THROW_MES(new_onchain_chunk.m_block_ids.size() == 0,
        "process ledger for onchain pass: final chunk does not have zero block ids as expected.");

    // 3. verify that our termination chunk is contiguous with the chunks received so far
    // - this can fail if a reorg dropped below our contiguity marker without replacing the dropped blocks, so the first
    //   chunk obtained after the reorg is this empty termination chunk
    // note: this test won't fail if the chain height is below our contiguity marker when our contiguity marker has
    //       an unspecified block id; we don't care if the chain height is lower than our scanning 'backstop' (i.e.
    //       lowest point in our enote store) when we haven't actually scanned any blocks
    const ScanStatus scan_status{
            get_scan_status(contiguity_marker_inout,
                new_onchain_chunk,
                first_contiguity_height,
                new_onchain_chunk.m_end_height - 1)
        };

    if (scan_status != ScanStatus::SUCCESS)
        return scan_status;

    // 4. final update for our enote store
    // - we need to update with the termination chunk in case a reorg popped blocks, so the enote store can roll back
    //   its state
    enote_store_updater_inout.consume_onchain_chunk({},
        {},
        contiguity_marker_inout.m_block_height + 1,
        contiguity_marker_inout.m_block_id ? *(contiguity_marker_inout.m_block_id) : rct::zero(),
        {});

    return ScanStatus::SUCCESS;
}
//-------------------------------------------------------------------------------------------------------------------
// IMPORTANT: chunk processing can't be parallelized since key image checks are sequential/cumulative
// - 'scanning_context_inout' can internally collect chunks in parallel
//-------------------------------------------------------------------------------------------------------------------
static ScanStatus process_ledger_for_full_refresh(const std::uint64_t max_chunk_size,
    ChainContiguityMarker contiguity_marker,
    EnoteScanningContextLedger &scanning_context_inout,
    EnoteStoreUpdater &enote_store_updater_inout)
{
    // 1. save the initial height of our existing known contiguous chain
    const std::uint64_t first_contiguity_height{contiguity_marker.m_block_height};

    // 2. create the scan process (initiates the scan process on construction)
    EnoteScanProcessLedger scan_process{first_contiguity_height + 1, max_chunk_size, scanning_context_inout};

    // 3. on-chain initial scanning pass
    const ScanStatus scan_status_first_onchain_pass{
        process_ledger_for_full_refresh_onchain_pass(first_contiguity_height,
            scan_process,
            enote_store_updater_inout,
            contiguity_marker)
        };

    // 4. early return if the initial onchain pass didn't succeed
    if (scan_status_first_onchain_pass != ScanStatus::SUCCESS)
        return scan_status_first_onchain_pass;

    // 5. unconfirmed scanning pass
    EnoteScanningChunkNonLedgerV1 unconfirmed_chunk;
    scan_process.get_unconfirmed_chunk(unconfirmed_chunk);
    enote_store_updater_inout.consume_nonledger_chunk(SpEnoteOriginStatus::UNCONFIRMED,
        unconfirmed_chunk.m_basic_records_per_tx,
        unconfirmed_chunk.m_contextual_key_images);

    // 6. on-chain follow-up pass
    // rationale:
    // - blocks may have been added between the initial on-chain pass and the unconfirmed pass, and those blocks may
    //   contain txs not seen by the unconfirmed pass (i.e. sneaky txs)
    // - we want scan results to be chronologically contiguous (it is better for the unconfirmed scan results to be stale
    //   than the on-chain scan results)
    return process_ledger_for_full_refresh_onchain_pass(first_contiguity_height,
        scan_process,
        enote_store_updater_inout,
        contiguity_marker);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void check_v1_enote_scan_chunk_ledger_semantics_v1(const EnoteScanningChunkLedgerV1 &onchain_chunk,
    const std::uint64_t expected_prefix_height)
{
    // 1. misc. checks
    CHECK_AND_ASSERT_THROW_MES(onchain_chunk.m_start_height - 1 == expected_prefix_height,
        "enote scan chunk semantics check (ledger): chunk range doesn't start at expected prefix height.");

    const std::uint64_t num_blocks_in_chunk{onchain_chunk.m_end_height - onchain_chunk.m_start_height};
    CHECK_AND_ASSERT_THROW_MES(num_blocks_in_chunk >= 1,
        "enote scan chunk semantics check (ledger): chunk has no blocks.");    
    CHECK_AND_ASSERT_THROW_MES(onchain_chunk.m_block_ids.size() == num_blocks_in_chunk,
        "enote scan chunk semantics check (ledger): unexpected number of block ids.");

    check_enote_scan_chunk_map_semantics_v1(onchain_chunk.m_basic_records_per_tx,
        onchain_chunk.m_contextual_key_images,
        SpEnoteOriginStatus::ONCHAIN,
        SpEnoteSpentStatus::SPENT_ONCHAIN);

    // 2. get start and end blocks
    // - start block = prefix block + 1
    const std::uint64_t allowed_lowest_height{onchain_chunk.m_start_height};
    // - end block
    const std::uint64_t allowed_heighest_height{onchain_chunk.m_end_height - 1};

    // 3. contextual basic records: height checks
    for (const auto &tx_basic_records : onchain_chunk.m_basic_records_per_tx)
    {
        for (const ContextualBasicRecordVariant &contextual_basic_record : tx_basic_records.second)
        {
            CHECK_AND_ASSERT_THROW_MES(origin_context_ref(contextual_basic_record).m_block_height ==
                    origin_context_ref(*tx_basic_records.second.begin()).m_block_height,
                "enote chunk semantics check (ledger): contextual record tx height doesn't match other records in tx.");

            CHECK_AND_ASSERT_THROW_MES(
                    origin_context_ref(contextual_basic_record).m_block_height >= allowed_lowest_height &&
                    origin_context_ref(contextual_basic_record).m_block_height <= allowed_heighest_height,
                "enote chunk semantics check (ledger): contextual record block height is out of the expected range.");
        }
    }

    // 4. contextual key images: height checks
    for (const SpContextualKeyImageSetV1 &contextual_key_image_set : onchain_chunk.m_contextual_key_images)
    {
        CHECK_AND_ASSERT_THROW_MES(
                contextual_key_image_set.m_spent_context.m_block_height >= allowed_lowest_height &&
                contextual_key_image_set.m_spent_context.m_block_height <= allowed_heighest_height,
            "enote chunk semantics check (ledger): contextual key image block height is out of the expected range.");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_enote_scan_chunk_nonledger_semantics_v1(const EnoteScanningChunkNonLedgerV1 &nonledger_chunk,
    const SpEnoteOriginStatus expected_origin_status,
    const SpEnoteSpentStatus expected_spent_status)
{
    check_enote_scan_chunk_map_semantics_v1(nonledger_chunk.m_basic_records_per_tx,
        nonledger_chunk.m_contextual_key_images,
        expected_origin_status,
        expected_spent_status);
}
//-------------------------------------------------------------------------------------------------------------------
void refresh_enote_store_ledger(const RefreshLedgerEnoteStoreConfig &config,
    EnoteScanningContextLedger &scanning_context_inout,
    EnoteStoreUpdater &enote_store_updater_inout)
{
    // make scan attempts until succeeding or throwing an error
    ScanStatus scan_status{ScanStatus::NEED_FULLSCAN};
    std::size_t partialscan_attempts{0};
    std::size_t fullscan_attempts{0};

    while (scan_status == ScanStatus::NEED_PARTIALSCAN ||
        scan_status == ScanStatus::NEED_FULLSCAN)
    {
        // 1. get the block height of the first block the enote store updater wants to have scanned (e.g. the first block
        //    after the last block that was scanned)
        const std::uint64_t desired_first_block{enote_store_updater_inout.desired_first_block()};

        // 2. set reorg avoidance depth
        // - this is the number of extra blocks to scan below our desired start height in case there was a reorg lower
        //   than our initial contiguity marker before this scan attempt
        // note: we use an exponential back-off as a function of fullscan attempts because if a fullscan fails then
        //       the true location of alignment divergence is unknown; moreover, the distance between the first
        //       desired start height and the enote store's refresh height may be very large; if a fixed back-off were
        //       used, then it could take many fullscan attempts to find the point of divergence
        const std::uint64_t reorg_avoidance_depth{
                get_reorg_avoidance_depth(config.m_reorg_avoidance_depth, fullscan_attempts)
            };

        // 3. initial block to scan = max(desired first block - reorg depth, enote store's min scan height)
        std::uint64_t initial_refresh_height;

        if (desired_first_block >= reorg_avoidance_depth + enote_store_updater_inout.refresh_height())
            initial_refresh_height = desired_first_block - reorg_avoidance_depth;
        else
            initial_refresh_height = enote_store_updater_inout.refresh_height();

        // 4. set initial contiguity marker
        // - this starts as the prefix of the first block to scan, and should either be known to the enote store
        //   updater or have an unspecified block id
        ChainContiguityMarker contiguity_marker;
        set_initial_contiguity_marker(enote_store_updater_inout, initial_refresh_height, contiguity_marker);

        // 5. record the scan attempt
        if (scan_status == ScanStatus::NEED_PARTIALSCAN)
            ++partialscan_attempts;
        else if (scan_status == ScanStatus::NEED_FULLSCAN)
            ++fullscan_attempts;

        CHECK_AND_ASSERT_THROW_MES(fullscan_attempts < 50,
            "refresh ledger for enote store: fullscan attempts exceeded 50 (sanity check fail).");

        // 6. fail if we have exceeded the max number of partial scanning attempts (i.e. too many reorgs were detected,
        //    so now we abort)
        if (partialscan_attempts > config.m_max_partialscan_attempts)
        {
            scan_status = ScanStatus::FAIL;
            break;
        }

        // 7. process the ledger
        scan_status = process_ledger_for_full_refresh(config.m_max_chunk_size,
            contiguity_marker,
            scanning_context_inout,
            enote_store_updater_inout);
    }

    CHECK_AND_ASSERT_THROW_MES(scan_status == ScanStatus::SUCCESS, "refresh ledger for enote store: refreshing failed!");
}
//-------------------------------------------------------------------------------------------------------------------
void refresh_enote_store_offchain(const EnoteFindingContextOffchain &enote_finding_context,
    EnoteStoreUpdater &enote_store_updater_inout)
{
    // 1. get an offchain scan chunk
    EnoteScanningChunkNonLedgerV1 offchain_chunk;
    enote_finding_context.get_offchain_chunk(offchain_chunk);

    // 2. validate chunk semantics (ensure consistent vector sizes, block heights in contexts are within range)
    check_v1_enote_scan_chunk_nonledger_semantics_v1(offchain_chunk,
        SpEnoteOriginStatus::OFFCHAIN,
        SpEnoteSpentStatus::SPENT_OFFCHAIN);

    // 3. consume the chunk
    enote_store_updater_inout.consume_nonledger_chunk(SpEnoteOriginStatus::OFFCHAIN,
        offchain_chunk.m_basic_records_per_tx,
        offchain_chunk.m_contextual_key_images);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp

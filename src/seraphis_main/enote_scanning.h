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

// Interface for robust balance recovery framework (works for both legacy and seraphis backends).
// PRECONDITIONS:
// 1. chunks must be built from an atomic view of the source cache (ledger, unconfirmed cache, offchain cache)
// 2. per chunk: m_contextual_key_images must reference a tx recorded in m_basic_records_per_tx (even if you
//    need to add empty map entries to achieve that)
// 3. any call to get a chunk from an enote scanning context should produce a chunk that is at least as fresh as any
//    other chunk obtained from that context (atomic ordering)
// 4. any call to consume a chunk in an enote store updater should resolve all side-effects observable via the updater
//    interface by the time the call is complete (e.g. any changes to block ids observable by try_get_block_id() need
//    to be completed during the 'consume chunk' call)

#pragma once

//local headers
#include "contextual_enote_record_types.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <list>
#include <unordered_map>
#include <vector>

//forward declarations
namespace sp
{
    class EnoteFindingContextOffchain;
    class EnoteScanningContextLedger;
    class EnoteStoreUpdater;
}

namespace sp
{

////
// EnoteScanningChunkLedgerV1
// - chunk range (in block heights): [start height, end height)
// - prefix block id: id of block that comes before the chunk range, used for contiguity checks between chunks and with
//   the enote store updater
// - contextual basic enote records for owned enote candidates in the chunk of blocks
// - key images from each of the txs recorded in the basic records map
//   - add empty entries to that map if you want to include the key images of txs without owned enote candidates, e.g.
//     for legacy scanning where key images can appear in a tx even if none of the tx outputs were sent to you)
///
struct EnoteScanningChunkLedgerV1 final
{
    /// block range: [start height, end height)  (range is size 0 if start == end)
    std::uint64_t m_start_height;
    std::uint64_t m_end_height;
    /// block id at 'start height - 1'  (implicitly ignored if start_height == 0)
    rct::key m_prefix_block_id;
    /// block ids in range [start height, end height)
    std::vector<rct::key> m_block_ids;
    /// owned enote candidates in range [start height, end height)  (mapped to tx id)
    std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> m_basic_records_per_tx;
    /// key images from txs with owned enote candidates in range [start height, end height)
    std::list<SpContextualKeyImageSetV1> m_contextual_key_images;
};

////
// EnoteScanningChunkNonLedgerV1
// - contextual basic enote records for owned enote candidates in a non-ledger context (at a single point in time)
// - key images from all txs with owned enote candidates
///
struct EnoteScanningChunkNonLedgerV1 final
{
    /// owned enote candidates in a non-ledger context (mapped to tx id)
    std::unordered_map<rct::key, std::list<ContextualBasicRecordVariant>> m_basic_records_per_tx;
    /// key images from txs with owned enote candidates in the non-ledger context
    std::list<SpContextualKeyImageSetV1> m_contextual_key_images;
};

////
// RefreshLedgerEnoteStoreConfig
// - configuration details for an on-chain scanning process, adjust these as needed for optimal performance
///
struct RefreshLedgerEnoteStoreConfig final
{
    /// number of blocks below highest known contiguous block to start scanning
    std::uint64_t m_reorg_avoidance_depth{10};
    /// max number of blocks per on-chain scanning chunk
    std::uint64_t m_max_chunk_size{100};
    /// maximum number of times to try rescanning if a partial reorg is detected
    std::uint64_t m_max_partialscan_attempts{3};
};

/**
* brief: check_v1_enote_scan_chunk_ledger_semantics_v1 - check semantics of an on-chain chunk
*   - throws on failure
* param: onchain_chunk -
* param: expected_prefix_height -
*/
void check_v1_enote_scan_chunk_ledger_semantics_v1(const EnoteScanningChunkLedgerV1 &onchain_chunk,
    const std::uint64_t expected_prefix_height);
/**
* brief: check_v1_enote_scan_chunk_nonledger_semantics_v1 - check semantics of an off-chain chunk
*   - throws on failure
* param: nonledger_chunk -
* param: expected_origin_status -
* param: expected_spent_status -
*/
void check_v1_enote_scan_chunk_nonledger_semantics_v1(const EnoteScanningChunkNonLedgerV1 &nonledger_chunk,
    const SpEnoteOriginStatus expected_origin_status,
    const SpEnoteSpentStatus expected_spent_status);
/**
* brief: refresh_enote_store_ledger - perform a complete on-chain + unconfirmed cache balance recovery process
* param: config -
* inoutparam: scanning_context_inout -
* inoutparam: enote_store_updater_inout -
* return: false if the refresh was not completely successful (a non-exceptional error was encountered, such as too many
*         partial-scan attempts or an exception being thrown deep in the scanning code that was caught and ignored)
*/
bool refresh_enote_store_ledger(const RefreshLedgerEnoteStoreConfig &config,
    EnoteScanningContextLedger &scanning_context_inout,
    EnoteStoreUpdater &enote_store_updater_inout);
/**
* brief: refresh_enote_store_offchain - perform an off-chain balance recovery process
* param: enote_finding_context -
* inoutparam: enote_store_updater_inout -
*/
void refresh_enote_store_offchain(const EnoteFindingContextOffchain &enote_finding_context,
    EnoteStoreUpdater &enote_store_updater_inout);

} //namespace sp

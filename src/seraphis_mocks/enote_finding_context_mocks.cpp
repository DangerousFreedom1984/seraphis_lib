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
#include "enote_finding_context_mocks.h"

//local headers
#include "seraphis_impl/scan_ledger_chunk_simple.h"
#include "seraphis_main/scan_core_types.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/scan_balance_recovery_utils.h"

//third party headers

//standard headers
#include <memory>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_mocks"

namespace sp
{
namespace mocks
{
//-------------------------------------------------------------------------------------------------------------------
std::unique_ptr<scanning::LedgerChunk> EnoteFindingContextLedgerMockLegacy::get_onchain_chunk(
    const std::uint64_t chunk_start_index,
    const std::uint64_t chunk_max_size) const
{
    scanning::ChunkContext chunk_context;
    scanning::ChunkData chunk_data;

    m_mock_ledger_context.get_onchain_chunk_legacy(chunk_start_index,
        chunk_max_size,
        m_legacy_base_spend_pubkey,
        m_legacy_subaddress_map,
        m_legacy_view_privkey,
        m_legacy_scan_mode,
        chunk_context,
        chunk_data);

    return std::make_unique<scanning::LedgerChunkStandard>(
            std::move(chunk_context),
            std::vector<scanning::ChunkData>{std::move(chunk_data)},
            std::vector<rct::key>{rct::zero()}
        );
}
//-------------------------------------------------------------------------------------------------------------------
std::unique_ptr<scanning::LedgerChunk> EnoteFindingContextLedgerMockSp::get_onchain_chunk(
    const std::uint64_t chunk_start_index,
    const std::uint64_t chunk_max_size) const
{
    scanning::ChunkContext chunk_context;
    scanning::ChunkData chunk_data;

    m_mock_ledger_context.get_onchain_chunk_sp(chunk_start_index,
        chunk_max_size,
        m_xk_find_received,
        chunk_context,
        chunk_data);

    return std::make_unique<scanning::LedgerChunkStandard>(
            std::move(chunk_context),
            std::vector<scanning::ChunkData>{std::move(chunk_data)},
            std::vector<rct::key>{rct::zero()}
        );
}
//-------------------------------------------------------------------------------------------------------------------
void EnoteFindingContextUnconfirmedMockSp::get_nonledger_chunk(scanning::ChunkData &chunk_out) const
{
    m_mock_ledger_context.get_unconfirmed_chunk_sp(m_xk_find_received, chunk_out);
}
//-------------------------------------------------------------------------------------------------------------------
void EnoteFindingContextOffchainMockSp::get_nonledger_chunk(scanning::ChunkData &chunk_out) const
{
    m_mock_offchain_context.get_offchain_chunk_sp(m_xk_find_received, chunk_out);
}
//-------------------------------------------------------------------------------------------------------------------
void EnoteFindingContextMockLegacy::find_basic_records(
    const std::uint64_t block_index,
    const std::uint64_t block_timestamp,
    const rct::key &transaction_id,
    const std::uint64_t total_enotes_before_tx,
    const std::uint64_t unlock_time,
    const TxExtra &tx_memo,
    const std::vector<sp::LegacyEnoteVariant> &enotes,
    std::list<sp::ContextualBasicRecordVariant> &collected_records) const
{
    // find owned enotes from tx
    sp::scanning::try_find_legacy_enotes_in_tx(
        m_legacy_base_spend_pubkey,
        m_legacy_subaddress_map,
        m_legacy_view_privkey,
        block_index,
        block_timestamp,
        transaction_id,
        total_enotes_before_tx,
        unlock_time,
        tx_memo,
        enotes,
        sp::SpEnoteOriginStatus::ONCHAIN,
        hw::get_device("default"),
        collected_records);
}
//-------------------------------------------------------------------------------------------------------------------
size_t EnoteFindingContextMockLegacy::http_client_index()
{
    std::lock_guard<std::mutex> lock{m_http_client_mutex};
    for (size_t i = 0; i < m_http_clients.size(); ++i)
    {
        CHECK_AND_ASSERT_THROW_MES(m_http_client_in_use.find(i) != m_http_client_in_use.end(),
                "http client not expected to exist yet");
        if (!m_http_client_in_use[i])
        {
            m_http_client_in_use[i] = true;
            return i;
        }
    }

    std::unique_ptr<epee::net_utils::http::abstract_http_client> http_client = std::unique_ptr<epee::net_utils::http::abstract_http_client>(new net::http::client());
    m_http_clients.emplace_back(std::move(http_client));
    const size_t index = m_http_clients.size() - 1;
    m_http_client_in_use[index] = true;
    return index;
}
//-------------------------------------------------------------------------------------------------------------------
void EnoteFindingContextMockLegacy::release_http_client(const size_t index)
{
    std::lock_guard<std::mutex> lock{m_http_client_mutex};
    CHECK_AND_ASSERT_THROW_MES(m_http_client_in_use.find(index) != m_http_client_in_use.end(),
            "http client does exist");
    m_http_client_in_use[index] = false;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace mocks
} //namespace sp

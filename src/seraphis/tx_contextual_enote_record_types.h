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

// Records of Seraphis enotes owned by some wallet.


#pragma once

//local headers
#include "crypto/crypto.h"
#include "jamtis_support_types.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_core_types.h"
#include "tx_component_types.h"
#include "tx_enote_record_types.h"
#include "tx_extra.h"

//third party headers
#include <boost/variant/get.hpp>
#include <boost/variant/variant.hpp>

//standard headers
#include <vector>

//forward declarations


namespace sp
{

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////// Contexts ///////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

////
// SpEnoteOriginStatus
// - flag indicating where an enote is located
///
enum class SpEnoteOriginStatus
{
    // is only located off-chain
    OFFCHAIN,
    // is in the tx pool (but not the blockchain)
    UNCONFIRMED,
    // is in the blockchain
    ONCHAIN
};

////
// SpEnoteSpentStatus
// - flag indicating where an enote was spent
///
enum class SpEnoteSpentStatus
{
    // has not been spent anywhere
    UNSPENT,
    // is spent in an off-chain tx
    SPENT_OFFCHAIN,
    // is spent in a tx in the mempool
    SPENT_UNCONFIRMED,
    // is spent in the ledger
    SPENT_ONCHAIN
};

////
// SpEnoteOriginContextV1
// - info related to where an enote record was found
///
struct SpEnoteOriginContextV1 final
{
    /// block height of transaction (-1 if height is unknown)
    std::uint64_t m_block_height{static_cast<std::uint64_t>(-1)};
    /// timestamp of transaction's block (-1 if timestamp is unknown)
    std::uint64_t m_block_timestamp{static_cast<std::uint64_t>(-1)};
    /// tx id (0 if tx is unknown)
    rct::key m_transaction_id{rct::zero()};
    /// ledger index of the enote (-1 if index is unknown)
    std::uint64_t m_enote_ledger_index{static_cast<std::uint64_t>(-1)};
    /// origin status (off chain by default)
    SpEnoteOriginStatus m_origin_status{SpEnoteOriginStatus::OFFCHAIN};

    /// associated memo field (none by default)
    TxExtra m_memo{};

    /// check if this context is older than another (returns false if apparently the same age, or younger)
    bool is_older_than(const SpEnoteOriginContextV1 &other_context) const;
};

////
// SpEnoteSpentContextV1
// - info related to where an enote was spent
///
struct SpEnoteSpentContextV1 final
{
    /// block height of transaction where it was spent (-1 if unspent or height is unknown)
    std::uint64_t m_block_height{static_cast<std::uint64_t>(-1)};
    /// timestamp of transaction's block (-1 if timestamp is unknown)
    std::uint64_t m_block_timestamp{static_cast<std::uint64_t>(-1)};
    /// tx id where it was spent (0 if unspent or tx is unknown)
    rct::key m_transaction_id{rct::zero()};
    /// spent status (unspent by default)
    SpEnoteSpentStatus m_spent_status{SpEnoteSpentStatus::UNSPENT};

    /// check if this context is older than another
    bool is_older_than(const SpEnoteSpentContextV1 &other_context) const;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////// Legacy ////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

////
// LegacyContextualBasicEnoteRecordV1
// - a legacy enote basic record, with additional info related to where it was found
///
struct LegacyContextualBasicEnoteRecordV1 final
{
    /// basic info about the enote
    LegacyBasicEnoteRecord m_record;
    /// info about where the enote was found
    SpEnoteOriginContextV1 m_origin_context;

    /// onetime address equivalence
    static bool have_same_destination(const LegacyContextualBasicEnoteRecordV1 &record1,
        const LegacyContextualBasicEnoteRecordV1 &record2);
};

////
// LegacyContextualIntermediateEnoteRecordV1
// - info extracted from a legacy enote, with additional info related to where it was found
///
struct LegacyContextualIntermediateEnoteRecordV1 final
{
    /// intermediate info about the enote
    LegacyIntermediateEnoteRecord m_record;
    /// info about where the enote was found
    SpEnoteOriginContextV1 m_origin_context;

    /// get this record's onetime address
    void get_onetime_address(rct::key &onetime_address_out) const;

    /// onetime address equivalence
    static bool have_same_destination(const LegacyContextualIntermediateEnoteRecordV1 &record1,
        const LegacyContextualIntermediateEnoteRecordV1 &record2);

    /// get this enote's amount
    rct::xmr_amount amount() const { return m_record.m_amount; }
};

////
// LegacyContextualEnoteRecordV1
// - an enote with all related contextual information, including spent status
///
struct LegacyContextualEnoteRecordV1 final
{
    /// info about the enote
    LegacyEnoteRecord m_record;
    /// info about where the enote was found
    SpEnoteOriginContextV1 m_origin_context;
    /// info about where the enote was spent
    SpEnoteSpentContextV1 m_spent_context;

    /// onetime address equivalence
    static bool have_same_destination(const LegacyContextualEnoteRecordV1 &record1,
        const LegacyContextualEnoteRecordV1 &record2);

    /// get this enote's key image
    const crypto::key_image& key_image() const { return m_record.m_key_image; }

    /// get this enote's amount
    rct::xmr_amount amount() const { return m_record.m_amount; }

    /// check origin status
    bool has_origin_status(const SpEnoteOriginStatus test_status) const;

    /// check spent status
    bool has_spent_status(const SpEnoteSpentStatus test_status) const;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////// Seraphis ///////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

////
// SpContextualBasicEnoteRecordV1
// - info extracted from a v1 enote, with additional info related to where it was found
///
struct SpContextualBasicEnoteRecordV1 final
{
    /// basic info about the enote
    SpBasicEnoteRecordV1 m_record;
    /// info about where the enote was found
    SpEnoteOriginContextV1 m_origin_context;

    /// onetime address equivalence
    static bool have_same_destination(const SpContextualBasicEnoteRecordV1 &record1,
        const SpContextualBasicEnoteRecordV1 &record2);
};

////
// SpContextualIntermediateEnoteRecordV1
// - info extracted from a v1 enote, with additional info related to where it was found
///
struct SpContextualIntermediateEnoteRecordV1 final
{
    /// intermediate info about the enote
    SpIntermediateEnoteRecordV1 m_record;
    /// info about where the enote was found
    SpEnoteOriginContextV1 m_origin_context;

    /// get this record's onetime address
    void get_onetime_address(rct::key &onetime_address_out) const;

    /// onetime address equivalence
    static bool have_same_destination(const SpContextualIntermediateEnoteRecordV1 &record1,
        const SpContextualIntermediateEnoteRecordV1 &record2);

    /// get this enote's amount
    rct::xmr_amount amount() const { return m_record.m_amount; }
};

////
// SpContextualEnoteRecordV1
// - an enote with all related contextual information, including spent status
///
struct SpContextualEnoteRecordV1 final
{
    /// info about the enote
    SpEnoteRecordV1 m_record;
    /// info about where the enote was found
    SpEnoteOriginContextV1 m_origin_context;
    /// info about where the enote was spent
    SpEnoteSpentContextV1 m_spent_context;

    /// onetime address equivalence
    static bool have_same_destination(const SpContextualEnoteRecordV1 &record1, const SpContextualEnoteRecordV1 &record2);

    /// get this enote's key image
    const crypto::key_image& key_image() const { return m_record.m_key_image; }

    /// get this enote's amount
    rct::xmr_amount amount() const { return m_record.m_amount; }

    /// check origin status
    bool has_origin_status(const SpEnoteOriginStatus test_status) const;

    /// check spent status
    bool has_spent_status(const SpEnoteSpentStatus test_status) const;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////// Joint /////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////

////
// ContextualBasicRecordVariant
// - variant of all contextual basic enote record types
///
class ContextualBasicRecordVariant final
{
    using VType = boost::variant<LegacyContextualBasicEnoteRecordV1, SpContextualBasicEnoteRecordV1>;

public:
//constructors
    ContextualBasicRecordVariant() = default;
    template <typename T>
    ContextualBasicRecordVariant(const T &basic_record) : m_basic_record{basic_record} {}

//accessors
    /// get the record's origin context
    const SpEnoteOriginContextV1& origin_context() const;

    /// interact with the variant
    template <typename T>
    bool is_type() const { return boost::strict_get<T>(&m_basic_record) != nullptr; }

    template <typename T>
    const T& contextual_record() const
    {
        static const T empty{};
        return this->is_type<T>() ? boost::get<T>(m_basic_record) : empty;
    }

private:
//member variables
    /// variant of all contextual basic records
    VType m_basic_record;
};

////
// ContextualRecordVariant
// - variant of all contextual full enote record types
///
class ContextualRecordVariant final
{
    using VType = boost::variant<LegacyContextualEnoteRecordV1, SpContextualEnoteRecordV1>;

public:
//constructors
    ContextualRecordVariant() = default;
    template <typename T>
    ContextualRecordVariant(const T &record) : m_record{record} {}

//accessors
    /// get the record's amount
    rct::xmr_amount amount() const;
    /// get the record's origin context
    const SpEnoteOriginContextV1& origin_context() const;
    /// get the record's spent context
    const SpEnoteSpentContextV1& spent_context() const;

    /// interact with the variant
    template <typename T>
    bool is_type() const { return boost::strict_get<T>(&m_record) != nullptr; }

    template <typename T>
    const T& contextual_record() const
    {
        static const T empty{};
        return this->is_type<T>() ? boost::get<T>(m_record) : empty;
    }

private:
//member variables
    /// variant of all contextual enote records
    VType m_record;
};

////
// SpContextualKeyImageSetV1
// - info about the tx where a set of key images was found
///
struct SpContextualKeyImageSetV1 final
{
    /// a set of legacy key images found in a single tx
    std::vector<crypto::key_image> m_legacy_key_images;
    /// a set of seraphis key images found in a single tx
    std::vector<crypto::key_image> m_sp_key_images;
    /// info about where the corresponding inputs were spent
    SpEnoteSpentContextV1 m_spent_context;

    bool has_key_image(const crypto::key_image &test_key_image) const;
};

} //namespace sp

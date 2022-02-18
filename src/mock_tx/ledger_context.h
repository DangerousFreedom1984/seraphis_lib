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

// Interface for interacting with a ledger when validating a tx.
// NOT FOR PRODUCTION

#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <vector>

//forward declarations
namespace mock_tx
{
    struct MockENoteSpV1;
    class MockTxSpConciseV1;
    class MockTxSpMergeV1;
    class MockTxSpPlainV1;
    class MockTxSpSquashedV1;
}


namespace mock_tx
{

class LedgerContext
{
public:
    /**
    * brief: linking_tag_exists_sp_v1 - checks if a Seraphis linking tag exists in the ledger
    * param: linking_tag -
    * return: true/false on check result
    */
    virtual bool linking_tag_exists_sp_v1(const crypto::key_image &linking_tag) const = 0;
    /**
    * brief: get_reference_set_sp_v1 - gets Seraphis enotes stored in the ledger
    * param: indices -
    * outparam: enotes_out - 
    */
    virtual void get_reference_set_sp_v1(const std::vector<std::size_t> &indices,
        std::vector<MockENoteSpV1> &enotes_out) const = 0;
    /**
    * brief: get_reference_set_components_sp_v1 - gets components of Seraphis enotes stored in the ledger
    * param: indices -
    * outparam: referenced_enotes_components - {{enote address, enote amount commitment}}
    */
    virtual void get_reference_set_components_sp_v1(const std::vector<std::size_t> &indices,
        rct::keyM &referenced_enotes_components) const = 0;
    /**
    * brief: get_reference_set_components_sp_v2 - gets Seraphis squashed enotes stored in the ledger
    * param: indices -
    * outparam: referenced_enotes_components - {{squashed enote}}
    */
    virtual void get_reference_set_components_sp_v2(const std::vector<std::size_t> &indices,
        rct::keyM &referenced_enotes_components) const = 0;
    /**
    * brief: add_transaction_sp_concise_v1 - add a MockTxSpConciseV1 transaction to the ledger
    * param: tx_to_add -
    */
    virtual void add_transaction_sp_concise_v1(const MockTxSpConciseV1 &tx_to_add) = 0;
    /**
    * brief: add_transaction_sp_merge_v1 - add a MockTxSpMergeV1 transaction to the ledger
    * param: tx_to_add -
    */
    virtual void add_transaction_sp_merge_v1(const MockTxSpMergeV1 &tx_to_add) = 0;
    /**
    * brief: add_transaction_sp_plain_v1 - add a MockTxSpPlainV1 transaction to the ledger
    * param: tx_to_add -
    */
    virtual void add_transaction_sp_plain_v1(const MockTxSpPlainV1 &tx_to_add) = 0;
    /**
    * brief: add_transaction_sp_squashed_v1 - add a MockTxSpSquashedV1 transaction to the ledger
    * param: tx_to_add -
    */
    virtual void add_transaction_sp_squashed_v1(const MockTxSpSquashedV1 &tx_to_add) = 0;
};

template<typename TxType>
void add_tx_to_ledger(const std::shared_ptr<LedgerContext> &ledger_context, const TxType &tx_to_add)
{}

template<>
inline void add_tx_to_ledger<MockTxSpConciseV1>(const std::shared_ptr<LedgerContext> &ledger_context,
    const MockTxSpConciseV1 &tx_to_add)
{
    if (ledger_context.get() != nullptr)
        ledger_context->add_transaction_sp_concise_v1(tx_to_add);
}

template<>
inline void add_tx_to_ledger<MockTxSpMergeV1>(const std::shared_ptr<LedgerContext> &ledger_context,
    const MockTxSpMergeV1 &tx_to_add)
{
    if (ledger_context.get() != nullptr)
        ledger_context->add_transaction_sp_merge_v1(tx_to_add);
}

template<>
inline void add_tx_to_ledger<MockTxSpPlainV1>(const std::shared_ptr<LedgerContext> &ledger_context,
    const MockTxSpPlainV1 &tx_to_add)
{
    if (ledger_context.get() != nullptr)
        ledger_context->add_transaction_sp_plain_v1(tx_to_add);
}

template<>
inline void add_tx_to_ledger<MockTxSpSquashedV1>(const std::shared_ptr<LedgerContext> &ledger_context,
    const MockTxSpSquashedV1 &tx_to_add)
{
    if (ledger_context.get() != nullptr)
        ledger_context->add_transaction_sp_squashed_v1(tx_to_add);
}

} //namespace mock_tx

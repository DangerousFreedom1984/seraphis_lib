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

// Mock-up of interface for interacting with a context where a tx should be valid (a mock ledger).


#pragma once

//local headers
#include "crypto/crypto.h"
#include "mock_ledger_context.h"
#include "ringct/rctTypes.h"
#include "tx_validation_context.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{

class TxValidationContextMock final : public TxValidationContext
{
public:
//constructors
    TxValidationContextMock(const MockLedgerContext &mock_ledger_context) :
        m_mock_ledger_context{mock_ledger_context}
    {}

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    TxValidationContextMock& operator=(TxValidationContextMock&&) = delete;

//member functions
    /**
    * brief: key_image_exists_v1 - checks if a key image (linking tag) exists in the mock ledger
    * param: key_image -
    * return: true/false on check result
    */
    bool key_image_exists_v1(const crypto::key_image &key_image) const override
    {
        return m_mock_ledger_context.key_image_exists_onchain_v1(key_image);
    }
    /**
    * brief: get_reference_set_proof_elements_v1 - gets legacy {KI, C} pairs stored in the mock ledger
    * param: indices -
    * outparam: proof_elements_out - {KI, C}
    */
    void get_reference_set_proof_elements_v1(const std::vector<std::uint64_t> &indices,
        rct::ctkeyV &proof_elements_out) const override
    {
        m_mock_ledger_context.get_reference_set_proof_elements_v1(indices, proof_elements_out);
    }
    /**
    * brief: get_reference_set_proof_elements_v2 - gets Seraphis squashed enotes stored in the mock ledger
    * param: indices -
    * outparam: proof_elements_out - {squashed enote}
    */
    void get_reference_set_proof_elements_v2(const std::vector<std::uint64_t> &indices,
        rct::keyV &proof_elements_out) const override
    {
        m_mock_ledger_context.get_reference_set_proof_elements_v2(indices, proof_elements_out);
    }

//member variables
private:
    const MockLedgerContext &m_mock_ledger_context;
};

////
// TxValidationContextMockPartial
// - wraps a mock ledger context
// - stores manually-specified legacy reference set elements (useful for validating partial txs)
///
class TxValidationContextMockPartial final : public TxValidationContext
{
public:
//constructors
    TxValidationContextMockPartial(const MockLedgerContext &mock_ledger_context,
        const std::unordered_map<std::uint64_t, rct::ctkey> &legacy_reference_set_proof_elements) :
        m_mock_ledger_context{mock_ledger_context},
        m_legacy_reference_set_proof_elements{legacy_reference_set_proof_elements}
    {}

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    TxValidationContextMockPartial& operator=(TxValidationContextMockPartial&&) = delete;

//member functions
    /**
    * brief: key_image_exists_v1 - checks if a key image (linking tag) exists in the mock ledger
    * param: key_image -
    * return: true/false on check result
    */
    bool key_image_exists_v1(const crypto::key_image &key_image) const override
    {
        return m_mock_ledger_context.key_image_exists_onchain_v1(key_image);
    }
    /**
    * brief: get_reference_set_proof_elements_v1 - gets legacy {KI, C} pairs stored in the validation context
    * param: indices -
    * outparam: proof_elements_out - {KI, C}
    */
    void get_reference_set_proof_elements_v1(const std::vector<std::uint64_t> &indices,
        rct::ctkeyV &proof_elements_out) const override
    {
        proof_elements_out.clear();
        proof_elements_out.reserve(indices.size());

        for (const std::uint64_t index : indices)
        {
            if (m_legacy_reference_set_proof_elements.find(index) != m_legacy_reference_set_proof_elements.end())
                proof_elements_out.emplace_back(m_legacy_reference_set_proof_elements.at(index));
            else
                proof_elements_out.emplace_back(rct::ctkey{});
        }
    }
    /**
    * brief: get_reference_set_proof_elements_v2 - gets seraphis squashed enotes stored in the mock ledger
    * param: indices -
    * outparam: proof_elements_out - {squashed enote}
    */
    void get_reference_set_proof_elements_v2(const std::vector<std::uint64_t> &indices,
        rct::keyV &proof_elements_out) const override
    {
        m_mock_ledger_context.get_reference_set_proof_elements_v2(indices, proof_elements_out);
    }

//member variables
private:
    const MockLedgerContext &m_mock_ledger_context;
    const std::unordered_map<std::uint64_t, rct::ctkey> &m_legacy_reference_set_proof_elements;
};

} //namespace sp

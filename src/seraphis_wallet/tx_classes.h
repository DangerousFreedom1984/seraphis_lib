// Copyright (c) 2023, The Monero Project
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

#pragma once

// local headers

// third party headers

// standard headers

// forward declarations

#include <boost/variant.hpp>

#include "cryptonote_basic/cryptonote_basic.h"
#include "seraphis_main/txtype_squashed_v1.h"

using TransactionVariant = tools::variant<sp::SpTxSquashedV1, cryptonote::transaction>;

const crypto::hash get_tx_id(const TransactionVariant &tx_variant);

// typedef boost::variant<sp::SpTxSquashedV1, cryptonote::transaction> TransactionVariant;

// enum TransactionType
// {
//     CRYPTONOTE,
//     SERAPHIS
// };

// class GenericTransaction
// {
//    private:
//     TransactionVariant tx_variant;
//     TransactionType tx_type;

//    public:
//     bool is_hash_valid(const TransactionVariant &tx_variant);
//     uint64_t get_tx_id(const TransactionVariant &tx_variant);

//     //   size_t get_size_bytes();
//     //   size_t get_weigth();
//     //   void set_null();
//     //   void invalidate_hashes();
//     //   bool is_hash_valid();
//     //   void set_hash_valid(bool v);
//     //   bool is_prunable_hash_valid();
//     //   void set_prunable_hash_valid(bool v);
//     //   bool is_blob_size_valid();
//     //   void set_blob_size_valid(bool v);
//     //   void set_hash(const crypto::hash &h);
//     //   void set_prunable_hash(const crypto::hash &h);
//     //   void set_blob_size(size_t sz);
//     //   void *get_ref_to_object();

//     // generic_transaction(transaction_type_t tx_type);
// };

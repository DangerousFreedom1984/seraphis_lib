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
#include "common/variant.h"
#include "legacy_enote_types.h"

//local headers
#include "crypto/crypto.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void LegacyEnoteV1::gen()
{
    m_onetime_address = rct::pkGen();
    m_amount = crypto::rand_idx(static_cast<rct::xmr_amount>(-1));
}
//-------------------------------------------------------------------------------------------------------------------
void LegacyEnoteV2::gen()
{
    m_onetime_address = rct::pkGen();
    m_amount_commitment = rct::pkGen();
    m_encoded_amount_blinding_factor = rct::skGen();
    m_encoded_amount = rct::skGen();
}
//-------------------------------------------------------------------------------------------------------------------
void LegacyEnoteV3::gen()
{
    m_onetime_address = rct::pkGen();
    m_amount_commitment = rct::pkGen();
    m_encoded_amount = crypto::rand_idx(static_cast<rct::xmr_amount>(-1));
}
//-------------------------------------------------------------------------------------------------------------------
void LegacyEnoteV4::gen()
{
    m_onetime_address = rct::pkGen();
    m_amount_commitment = rct::pkGen();
    m_encoded_amount = crypto::rand_idx(static_cast<rct::xmr_amount>(-1));
    m_view_tag.data = static_cast<char>(crypto::rand_idx(static_cast<unsigned char>(-1)));
}
//-------------------------------------------------------------------------------------------------------------------
const rct::key& onetime_address_ref(const LegacyEnoteVariant &variant)
{
    struct visitor : public tools::variant_static_visitor<const rct::key&>
    {
        using variant_static_visitor::operator();  //for blank overload
        const rct::key& operator()(const LegacyEnoteV1 &enote) const { return enote.m_onetime_address; }
        const rct::key& operator()(const LegacyEnoteV2 &enote) const { return enote.m_onetime_address; }
        const rct::key& operator()(const LegacyEnoteV3 &enote) const { return enote.m_onetime_address; }
        const rct::key& operator()(const LegacyEnoteV4 &enote) const { return enote.m_onetime_address; }
    };

    return variant.visit(visitor{});
}
//-------------------------------------------------------------------------------------------------------------------
rct::key amount_commitment_ref(const LegacyEnoteVariant &variant)
{
    struct visitor : public tools::variant_static_visitor<rct::key>
    {
        using variant_static_visitor::operator();  //for blank overload
        rct::key operator()(const LegacyEnoteV1 &enote) const { return rct::zeroCommit(enote.m_amount); }
        rct::key operator()(const LegacyEnoteV2 &enote) const { return enote.m_amount_commitment; }
        rct::key operator()(const LegacyEnoteV3 &enote) const { return enote.m_amount_commitment; }
        rct::key operator()(const LegacyEnoteV4 &enote) const { return enote.m_amount_commitment; }
    };

    return variant.visit(visitor{});
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp

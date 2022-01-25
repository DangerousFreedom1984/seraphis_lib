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

// Core types for making enotes with Jamtis addresses
// - Jamtis is a specification for Seraphis-compatible addresses


#pragma once

//local headers
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "ringct/rctTypes.h"
#include "tx_builder_types.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{

/// self-send destination type, used to define enote-construction procedure for self-sends
enum class JamtisSelfSendType
{
    CHANGE,
    SELF_SPEND
};

////
// JamtisDestinationV1
// - for creating an output proposal to send an amount to someone
///
struct JamtisDestinationV1 final
{
    /// K_1 = k^j_x X + K_s  (address spend key)
    rct::key m_addr_K1;
    /// K_2 = k^j_a K_fr     (address view key)
    rct::key m_addr_K2;
    /// K_3 = k^j_a G        (DH base key)
    rct::key m_addr_K3;
    /// t_addr
    address_tag_t m_address_tag;

    /// b
    rct::xmr_amount m_amount;

    /// enote privkey
    crypto::secret_key m_enote_privkey;

    /**
    * brief: get_output_proposal_v1 - convert this destination to a concrete output proposal
    * outparam: enote_out -
    */
    void get_output_proposal_v1(SpOutputProposalV1 &output_proposal_out, rct::key &enote_pubkey_out) const;

    /**
    * brief: gen - generate a random destination address
    * param: amount -
    */
    void gen(const rct::xmr_amount amount);
};

////
// JamtisDestinationSelfSendV1
// - for creating an output proposal to send an amount to the tx author
///
struct JamtisDestinationSelfSendV1 final
{
    /// K_1 = k^j_x X + K_s  (address spend key)
    rct::key m_addr_K1;
    /// K_2 = k^j_a K_fr     (address view key)
    rct::key m_addr_K2;
    /// K_3 = k^j_a G        (DH base key)
    rct::key m_addr_K3;
    /// j
    address_index_t m_address_index;
    /// type
    JamtisSelfSendType m_type;

    /// b
    rct::xmr_amount m_amount;

    /// enote privkey
    crypto::secret_key m_enote_privkey;

    /// view-balance key
    crypto::secret_key m_viewbalance_privkey;

    /**
    * brief: get_output_proposal_v1 - convert this destination to a concrete output proposal
    * outparam: enote_out -
    */
    void get_output_proposal_v1(SpOutputProposalV1 &output_proposal_out, rct::key &enote_pubkey_out) const;

    /**
    * brief: gen - generate a random destination address
    * param: amount -
    */
    void gen(const rct::xmr_amount amount);
};

} //namespace sp

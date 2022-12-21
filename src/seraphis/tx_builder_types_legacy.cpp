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
#include "tx_builder_types_legacy.h"

//local headers
#include "crypto/crypto.h"
#include "legacy_core_utils.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "tx_component_types_legacy.h"

//third party headers

//standard headers
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount amount_ref(const LegacyInputProposalV1 &proposal)
{
    return proposal.m_amount;
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_KI(const LegacyInputProposalV1 &a, const LegacyInputProposalV1 &b)
{
    return a.m_key_image < b.m_key_image;
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_KI(const LegacyRingSignaturePrepV1 &a, const LegacyRingSignaturePrepV1 &b)
{
    return compare_KI(a.m_reference_image, b.m_reference_image);
}
//-------------------------------------------------------------------------------------------------------------------
bool compare_KI(const LegacyInputV1 &a, const LegacyInputV1 &b)
{
    return compare_KI(a.m_input_image, b.m_input_image);
}
//-------------------------------------------------------------------------------------------------------------------
void get_enote_image_v2(const LegacyInputProposalV1 &proposal, LegacyEnoteImageV2 &image_out)
{
    mask_key(proposal.m_commitment_mask, proposal.m_amount_commitment, image_out.m_masked_commitment);
    image_out.m_key_image = proposal.m_key_image;
}
//-------------------------------------------------------------------------------------------------------------------
LegacyInputProposalV1 gen_legacy_input_proposal_v1(const crypto::secret_key &legacy_spend_privkey,
    const rct::xmr_amount amount)
{
    LegacyInputProposalV1 temp;

    temp.m_enote_view_privkey = rct::rct2sk(rct::skGen());
    temp.m_amount_blinding_factor = rct::rct2sk(rct::skGen());
    temp.m_amount = amount;
    temp.m_commitment_mask = rct::rct2sk(rct::skGen());
    temp.m_onetime_address = rct::scalarmultBase(rct::sk2rct(legacy_spend_privkey));
    rct::addKeys1(temp.m_onetime_address, rct::sk2rct(temp.m_enote_view_privkey), temp.m_onetime_address);
    temp.m_amount_commitment = rct::commit(temp.m_amount, rct::sk2rct(temp.m_amount_blinding_factor));
    make_legacy_key_image(temp.m_enote_view_privkey, legacy_spend_privkey, temp.m_onetime_address, temp.m_key_image);

    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp

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
#include "tx_builders_inputs.h"

//local headers
#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "cryptonote_config.h"
#include "jamtis_enote_utils.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_crypto/grootle.h"
#include "seraphis_crypto/sp_composition_proof.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_crypto/sp_hash_functions.h"
#include "seraphis_crypto/sp_transcript.h"
#include "sp_core_enote_utils.h"
#include "tx_binned_reference_set.h"
#include "tx_binned_reference_set_utils.h"
#include "tx_builder_types.h"
#include "tx_builder_types_legacy.h"
#include "tx_component_types.h"
#include "tx_component_types_legacy.h"
#include "tx_enote_record_types.h"
#include "tx_enote_record_utils.h"

//third party headers

//standard headers
#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
void make_binned_ref_set_generator_seed_v1(const rct::key &masked_address,
    const rct::key &masked_commitment,
    rct::key &generator_seed_out)
{
    // make binned reference set generator seed

    // seed = H_32(K", C")
    SpKDFTranscript transcript{config::HASH_KEY_BINNED_REF_SET_GENERATOR_SEED, 2*sizeof(rct::key)};
    transcript.append("K_masked", masked_address);
    transcript.append("C_masked", masked_commitment);

    // hash to the result
    sp_hash_to_32(transcript.data(), transcript.size(), generator_seed_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_binned_ref_set_generator_seed_v1(const rct::key &onetime_address,
    const rct::key &amount_commitment,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    rct::key &generator_seed_out)
{
    // make binned reference set generator seed from pieces

    // masked address and commitment
    rct::key masked_address;     //K" = t_k G + H_n(Ko,C) Ko
    rct::key masked_commitment;  //C" = t_c G + C
    make_seraphis_enote_image_masked_keys(onetime_address,
        amount_commitment,
        address_mask,
        commitment_mask,
        masked_address,
        masked_commitment);

    // finish making the seed
    make_binned_ref_set_generator_seed_v1(masked_address, masked_commitment, generator_seed_out);
}
//-------------------------------------------------------------------------------------------------------------------
void align_v1_membership_proofs_v1(const std::vector<SpEnoteImageV1> &input_images,
    std::vector<SpAlignableMembershipProofV1> alignable_membership_proofs,
    std::vector<SpMembershipProofV1> &membership_proofs_out)
{
    CHECK_AND_ASSERT_THROW_MES(alignable_membership_proofs.size() == input_images.size(),
        "Mismatch between alignable membership proof count and partial tx input image count.");

    membership_proofs_out.clear();
    membership_proofs_out.reserve(alignable_membership_proofs.size());

    for (const SpEnoteImageV1 &input_image : input_images)
    {
        // find the membership proof that matches with the input image at this index
        auto membership_proof_match =
            std::find_if(
                alignable_membership_proofs.begin(),
                alignable_membership_proofs.end(),
                [&masked_address = input_image.m_core.m_masked_address](const SpAlignableMembershipProofV1 &a) -> bool
                {
                    return alignment_check(a, masked_address);
                }
            );

        CHECK_AND_ASSERT_THROW_MES(membership_proof_match != alignable_membership_proofs.end(),
            "Could not find input image to match with an alignable membership proof.");

        membership_proofs_out.emplace_back(std::move(membership_proof_match->m_membership_proof));
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_tx_membership_proof_message_v1(const SpBinnedReferenceSetV1 &binned_reference_set, rct::key &message_out)
{
    static const std::string project_name{CRYPTONOTE_NAME};

    // m = H_32('project name', {binned reference set})
    SpFSTranscript transcript{
            config::HASH_KEY_SERAPHIS_MEMBERSHIP_PROOF_MESSAGE_V1,
            project_name.size() +
                sp_binned_ref_set_v1_size_bytes(binned_reference_set) +
                sp_binned_ref_set_config_v1_size_bytes()
        };
    transcript.append("project_name", project_name);  //i.e. referenced enotes are members of what project's ledger?
    transcript.append("binned_reference_set", binned_reference_set);

    sp_hash_to_32(transcript.data(), transcript.size(), message_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void prepare_input_commitment_factors_for_balance_proof_v1(const std::vector<SpInputProposalV1> &input_proposals,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &blinding_factors_out)
{
    // use input proposals to get amounts/blinding factors
    blinding_factors_out.clear();
    input_amounts_out.clear();
    blinding_factors_out.resize(input_proposals.size());
    input_amounts_out.reserve(input_proposals.size());

    for (std::size_t input_index{0}; input_index < input_proposals.size(); ++input_index)
    {
        // input image amount commitment blinding factor: t_c + x
        sc_add(to_bytes(blinding_factors_out[input_index]),
            to_bytes(input_proposals[input_index].m_core.m_commitment_mask),  // t_c
            to_bytes(input_proposals[input_index].m_core.m_amount_blinding_factor));  // x

        // input amount: a
        input_amounts_out.emplace_back(input_proposals[input_index].amount());
    }
}
//-------------------------------------------------------------------------------------------------------------------
void prepare_input_commitment_factors_for_balance_proof_v1(const std::vector<SpPartialInputV1> &partial_inputs,
    std::vector<rct::xmr_amount> &input_amounts_out,
    std::vector<crypto::secret_key> &blinding_factors_out)
{
    // use partial inputs to get amounts/blinding factors
    blinding_factors_out.clear();
    input_amounts_out.clear();
    blinding_factors_out.resize(partial_inputs.size());
    input_amounts_out.reserve(partial_inputs.size());

    for (std::size_t input_index{0}; input_index < partial_inputs.size(); ++input_index)
    {
        // input image amount commitment blinding factor: t_c + x
        sc_add(to_bytes(blinding_factors_out[input_index]),
            to_bytes(partial_inputs[input_index].m_commitment_mask),  // t_c
            to_bytes(partial_inputs[input_index].m_input_amount_blinding_factor));  // x

        // input amount: a
        input_amounts_out.emplace_back(partial_inputs[input_index].m_input_amount);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_input_images_prefix_v1(const std::vector<LegacyEnoteImageV2> &legacy_enote_images,
    const std::vector<SpEnoteImageV1> &sp_enote_images,
    rct::key &input_images_prefix_out)
{
    // input images prefix = H_32({C", KI}((legacy)), {K", C", KI})
    SpFSTranscript transcript{
            config::HASH_KEY_SERAPHIS_INPUT_IMAGES_PREFIX_V1,
            legacy_enote_images.size() * LegacyEnoteImageV2::size_bytes() +
            sp_enote_images.size() * SpEnoteImageV1::size_bytes()
        };
    transcript.append("legacy_enote_images", legacy_enote_images);
    transcript.append("sp_enote_images", sp_enote_images);

    sp_hash_to_32(transcript.data(), transcript.size(), input_images_prefix_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_input_proposal_semantics_v1(const SpInputProposalV1 &input_proposal, const rct::key &sp_core_spend_pubkey)
{
    // 1. the onetime address must be reproducible
    rct::key extended_spendkey{sp_core_spend_pubkey};
    extend_seraphis_spendkey_u(input_proposal.m_core.m_enote_view_privkey_u, extended_spendkey);

    rct::key onetime_address_reproduced{extended_spendkey};
    extend_seraphis_spendkey_x(input_proposal.m_core.m_enote_view_privkey_x, onetime_address_reproduced);
    mask_key(input_proposal.m_core.m_enote_view_privkey_g, onetime_address_reproduced, onetime_address_reproduced);

    CHECK_AND_ASSERT_THROW_MES(onetime_address_reproduced == onetime_address_ref(input_proposal.m_core.m_enote_core),
        "input proposal v1 semantics check: could not reproduce the one-time address.");

    // 2. the key image must be reproducible and canonical
    crypto::key_image key_image_reproduced;
    make_seraphis_key_image(input_proposal.m_core.m_enote_view_privkey_x,
        rct::rct2pk(extended_spendkey),
        key_image_reproduced);

    CHECK_AND_ASSERT_THROW_MES(key_image_reproduced == input_proposal.m_core.m_key_image,
        "input proposal v1 semantics check: could not reproduce the key image.");
    CHECK_AND_ASSERT_THROW_MES(key_domain_is_prime_subgroup(rct::ki2rct(key_image_reproduced)),
        "input proposal v1 semantics check: the key image is not canonical.");

    // 3. the amount commitment must be reproducible
    const rct::key amount_commitment_reproduced{
            rct::commit(input_proposal.m_core.m_amount, rct::sk2rct(input_proposal.m_core.m_amount_blinding_factor))
        };

    CHECK_AND_ASSERT_THROW_MES(amount_commitment_reproduced == amount_commitment_ref(input_proposal.m_core.m_enote_core),
        "input proposal v1 semantics check: could not reproduce the amount commitment.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_input_proposal(const SpEnoteCoreVariant &enote_core,
    const crypto::key_image &key_image,
    const crypto::secret_key &enote_view_privkey_g,
    const crypto::secret_key &enote_view_privkey_x,
    const crypto::secret_key &enote_view_privkey_u,
    const crypto::secret_key &input_amount_blinding_factor,
    const rct::xmr_amount &input_amount,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpInputProposalCore &proposal_out)
{
    // make an input proposal
    proposal_out.m_enote_core             = enote_core;
    proposal_out.m_key_image              = key_image;
    proposal_out.m_enote_view_privkey_g   = enote_view_privkey_g;
    proposal_out.m_enote_view_privkey_x   = enote_view_privkey_x;
    proposal_out.m_enote_view_privkey_u   = enote_view_privkey_u;
    proposal_out.m_amount_blinding_factor = input_amount_blinding_factor;
    proposal_out.m_amount                 = input_amount;
    proposal_out.m_address_mask           = address_mask;
    proposal_out.m_commitment_mask        = commitment_mask;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_input_proposal_v1(const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpInputProposalV1 &proposal_out)
{
    // make input proposal from enote record
    make_input_proposal(core_ref(enote_record.m_enote),
        enote_record.m_key_image,
        enote_record.m_enote_view_privkey_g,
        enote_record.m_enote_view_privkey_x,
        enote_record.m_enote_view_privkey_u,
        enote_record.m_amount_blinding_factor,
        enote_record.m_amount,
        address_mask,
        commitment_mask,
        proposal_out.m_core);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_v1_input_proposal_v1(const SpEnoteVariant &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpInputProposalV1 &proposal_out)
{
    // try to extract info from enote then make an input proposal
    SpEnoteRecordV1 enote_record;
    if (!try_get_enote_record_v1(enote,
            enote_ephemeral_pubkey,
            input_context,
            jamtis_spend_pubkey,
            k_view_balance,
            enote_record))
        return false;

    make_v1_input_proposal_v1(enote_record, address_mask, commitment_mask, proposal_out);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void make_standard_input_context_v1(const std::vector<LegacyInputProposalV1> &legacy_input_proposals,
    const std::vector<SpInputProposalV1> &sp_input_proposals,
    rct::key &input_context_out)
{
    // collect key images
    std::vector<crypto::key_image> legacy_key_images_collected;
    std::vector<crypto::key_image> sp_key_images_collected;
    legacy_key_images_collected.reserve(legacy_input_proposals.size());
    sp_key_images_collected.reserve(sp_input_proposals.size());

    for (const LegacyInputProposalV1 &legacy_input_proposal : legacy_input_proposals)
        legacy_key_images_collected.emplace_back(legacy_input_proposal.m_key_image);

    for (const SpInputProposalV1 &sp_input_proposal : sp_input_proposals)
        sp_key_images_collected.emplace_back(key_image_ref(sp_input_proposal.m_core));

    // sort the key images
    std::sort(legacy_key_images_collected.begin(), legacy_key_images_collected.end());
    std::sort(sp_key_images_collected.begin(), sp_key_images_collected.end());

    // make the input context
    jamtis::make_jamtis_input_context_standard(legacy_key_images_collected, sp_key_images_collected, input_context_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_image_proof_v1(const SpInputProposalCore &input_proposal,
    const rct::key &message,
    const crypto::secret_key &sp_spend_privkey,
    SpImageProofV1 &image_proof_out)
{
    // make image proof

    // 1. the input enote
    const SpEnoteCoreVariant &input_enote_core{enote_core_ref(input_proposal)};

    // 2. the input enote image
    SpEnoteImageCore input_enote_image_core;
    get_enote_image_core(input_proposal, input_enote_image_core);

    // 3. prepare for proof (squashed enote model): x, y, z

    // a. squash prefix: H_n(Ko,C)
    rct::key squash_prefix;
    make_seraphis_squash_prefix(onetime_address_ref(input_enote_core),
        amount_commitment_ref(input_enote_core),
        squash_prefix);  // H_n(Ko,C)

    // b. x: t_k + H_n(Ko,C) (k_{mask, recipient} + k_{mask, sender})
    crypto::secret_key x;
    sc_mul(to_bytes(x), squash_prefix.bytes, to_bytes(input_proposal.m_enote_view_privkey_g));
    sc_add(to_bytes(x), to_bytes(input_proposal.m_address_mask), to_bytes(x));

    // c. y: H_n(Ko,C) (k_{a, recipient} + k_{a, sender})
    crypto::secret_key y;
    sc_mul(to_bytes(y), squash_prefix.bytes, to_bytes(input_proposal.m_enote_view_privkey_x));

    // d. z: H_n(Ko,C) (k_{b, recipient} + k_{b, sender})
    crypto::secret_key z;
    sc_add(to_bytes(z), to_bytes(input_proposal.m_enote_view_privkey_u), to_bytes(sp_spend_privkey));
    sc_mul(to_bytes(z), squash_prefix.bytes, to_bytes(z));

    // 4. make seraphis composition proof
    make_sp_composition_proof(message,
        input_enote_image_core.m_masked_address,
        x,
        y,
        z,
        image_proof_out.m_composition_proof);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_image_proofs_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const rct::key &message,
    const crypto::secret_key &sp_spend_privkey,
    std::vector<SpImageProofV1> &image_proofs_out)
{
    // make multiple image proofs
    CHECK_AND_ASSERT_THROW_MES(input_proposals.size() > 0, "Tried to make image proofs for 0 inputs.");

    image_proofs_out.clear();
    image_proofs_out.reserve(input_proposals.size());

    for (const SpInputProposalV1 &input_proposal : input_proposals)
        make_v1_image_proof_v1(input_proposal.m_core, message, sp_spend_privkey, tools::add_element(image_proofs_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_membership_proof_v1(const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    SpBinnedReferenceSetV1 binned_reference_set,
    const std::vector<rct::key> &referenced_enotes_squashed,
    const SpEnoteCoreVariant &real_reference_enote,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMembershipProofV1 &membership_proof_out)
{
    // make membership proof

    /// checks and initialization

    // 1. misc
    const std::size_t ref_set_size{size_from_decomposition(ref_set_decomp_n, ref_set_decomp_m)};

    CHECK_AND_ASSERT_THROW_MES(referenced_enotes_squashed.size() == ref_set_size,
        "make membership proof: ref set size doesn't match number of referenced enotes.");
    CHECK_AND_ASSERT_THROW_MES(reference_set_size(binned_reference_set) == ref_set_size,
        "make membership proof: ref set size doesn't number of references in the binned reference set.");

    // 2. make the real reference's squashed representation for later
    rct::key transformed_address;
    make_seraphis_squashed_address_key(onetime_address_ref(real_reference_enote),
        amount_commitment_ref(real_reference_enote),
        transformed_address);  //H_n(Ko,C) Ko

    rct::key real_Q;
    rct::addKeys(real_Q, transformed_address, amount_commitment_ref(real_reference_enote));  //Hn(Ko, C) Ko + C

    // 3. check binned reference set generator
    rct::key masked_address;
    mask_key(address_mask, transformed_address, masked_address);  //K" = t_k G + H_n(Ko,C) Ko

    rct::key masked_commitment;
    mask_key(commitment_mask, amount_commitment_ref(real_reference_enote), masked_commitment);  //C" = t_c G + C

    rct::key generator_seed_reproduced;
    make_binned_ref_set_generator_seed_v1(masked_address, masked_commitment, generator_seed_reproduced);

    CHECK_AND_ASSERT_THROW_MES(generator_seed_reproduced == binned_reference_set.m_bin_generator_seed,
        "make membership proof: unable to reproduce binned reference set generator seed.");


    /// prepare to make proof

    // 1. find the real referenced enote
    std::size_t real_spend_index_in_set{ref_set_size};  //l

    for (std::size_t ref_index{0}; ref_index < ref_set_size; ++ref_index)
    {
        if (real_Q == referenced_enotes_squashed[ref_index])  //Q[l]
        {
            real_spend_index_in_set = ref_index;
            break;
        }
    }
    CHECK_AND_ASSERT_THROW_MES(real_spend_index_in_set < ref_set_size,
        "make membership proof: could not find enote for membership proof in reference set.");

    // 2. proof offset (only one in the squashed enote model)
    const rct::key image_offset{rct::addKeys(masked_address, masked_commitment)};  //Q" = K" + C"

    // 3. secret key of: Q[l] - Q" = -(t_k + t_c) G
    static const rct::key MINUS_ONE{minus_one()};

    crypto::secret_key image_mask;
    sc_add(to_bytes(image_mask), to_bytes(address_mask), to_bytes(commitment_mask));  // t_k + t_c
    sc_mul(to_bytes(image_mask), to_bytes(image_mask), MINUS_ONE.bytes);  // -(t_k + t_c)

    // 4. proof message
    rct::key message;
    make_tx_membership_proof_message_v1(binned_reference_set, message);


    /// make grootle proof
    make_grootle_proof(message,
        referenced_enotes_squashed,
        real_spend_index_in_set,
        image_offset,
        image_mask,
        ref_set_decomp_n,
        ref_set_decomp_m,
        membership_proof_out.m_grootle_proof);


    /// copy miscellaneous components
    membership_proof_out.m_binned_reference_set = std::move(binned_reference_set);
    membership_proof_out.m_ref_set_decomp_n     = ref_set_decomp_n;
    membership_proof_out.m_ref_set_decomp_m     = ref_set_decomp_m;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_membership_proof_v1(SpMembershipProofPrepV1 membership_proof_prep, SpMembershipProofV1 &membership_proof_out)
{
    make_v1_membership_proof_v1(membership_proof_prep.m_ref_set_decomp_n,
        membership_proof_prep.m_ref_set_decomp_m,
        std::move(membership_proof_prep.m_binned_reference_set),
        membership_proof_prep.m_referenced_enotes_squashed,
        membership_proof_prep.m_real_reference_enote,
        membership_proof_prep.m_address_mask,
        membership_proof_prep.m_commitment_mask,
        membership_proof_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_membership_proof_v1(SpMembershipProofPrepV1 membership_proof_prep,
    SpAlignableMembershipProofV1 &alignable_membership_proof_out)
{
    // make alignable membership proof

    // save the masked address to later match the membership proof with its input image
    make_seraphis_squashed_address_key(
        onetime_address_ref(membership_proof_prep.m_real_reference_enote),
        amount_commitment_ref(membership_proof_prep.m_real_reference_enote),
        alignable_membership_proof_out.m_masked_address);  //H_n(Ko,C) Ko

    mask_key(membership_proof_prep.m_address_mask,
        alignable_membership_proof_out.m_masked_address,
        alignable_membership_proof_out.m_masked_address);  //t_k G + H_n(Ko,C) Ko

    // make the membership proof
    make_v1_membership_proof_v1(std::move(membership_proof_prep), alignable_membership_proof_out.m_membership_proof);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_membership_proofs_v1(std::vector<SpMembershipProofPrepV1> membership_proof_preps,
    std::vector<SpMembershipProofV1> &membership_proofs_out)
{
    // make multiple membership proofs
    // note: proof preps are assumed to be pre-sorted here, so alignable membership proofs are not needed
    membership_proofs_out.clear();
    membership_proofs_out.reserve(membership_proof_preps.size());

    for (SpMembershipProofPrepV1 &proof_prep : membership_proof_preps)
        make_v1_membership_proof_v1(std::move(proof_prep), tools::add_element(membership_proofs_out));
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_membership_proofs_v1(std::vector<SpMembershipProofPrepV1> membership_proof_preps,
    std::vector<SpAlignableMembershipProofV1> &alignable_membership_proofs_out)
{
    // make multiple alignable membership proofs
    alignable_membership_proofs_out.clear();
    alignable_membership_proofs_out.reserve(membership_proof_preps.size());

    for (SpMembershipProofPrepV1 &proof_prep : membership_proof_preps)
        make_v1_membership_proof_v1(std::move(proof_prep), tools::add_element(alignable_membership_proofs_out));
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_partial_input_semantics_v1(const SpPartialInputV1 &partial_input)
{
    // input amount commitment can be reconstructed
    const rct::key reconstructed_amount_commitment{
            rct::commit(partial_input.m_input_amount, rct::sk2rct(partial_input.m_input_amount_blinding_factor))
        };

    CHECK_AND_ASSERT_THROW_MES(reconstructed_amount_commitment == amount_commitment_ref(partial_input.m_input_enote_core),
        "partial input semantics (v1): could not reconstruct amount commitment.");

    // input image masked address and commitment can be reconstructed
    rct::key reconstructed_masked_address;
    rct::key reconstructed_masked_commitment;
    make_seraphis_enote_image_masked_keys(onetime_address_ref(partial_input.m_input_enote_core),
        reconstructed_amount_commitment,
        partial_input.m_address_mask,
        partial_input.m_commitment_mask,
        reconstructed_masked_address,
        reconstructed_masked_commitment);

    CHECK_AND_ASSERT_THROW_MES(reconstructed_masked_address == partial_input.m_input_image.m_core.m_masked_address,
        "partial input semantics (v1): could not reconstruct masked address.");
    CHECK_AND_ASSERT_THROW_MES(reconstructed_masked_commitment == partial_input.m_input_image.m_core.m_masked_commitment,
        "partial input semantics (v1): could not reconstruct masked address.");

    // image proof is valid
    CHECK_AND_ASSERT_THROW_MES(verify_sp_composition_proof(partial_input.m_image_proof.m_composition_proof,
            partial_input.m_proposal_prefix,
            reconstructed_masked_address,
            partial_input.m_input_image.m_core.m_key_image),
        "partial input semantics (v1): image proof is invalid.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_partial_input_v1(const SpInputProposalV1 &input_proposal,
    const rct::key &proposal_prefix,
    SpImageProofV1 sp_image_proof,
    const rct::key &sp_core_spend_pubkey,
    SpPartialInputV1 &partial_input_out)
{
    // 1. check input proposal semantics
    check_v1_input_proposal_semantics_v1(input_proposal, sp_core_spend_pubkey);

    // 2. prepare input image
    input_proposal.get_enote_image_v1(partial_input_out.m_input_image);

    // 3. set partial input pieces
    partial_input_out.m_image_proof                  = std::move(sp_image_proof);
    partial_input_out.m_address_mask                 = input_proposal.m_core.m_address_mask;
    partial_input_out.m_commitment_mask              = input_proposal.m_core.m_commitment_mask;
    partial_input_out.m_proposal_prefix              = proposal_prefix;
    partial_input_out.m_input_enote_core             = enote_core_ref(input_proposal.m_core);
    partial_input_out.m_input_amount                 = input_proposal.amount();
    partial_input_out.m_input_amount_blinding_factor = input_proposal.m_core.m_amount_blinding_factor;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_partial_input_v1(const SpInputProposalV1 &input_proposal,
    const rct::key &proposal_prefix,
    const crypto::secret_key &sp_spend_privkey,
    SpPartialInputV1 &partial_input_out)
{
    // 1. initialization
    rct::key sp_core_spend_pubkey;
    make_seraphis_spendbase(sp_spend_privkey, sp_core_spend_pubkey);

    // 2. construct image proof
    SpImageProofV1 sp_image_proof;
    make_v1_image_proof_v1(input_proposal.m_core,
        proposal_prefix,
        sp_spend_privkey,
        sp_image_proof);

    // 3. finalize the partial input
    make_v1_partial_input_v1(input_proposal,
        proposal_prefix,
        std::move(sp_image_proof),
        sp_core_spend_pubkey,
        partial_input_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_partial_inputs_v1(const std::vector<SpInputProposalV1> &input_proposals,
    const rct::key &proposal_prefix,
    const crypto::secret_key &sp_spend_privkey,
    std::vector<SpPartialInputV1> &partial_inputs_out)
{
    partial_inputs_out.clear();
    partial_inputs_out.reserve(input_proposals.size());

    // make all inputs
    for (const SpInputProposalV1 &input_proposal : input_proposals)
    {
        make_v1_partial_input_v1(input_proposal,
            proposal_prefix,
            sp_spend_privkey,
            tools::add_element(partial_inputs_out));
    }
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp

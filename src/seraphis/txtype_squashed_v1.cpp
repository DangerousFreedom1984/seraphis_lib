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

//paired header
#include "txtype_squashed_v1.h"

//local headers
#include "cryptonote_config.h"
#include "seraphis_config_temp.h"
#include "misc_log_ex.h"
#include "mock_ledger_context.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/multiexp.h"
#include "ringct/rctTypes.h"
#include "sp_core_enote_utils.h"
#include "sp_core_types.h"
#include "sp_crypto_utils.h"
#include "sp_hash_functions.h"
#include "sp_multiexp.h"
#include "sp_transcript.h"
#include "tx_binned_reference_set.h"
#include "tx_builder_types.h"
#include "tx_builders_inputs.h"
#include "tx_builders_legacy_inputs.h"
#include "tx_builders_mixed.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"
#include "tx_discretized_fee.h"
#include "tx_legacy_component_types.h"
#include "tx_misc_utils.h"
#include "tx_validation_context.h"
#include "tx_validators.h"

//third party headers

//standard headers
#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpTxSquashedV1::get_size_bytes(const std::size_t num_legacy_inputs,
    const std::size_t num_sp_inputs,
    const std::size_t num_outputs,
    const std::size_t legacy_ring_size,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const std::size_t num_bin_members,
    const TxExtra &tx_extra)
{
    // size of the transaction as represented in C++ (it is likely ~5-15% smaller when serialized)
    // note: configs and derived data that are cached post-deserialization are NOT included (e.g. binned reference set
    //       config and seed)
    std::size_t size{0};

    // legacy input images
    size += num_legacy_inputs * LegacyEnoteImageV2::get_size_bytes();

    // seraphis input images
    size += num_sp_inputs * SpEnoteImageV1::get_size_bytes();

    // outputs
    size += num_outputs * SpEnoteV1::get_size_bytes();

    // balance proof (note: only seraphis inputs are range proofed)
    size += SpBalanceProofV1::get_size_bytes(num_sp_inputs, num_outputs);

    // legacy ring signatures
    size += num_legacy_inputs * LegacyRingSignatureV3::get_size_bytes(legacy_ring_size);

    // ownership/key-image-legitimacy proof for all seraphis inputs
    size += num_sp_inputs * SpImageProofV1::get_size_bytes();

    // membership proofs for seraphis inputs
    size += num_sp_inputs * SpMembershipProofV1::get_size_bytes(ref_set_decomp_n, ref_set_decomp_m, num_bin_members);

    // extra data in tx
    size += SpTxSupplementV1::get_size_bytes(num_outputs, tx_extra);

    // tx fee
    size += DiscretizedFee::get_size_bytes();

    return size;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpTxSquashedV1::get_size_bytes() const
{
    const std::size_t legacy_ring_size{
            m_legacy_ring_signatures.size()
            ? m_legacy_ring_signatures[0].m_reference_set.size()
            : 0
        };
    const std::size_t ref_set_decomp_n{
            m_sp_membership_proofs.size()
            ? m_sp_membership_proofs[0].m_ref_set_decomp_n
            : 0
        };
    const std::size_t ref_set_decomp_m{
            m_sp_membership_proofs.size()
            ? m_sp_membership_proofs[0].m_ref_set_decomp_m
            : 0
        };
    const std::size_t num_bin_members{
            m_sp_membership_proofs.size()
            ? m_sp_membership_proofs[0].m_binned_reference_set.m_bin_config.m_num_bin_members
            : 0u
        };

    return SpTxSquashedV1::get_size_bytes(m_legacy_input_images.size(),
        m_sp_input_images.size(),
        m_outputs.size(),
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        num_bin_members,
        m_tx_supplement.m_tx_extra);
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpTxSquashedV1::get_weight(const std::size_t num_legacy_inputs,
    const std::size_t num_sp_inputs,
    const std::size_t num_outputs,
    const std::size_t legacy_ring_size,
    const std::size_t ref_set_decomp_n,
    const std::size_t ref_set_decomp_m,
    const std::size_t num_bin_members,
    const TxExtra &tx_extra)
{
    // tx weight = tx size + balance proof clawback
    std::size_t weight{
            SpTxSquashedV1::get_size_bytes(num_legacy_inputs,
                num_sp_inputs,
                num_outputs,
                legacy_ring_size,
                ref_set_decomp_n,
                ref_set_decomp_m,
                num_bin_members,
                tx_extra)
        };

    // subtract balance proof size and add its weight
    weight -= SpBalanceProofV1::get_size_bytes(num_sp_inputs, num_outputs);
    weight += SpBalanceProofV1::get_weight(num_sp_inputs, num_outputs);

    return weight;
}
//-------------------------------------------------------------------------------------------------------------------
std::size_t SpTxSquashedV1::get_weight() const
{
    const std::size_t legacy_ring_size{
            m_legacy_ring_signatures.size()
            ? m_legacy_ring_signatures[0].m_reference_set.size()
            : 0
        };
    const std::size_t ref_set_decomp_n{
            m_sp_membership_proofs.size()
            ? m_sp_membership_proofs[0].m_ref_set_decomp_n
            : 0
        };
    const std::size_t ref_set_decomp_m{
            m_sp_membership_proofs.size()
            ? m_sp_membership_proofs[0].m_ref_set_decomp_m
            : 0
        };
    const std::size_t num_bin_members{
            m_sp_membership_proofs.size()
            ? m_sp_membership_proofs[0].m_binned_reference_set.m_bin_config.m_num_bin_members
            : 0u
        };

    return SpTxSquashedV1::get_weight(m_legacy_input_images.size(),
        m_sp_input_images.size(),
        m_outputs.size(),
        legacy_ring_size,
        ref_set_decomp_n,
        ref_set_decomp_m,
        num_bin_members,
        m_tx_supplement.m_tx_extra);
}
//-------------------------------------------------------------------------------------------------------------------
void SpTxSquashedV1::get_hash(rct::key &tx_hash_out) const
{
    // tx_hash = H_32(tx_proposal_prefix, input images, proofs)

    // 1. tx proposal
    // H_32(crypto project name, version string, legacy input key images, sp input key images, output enotes,
    //        tx supplement, fee)
    std::string version_string;
    version_string.reserve(3);
    make_versioning_string(m_tx_semantic_rules_version, version_string);

    rct::key tx_proposal_prefix;
    make_tx_proposal_prefix_v1(version_string,
        m_legacy_input_images,
        m_sp_input_images,
        m_outputs,
        m_tx_supplement,
        m_tx_fee,
        tx_proposal_prefix);

    // 2. input images (note: key images are represented in the tx hash twice (image proofs message and input images))
    // H_32({C", KI}((legacy)), {K", C", KI})
    rct::key input_images_prefix;
    make_input_images_prefix_v1(m_legacy_input_images, m_sp_input_images, input_images_prefix);

    // 3. proofs
    // H_32(balance proof, image proofs, membership proofs)
    rct::key tx_proofs_prefix;
    make_tx_proofs_prefix_v1(m_balance_proof,
        m_legacy_ring_signatures,
        m_sp_image_proofs,
        m_sp_membership_proofs,
        tx_proofs_prefix);

    // 4. tx hash
    // tx_hash = H_32(tx_proposal_prefix, input images, proofs)
    SpFSTranscript transcript{config::HASH_KEY_SERAPHIS_TRANSACTION_TYPE_SQUASHED_V1, 3*sizeof(rct::key)};
    transcript.append("tx_proposal_prefix", tx_proposal_prefix);
    transcript.append("input_images_prefix", input_images_prefix);
    transcript.append("tx_proofs_prefix", tx_proofs_prefix);

    sp_hash_to_32(transcript, tx_hash_out.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_squashed_v1(const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    std::vector<LegacyEnoteImageV2> legacy_input_images,
    std::vector<SpEnoteImageV1> sp_input_images,
    std::vector<SpEnoteV1> outputs,
    SpBalanceProofV1 balance_proof,
    std::vector<LegacyRingSignatureV3> legacy_ring_signatures,
    std::vector<SpImageProofV1> sp_image_proofs,
    std::vector<SpMembershipProofV1> sp_membership_proofs,
    SpTxSupplementV1 tx_supplement,
    const DiscretizedFee &discretized_transaction_fee,
    SpTxSquashedV1 &tx_out)
{
    tx_out.m_tx_semantic_rules_version = semantic_rules_version;
    tx_out.m_legacy_input_images = std::move(legacy_input_images);
    tx_out.m_sp_input_images = std::move(sp_input_images);
    tx_out.m_outputs = std::move(outputs);
    tx_out.m_balance_proof = std::move(balance_proof);
    tx_out.m_legacy_ring_signatures = std::move(legacy_ring_signatures);
    tx_out.m_sp_image_proofs = std::move(sp_image_proofs);
    tx_out.m_sp_membership_proofs = std::move(sp_membership_proofs);
    tx_out.m_tx_supplement = std::move(tx_supplement);
    tx_out.m_tx_fee = discretized_transaction_fee;

    CHECK_AND_ASSERT_THROW_MES(validate_tx_semantics(tx_out), "Failed to assemble an SpTxSquashedV1.");
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_squashed_v1(const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    SpPartialTxV1 partial_tx,
    std::vector<SpMembershipProofV1> sp_membership_proofs,
    SpTxSquashedV1 &tx_out)
{
    // check partial tx semantics
    check_v1_partial_tx_semantics_v1(partial_tx, semantic_rules_version);

    // note: seraphis membership proofs cannot be validated without the ledger used to construct them, so there is no
    //       check here

    // finish tx
    make_seraphis_tx_squashed_v1(semantic_rules_version,
        std::move(partial_tx.m_legacy_input_images),
        std::move(partial_tx.m_sp_input_images),
        std::move(partial_tx.m_outputs),
        std::move(partial_tx.m_balance_proof),
        std::move(partial_tx.m_legacy_ring_signatures),
        std::move(partial_tx.m_sp_image_proofs),
        std::move(sp_membership_proofs),
        std::move(partial_tx.m_tx_supplement),
        partial_tx.m_tx_fee,
        tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_squashed_v1(const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    SpPartialTxV1 partial_tx,
    std::vector<SpAlignableMembershipProofV1> alignable_membership_proofs,
    SpTxSquashedV1 &tx_out)
{
    // line up the the membership proofs with the partial tx's input images (which are sorted)
    std::vector<SpMembershipProofV1> tx_membership_proofs;
    align_v1_membership_proofs_v1(partial_tx.m_sp_input_images,
        std::move(alignable_membership_proofs),
        tx_membership_proofs);

    // finish tx
    make_seraphis_tx_squashed_v1(semantic_rules_version, std::move(partial_tx), std::move(tx_membership_proofs), tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_squashed_v1(const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    const SpTxProposalV1 &tx_proposal,
    std::vector<LegacyInputV1> legacy_inputs,
    std::vector<SpPartialInputV1> sp_partial_inputs,
    std::vector<SpMembershipProofPrepV1> sp_membership_proof_preps,
    const rct::key &legacy_spend_pubkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpTxSquashedV1 &tx_out)
{
    // versioning for proofs
    std::string version_string;
    version_string.reserve(3);
    make_versioning_string(semantic_rules_version, version_string);

    // partial tx
    SpPartialTxV1 partial_tx;
    make_v1_partial_tx_v1(tx_proposal,
        std::move(legacy_inputs),
        std::move(sp_partial_inputs),
        version_string,
        legacy_spend_pubkey,
        jamtis_spend_pubkey,
        k_view_balance,
        partial_tx);

    // seraphis membership proofs (assumes the caller prepared to make a membership proof for each input)
    std::vector<SpAlignableMembershipProofV1> alignable_membership_proofs;
    make_v1_membership_proofs_v1(std::move(sp_membership_proof_preps), alignable_membership_proofs);

    // finish tx
    make_seraphis_tx_squashed_v1(semantic_rules_version,
        std::move(partial_tx),
        std::move(alignable_membership_proofs),
        tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_squashed_v1(const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    const SpTxProposalV1 &tx_proposal,
    std::vector<LegacyRingSignaturePrepV1> legacy_ring_signature_preps,
    std::vector<SpMembershipProofPrepV1> sp_membership_proof_preps,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    SpTxSquashedV1 &tx_out)
{
    // versioning for proofs
    std::string version_string;
    version_string.reserve(3);
    make_versioning_string(semantic_rules_version, version_string);

    // tx proposal prefix
    rct::key proposal_prefix;
    tx_proposal.get_proposal_prefix(version_string, k_view_balance, proposal_prefix);

    // legacy inputs
    std::vector<LegacyInputV1> legacy_inputs;

    make_v1_legacy_inputs_v1(proposal_prefix,
        tx_proposal.m_legacy_input_proposals,
        std::move(legacy_ring_signature_preps),
        legacy_spend_privkey,
        legacy_inputs);

    // seraphis partial inputs
    std::vector<SpPartialInputV1> sp_partial_inputs;
    make_v1_partial_inputs_v1(tx_proposal.m_sp_input_proposals, proposal_prefix, sp_spend_privkey, sp_partial_inputs);

    // legacy spend pubkey
    const rct::key legacy_spend_pubkey{rct::scalarmultBase(rct::sk2rct(legacy_spend_privkey))};

    // jamtis spend pubkey
    rct::key jamtis_spend_pubkey;
    make_seraphis_spendkey(k_view_balance, sp_spend_privkey, jamtis_spend_pubkey);

    // finish tx
    make_seraphis_tx_squashed_v1(semantic_rules_version,
        tx_proposal,
        std::move(legacy_inputs),
        std::move(sp_partial_inputs),
        std::move(sp_membership_proof_preps),
        legacy_spend_pubkey,
        jamtis_spend_pubkey,
        k_view_balance,
        tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
void make_seraphis_tx_squashed_v1(const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    const DiscretizedFee &tx_fee,
    std::vector<LegacyInputProposalV1> legacy_input_proposals,
    std::vector<SpInputProposalV1> sp_input_proposals,
    std::vector<ExtraFieldElement> additional_memo_elements,
    std::vector<LegacyRingSignaturePrepV1> legacy_ring_signature_preps,
    std::vector<SpMembershipProofPrepV1> sp_membership_proof_preps,
    const crypto::secret_key &legacy_spend_privkey,
    const crypto::secret_key &sp_spend_privkey,
    const crypto::secret_key &k_view_balance,
    SpTxSquashedV1 &tx_out)
{
    // tx proposal
    SpTxProposalV1 tx_proposal;
    make_v1_tx_proposal_v1(std::move(normal_payment_proposals),
        std::move(selfsend_payment_proposals),
        tx_fee,
        std::move(legacy_input_proposals),
        std::move(sp_input_proposals),
        std::move(additional_memo_elements),
        tx_proposal);

    // finish tx
    make_seraphis_tx_squashed_v1(semantic_rules_version,
        tx_proposal,
        std::move(legacy_ring_signature_preps),
        std::move(sp_membership_proof_preps),
        legacy_spend_privkey,
        sp_spend_privkey,
        k_view_balance,
        tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
SemanticConfigComponentCountsV1 semantic_config_component_counts_v1(
    const SpTxSquashedV1::SemanticRulesVersion tx_semantic_rules_version)
{
    SemanticConfigComponentCountsV1 config{};

    // note: in the squashed model, inputs + outputs must be <= the BP+ pre-generated generator array size ('maxM')
    if (tx_semantic_rules_version == SpTxSquashedV1::SemanticRulesVersion::MOCK)
    {
        config.m_min_inputs = 1;
        config.m_max_inputs = 100000;
        config.m_min_outputs = 1;
        config.m_max_outputs = 100000;
    }
    else if (tx_semantic_rules_version == SpTxSquashedV1::SemanticRulesVersion::ONE)
    {
        config.m_min_inputs = 1;
        config.m_max_inputs = config::SP_MAX_INPUTS_V1;
        config.m_min_outputs = 2;
        config.m_max_outputs = config::SP_MAX_OUTPUTS_V1;
    }
    else  //unknown semantic rules version
    {
        CHECK_AND_ASSERT_THROW_MES(false, "Tried to get semantic config for component counts with unknown rules version.");
    }

    return config;
}
//-------------------------------------------------------------------------------------------------------------------
SemanticConfigLegacyRefSetV1 semantic_config_legacy_ref_sets_v1(
    const SpTxSquashedV1::SemanticRulesVersion tx_semantic_rules_version)
{
    SemanticConfigLegacyRefSetV1 config{};

    if (tx_semantic_rules_version == SpTxSquashedV1::SemanticRulesVersion::MOCK)
    {
        config.m_ring_size_min = 1;
        config.m_ring_size_max = 1000;
    }
    else if (tx_semantic_rules_version == SpTxSquashedV1::SemanticRulesVersion::ONE)
    {
        config.m_ring_size_min = config::LEGACY_RING_SIZE_V1;
        config.m_ring_size_max = config::LEGACY_RING_SIZE_V1;
    }
    else  //unknown semantic rules version
    {
        CHECK_AND_ASSERT_THROW_MES(false,
            "Tried to get semantic config for legacy ref set sizes with unknown rules version.");
    }

    return config;
}
//-------------------------------------------------------------------------------------------------------------------
SemanticConfigSpRefSetV1 semantic_config_sp_ref_sets_v1(const SpTxSquashedV1::SemanticRulesVersion tx_semantic_rules_version)
{
    SemanticConfigSpRefSetV1 config{};

    if (tx_semantic_rules_version == SpTxSquashedV1::SemanticRulesVersion::MOCK)
    {
        // note: if n*m exceeds GROOTLE_MAX_MN, an exception will be thrown
        config.m_decomp_n_min = 2;
        config.m_decomp_n_max = 100000;
        config.m_decomp_m_min = 2;
        config.m_decomp_m_max = 100000;
        config.m_bin_radius_min = 0;
        config.m_bin_radius_max = 30000;
        config.m_num_bin_members_min = 1;
        config.m_num_bin_members_max = 60000;
    }
    else if (tx_semantic_rules_version == SpTxSquashedV1::SemanticRulesVersion::ONE)
    {
        config.m_decomp_n_min = config::SP_GROOTLE_N_V1;
        config.m_decomp_n_max = config::SP_GROOTLE_N_V1;
        config.m_decomp_m_min = config::SP_GROOTLE_M_V1;
        config.m_decomp_m_max = config::SP_GROOTLE_M_V1;
        config.m_bin_radius_min = config::SP_REF_SET_BIN_RADIUS_V1;
        config.m_bin_radius_max = config::SP_REF_SET_BIN_RADIUS_V1;
        config.m_num_bin_members_min = config::SP_REF_SET_NUM_BIN_MEMBERS_V1;
        config.m_num_bin_members_max = config::SP_REF_SET_NUM_BIN_MEMBERS_V1;
    }
    else  //unknown semantic rules version
    {
        CHECK_AND_ASSERT_THROW_MES(false, "Tried to get semantic config for ref set sizes with unknown rules version.");
    }

    return config;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_semantics<SpTxSquashedV1>(const SpTxSquashedV1 &tx)
{
    // validate component counts (num inputs/outputs/etc.)
    if (!validate_sp_semantics_component_counts_v1(semantic_config_component_counts_v1(tx.m_tx_semantic_rules_version),
            tx.m_legacy_input_images.size(),
            tx.m_sp_input_images.size(),
            tx.m_legacy_ring_signatures.size(),
            tx.m_sp_membership_proofs.size(),
            tx.m_sp_image_proofs.size(),
            tx.m_outputs.size(),
            tx.m_tx_supplement.m_output_enote_ephemeral_pubkeys.size(),
            tx.m_balance_proof.m_bpp2_proof.V.size()))
        return false;

    // validate legacy input proof reference set sizes
    if (!validate_sp_semantics_legacy_reference_sets_v1(semantic_config_legacy_ref_sets_v1(tx.m_tx_semantic_rules_version),
            tx.m_legacy_ring_signatures))
        return false;

    // validate seraphis input proof reference set sizes
    if (!validate_sp_semantics_sp_reference_sets_v1(semantic_config_sp_ref_sets_v1(tx.m_tx_semantic_rules_version),
            tx.m_sp_membership_proofs))
        return false;

    // validate output serialization semantics
    if (!validate_sp_semantics_output_serialization_v1(tx.m_outputs, tx.m_tx_supplement))
        return false;

    // validate input image semantics
    if (!validate_sp_semantics_input_images_v1(tx.m_legacy_input_images, tx.m_sp_input_images))
        return false;

    // validate layout (sorting, uniqueness) of input images, membership proof ref sets, outputs, and tx supplement
    if (!validate_sp_semantics_layout_v1(tx.m_legacy_ring_signatures,
            tx.m_sp_membership_proofs,
            tx.m_legacy_input_images,
            tx.m_sp_input_images,
            tx.m_outputs,
            tx.m_tx_supplement.m_output_enote_ephemeral_pubkeys,
            tx.m_tx_supplement.m_tx_extra))
        return false;

    // validate the tx fee is well-formed
    if (!validate_sp_semantics_fee_v1(tx.m_tx_fee))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_linking_tags<SpTxSquashedV1>(const SpTxSquashedV1 &tx, const TxValidationContext &tx_validation_context)
{
    // unspentness proof (key images not in ledger)
    if (!validate_sp_linking_tags_v1(tx.m_legacy_input_images, tx.m_sp_input_images, tx_validation_context))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_amount_balance<SpTxSquashedV1>(const SpTxSquashedV1 &tx)
{
    // balance proof
    if (!validate_sp_amount_balance_v1(tx.m_legacy_input_images,
            tx.m_sp_input_images,
            tx.m_outputs,
            tx.m_tx_fee,
            tx.m_balance_proof))
        return false;

    // deferred for batching: range proofs

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_tx_input_proofs<SpTxSquashedV1>(const SpTxSquashedV1 &tx, const TxValidationContext &tx_validation_context)
{
    // seraphis membership proofs: deferred for batching

    // prepare image proofs message
    std::string version_string;
    version_string.reserve(3);
    make_versioning_string(tx.m_tx_semantic_rules_version, version_string);

    rct::key tx_proposal_prefix;
    make_tx_proposal_prefix_v1(version_string,
        tx.m_legacy_input_images,
        tx.m_sp_input_images,
        tx.m_outputs,
        tx.m_tx_supplement,
        tx.m_tx_fee,
        tx_proposal_prefix);

    // ownership, membership, and key image validity of legacy inputs
    if (!validate_sp_legacy_input_proofs_v1(tx.m_legacy_ring_signatures,
            tx.m_legacy_input_images,
            tx_proposal_prefix,
            tx_validation_context))
        return false;

    // ownership proof (and proof that key images are well-formed)
    if (!validate_sp_composition_proofs_v1(tx.m_sp_image_proofs, tx.m_sp_input_images, tx_proposal_prefix))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
bool validate_txs_batchable<SpTxSquashedV1>(const std::vector<const SpTxSquashedV1*> &txs,
    const TxValidationContext &tx_validation_context)
{
    std::vector<const SpMembershipProofV1*> sp_membership_proof_ptrs;
    std::vector<const SpEnoteImage*> sp_input_image_ptrs;
    std::vector<const BulletproofPlus2*> range_proof_ptrs;
    sp_membership_proof_ptrs.reserve(txs.size()*20);  //heuristic... (most tx have 1-2 seraphis inputs)
    sp_input_image_ptrs.reserve(txs.size()*20);
    range_proof_ptrs.reserve(txs.size());

    // prepare for batch-verification
    for (const SpTxSquashedV1 *tx : txs)
    {
        if (!tx)
            return false;

        // gather membership proof pieces
        for (const auto &sp_membership_proof : tx->m_sp_membership_proofs)
            sp_membership_proof_ptrs.push_back(&sp_membership_proof);

        for (const auto &sp_input_image : tx->m_sp_input_images)
            sp_input_image_ptrs.push_back(&(sp_input_image.m_core));

        // gather range proofs
        range_proof_ptrs.push_back(&(tx->m_balance_proof.m_bpp2_proof));
    }

    // batch verification: collect pippenger data sets for an aggregated multiexponentiation

    // seraphis membership proofs
    std::list<SpMultiexpBuilder> validation_data_sp_membership_proofs;
    if (!try_get_sp_membership_proofs_v1_validation_data(sp_membership_proof_ptrs,
            sp_input_image_ptrs,
            tx_validation_context,
            validation_data_sp_membership_proofs))
        return false;

    // range proofs
    std::list<SpMultiexpBuilder> validation_data_range_proofs;
    if (!try_get_bulletproof_plus2_verification_data(range_proof_ptrs, validation_data_range_proofs))
        return false;

    // batch verify
    std::list<SpMultiexpBuilder> validation_data{std::move(validation_data_sp_membership_proofs)};
    validation_data.splice(validation_data.end(), validation_data_range_proofs);

    if (!SpMultiexp{validation_data}.evaluates_to_point_at_infinity())
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
template <>
void make_mock_tx<SpTxSquashedV1>(const SpTxParamPackV1 &params,
    const std::vector<rct::xmr_amount> &legacy_in_amounts,
    const std::vector<rct::xmr_amount> &sp_in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts,
    const DiscretizedFee &tx_fee,
    MockLedgerContext &ledger_context_inout,
    SpTxSquashedV1 &tx_out)
{
    CHECK_AND_ASSERT_THROW_MES(legacy_in_amounts.size() + sp_in_amounts.size() > 0,
        "SpTxSquashedV1: tried to make mock tx without any inputs.");
    CHECK_AND_ASSERT_THROW_MES(out_amounts.size() > 0, "SpTxSquashedV1: tried to make mock tx without any outputs.");

    // mock semantics version
    const SpTxSquashedV1::SemanticRulesVersion semantic_rules_version{SpTxSquashedV1::SemanticRulesVersion::MOCK};

    // make legacy spend privkey
    const crypto::secret_key legacy_spend_privkey{rct::rct2sk(rct::skGen())};

    // make seraphis spendbase privkey (master key)
    const crypto::secret_key sp_spend_privkey{rct::rct2sk(rct::skGen())};

    // make mock legacy inputs
    std::vector<LegacyInputProposalV1> legacy_input_proposals{
            gen_mock_legacy_input_proposals_v1(legacy_spend_privkey, legacy_in_amounts)
        };
    std::sort(legacy_input_proposals.begin(), legacy_input_proposals.end());

    // make mock seraphis inputs
    std::vector<SpInputProposalV1> sp_input_proposals{gen_mock_sp_input_proposals_v1(sp_spend_privkey, sp_in_amounts)};
    std::sort(sp_input_proposals.begin(), sp_input_proposals.end());

    // make mock outputs
    std::vector<SpOutputProposalV1> output_proposals{
            gen_mock_sp_output_proposals_v1(out_amounts, params.num_random_memo_elements)
        };

    // for 2-out tx, the enote ephemeral pubkey is shared by both outputs
    if (output_proposals.size() == 2)
        output_proposals[1].m_enote_ephemeral_pubkey = output_proposals[0].m_enote_ephemeral_pubkey;

    // expect amounts to balance
    CHECK_AND_ASSERT_THROW_MES(balance_check_in_out_amnts_v1(legacy_input_proposals,
            sp_input_proposals,
            output_proposals,
            tx_fee),
        "SpTxSquashedV1: tried to make mock tx with unbalanced amounts.");

    // make partial memo
    std::vector<ExtraFieldElement> additional_memo_elements;
    additional_memo_elements.resize(params.num_random_memo_elements);

    for (ExtraFieldElement &element : additional_memo_elements)
        element.gen();

    TxExtra partial_memo;
    make_tx_extra(std::move(additional_memo_elements), partial_memo);

    // versioning for proofs
    std::string version_string;
    version_string.reserve(3);
    make_versioning_string(semantic_rules_version, version_string);

    // proposal prefix
    rct::key proposal_prefix;
    make_tx_proposal_prefix_v1(version_string,
        legacy_input_proposals,
        sp_input_proposals,
        output_proposals,
        partial_memo,
        tx_fee,
        proposal_prefix);

    // make legacy ring signature preps
    std::vector<LegacyRingSignaturePrepV1> legacy_ring_signature_preps{
            gen_mock_legacy_ring_signature_preps_v1(proposal_prefix,
                legacy_input_proposals,
                params.legacy_ring_size,
                ledger_context_inout)
        };
    std::sort(legacy_ring_signature_preps.begin(), legacy_ring_signature_preps.end());

    // make legacy inputs
    std::vector<LegacyInputV1> legacy_inputs;

    make_v1_legacy_inputs_v1(proposal_prefix,
        legacy_input_proposals,
        std::move(legacy_ring_signature_preps),
        legacy_spend_privkey,
        legacy_inputs);
    std::sort(legacy_inputs.begin(), legacy_inputs.end());

    // make seraphis partial inputs
    std::vector<SpPartialInputV1> sp_partial_inputs;

    make_v1_partial_inputs_v1(sp_input_proposals, proposal_prefix, sp_spend_privkey, sp_partial_inputs);
    std::sort(sp_partial_inputs.begin(), sp_partial_inputs.end());

    // prepare partial tx
    SpPartialTxV1 partial_tx;

    make_v1_partial_tx_v1(std::move(legacy_inputs),
        std::move(sp_partial_inputs),
        std::move(output_proposals),
        partial_memo,
        tx_fee,
        version_string,
        partial_tx);

    // make mock seraphis membership proof ref sets
    std::vector<SpMembershipProofPrepV1> sp_membership_proof_preps{
            gen_mock_sp_membership_proof_preps_v1(sp_input_proposals,
                params.ref_set_decomp_n,
                params.ref_set_decomp_m,
                params.bin_config,
                ledger_context_inout)
        };

    // seraphis membership proofs (assumes the caller prepared to make a membership proof for each input)
    std::vector<SpAlignableMembershipProofV1> sp_alignable_membership_proofs;
    make_v1_membership_proofs_v1(std::move(sp_membership_proof_preps), sp_alignable_membership_proofs);

    // make tx
    make_seraphis_tx_squashed_v1(semantic_rules_version,
        std::move(partial_tx),
        std::move(sp_alignable_membership_proofs),
        tx_out);
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp

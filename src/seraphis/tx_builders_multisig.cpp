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
#include "tx_builders_multisig.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "crypto/generators.h"
#include "jamtis_address_utils.h"
#include "jamtis_core_utils.h"
#include "jamtis_enote_utils.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "multisig/multisig_signer_set_filter.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_config_temp.h"
#include "sp_core_enote_utils.h"
#include "sp_crypto_utils.h"
#include "sp_multisig_nonce_record.h"
#include "tx_builder_types.h"
#include "tx_builder_types_multisig.h"
#include "tx_builders_mixed.h"
#include "tx_builders_outputs.h"
#include "tx_component_types.h"
#include "tx_contextual_enote_record_utils.h"
#include "tx_discretized_fee.h"
#include "tx_enote_record_types.h"
#include "tx_enote_record_utils.h"
#include "tx_input_selection_output_context_v1.h"
#include "tx_misc_utils.h"

//third party headers
#include <boost/math/special_functions/binomial.hpp>
#include "boost/multiprecision/cpp_int.hpp"

//standard headers
#include <unordered_map>
#include <unordered_set>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//----------------------------------------------------------------------------------------------------------------------
// TODO: move to a 'math' library, with unit tests
//----------------------------------------------------------------------------------------------------------------------
static std::uint32_t n_choose_k(const std::uint32_t n, const std::uint32_t k)
{
    static_assert(std::numeric_limits<std::int32_t>::digits <= std::numeric_limits<double>::digits,
        "n_choose_k requires no rounding issues when converting between int32 <-> double.");

    if (n < k)
        return 0;

    double fp_result = boost::math::binomial_coefficient<double>(n, k);

    if (fp_result < 0)
        return 0;

    if (fp_result > std::numeric_limits<std::int32_t>::max())  // note: std::round() returns std::int32_t
        return 0;

    return static_cast<std::uint32_t>(std::round(fp_result));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool validate_v1_multisig_input_init_set_for_partial_sig_set_v1(const SpMultisigInputInitSetV1 &input_init_set,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &expected_proposal_prefix,
    const multisig::signer_set_filter expected_aggregate_signer_set_filter,
    const std::vector<rct::key> &expected_masked_addresses)
{
    // signer in signer list
    if (std::find(multisig_signers.begin(), multisig_signers.end(), input_init_set.m_signer_id) == multisig_signers.end())
        return false;

    // proposal prefix matches expected prefix
    if (!(input_init_set.m_proposal_prefix == expected_proposal_prefix))
        return false;

    // aggregate filter matches expected aggregate filter
    if (input_init_set.m_aggregate_signer_set_filter != expected_aggregate_signer_set_filter)
        return false;

    // signer is in aggregate filter
    try
    {
        if (!multisig::signer_is_in_filter(input_init_set.m_signer_id,
                multisig_signers,
                expected_aggregate_signer_set_filter))
            return false;
    }
    catch (...) { return false; }

    // masked addresses in init set line up 1:1 with expected masked addresses
    if (input_init_set.m_input_inits.size() != expected_masked_addresses.size())
        return false;

    for (const rct::key &masked_address : expected_masked_addresses)
    {
        if (input_init_set.m_input_inits.find(masked_address) == input_init_set.m_input_inits.end())
            return false;
    }

    // init set semantics must be valid
    try { check_v1_multisig_input_init_set_semantics_v1(input_init_set, threshold, multisig_signers); }
    catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void get_masked_addresses(const std::vector<SpInputProposalV1> &plain_input_proposals,
    rct::keyV &masked_addresses_out)
{
    masked_addresses_out.clear();
    masked_addresses_out.reserve(plain_input_proposals.size());
    SpEnoteImageV1 enote_image_temp;

    for (const SpInputProposalV1 &input_proposal : plain_input_proposals)
    {
        input_proposal.get_enote_image_v1(enote_image_temp);
        masked_addresses_out.emplace_back(enote_image_temp.m_core.m_masked_address);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void validate_and_prepare_input_inits_for_partial_sig_sets_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const crypto::public_key &local_signer_id,
    const rct::keyV &input_masked_addresses,
    const rct::key &proposal_prefix,
    const SpMultisigInputInitSetV1 &local_input_init_set,
    std::vector<SpMultisigInputInitSetV1> other_input_init_sets,
    std::vector<SpMultisigInputInitSetV1> &all_input_init_sets_out)
{
    /// validate and filter input inits

    // 1. local input init set must be valid
    CHECK_AND_ASSERT_THROW_MES(local_input_init_set.m_signer_id == local_signer_id,
        "multisig input partial sigs: local input init set is not from local signer.");
    CHECK_AND_ASSERT_THROW_MES(validate_v1_multisig_input_init_set_for_partial_sig_set_v1(
            local_input_init_set,
            threshold,
            multisig_signers,
            proposal_prefix,
            multisig_tx_proposal.m_aggregate_signer_set_filter,
            input_masked_addresses),
        "multisig input partial sigs: the local signer's input initializer doesn't match the multisig tx proposal.");

    // 2. weed out invalid other input init sets
    auto removed_end = std::remove_if(other_input_init_sets.begin(), other_input_init_sets.end(),
            [&](const SpMultisigInputInitSetV1 &other_input_init_set) -> bool
            {
                return !validate_v1_multisig_input_init_set_for_partial_sig_set_v1(
                    other_input_init_set,
                    threshold,
                    multisig_signers,
                    proposal_prefix,
                    multisig_tx_proposal.m_aggregate_signer_set_filter,
                    input_masked_addresses);
            }
        );
    other_input_init_sets.erase(removed_end, other_input_init_sets.end());

    // 3. collect all input init sets
    all_input_init_sets_out = std::move(other_input_init_sets);
    all_input_init_sets_out.emplace_back(local_input_init_set);

    // 4. remove inits from duplicate signers (including duplicate local signer inits)
    std::sort(all_input_init_sets_out.begin(), all_input_init_sets_out.end(),
            [](const SpMultisigInputInitSetV1 &set1, const SpMultisigInputInitSetV1 &set2) -> bool
            {
                return set1.m_signer_id < set2.m_signer_id;
            }
        );
    auto unique_end = std::unique(all_input_init_sets_out.begin(), all_input_init_sets_out.end(),
            [](const SpMultisigInputInitSetV1 &set1, const SpMultisigInputInitSetV1 &set2) -> bool
            {
                return set1.m_signer_id == set2.m_signer_id;
            }
        );
    all_input_init_sets_out.erase(unique_end, all_input_init_sets_out.end());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void attempt_make_v1_multisig_input_partial_sig_set_v1(const multisig::multisig_account &signer_account,
    const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const rct::key &proposal_prefix,
    const multisig::signer_set_filter filter,
    const rct::keyV &input_masked_addresses,
    const std::vector<SpMultisigInputInitSetV1> &all_input_init_sets,
    const std::vector<multisig::signer_set_filter> &available_signers_as_filters,
    const std::vector<std::size_t> &signer_nonce_trackers,
    const std::vector<crypto::secret_key> &squash_prefixes,
    const std::vector<crypto::secret_key> &enote_view_privkeys_g,
    const std::vector<crypto::secret_key> &enote_view_privkeys_x,
    const std::vector<crypto::secret_key> &enote_view_privkeys_u,
    SpMultisigNonceRecord &nonce_record_inout,
    SpMultisigInputPartialSigSetV1 &new_partial_sig_set_out)
{
    /// make partial signatures for one group of signers of size threshold that is presumed to include the local signer

    // checks
    CHECK_AND_ASSERT_THROW_MES(signer_account.multisig_is_ready(),
        "multisig input partial sigs: signer account is not complete, so it can't make partial signatures.");

    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proposals.size() == 
            multisig_tx_proposal.m_input_proof_proposals.size(),
        "multisig input partial sigs: input proposals don't line up with input proof proposals (bug).");
    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proposals.size() == enote_view_privkeys_g.size(),
        "multisig input partial sigs: input proposals don't line up with converted input proposals (bug).");
    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proposals.size() == enote_view_privkeys_x.size(),
        "multisig input partial sigs: input proposals don't line up with converted input proposals (bug).");
    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proposals.size() == enote_view_privkeys_u.size(),
        "multisig input partial sigs: input proposals don't line up with converted input proposals (bug).");
    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proposals.size() == squash_prefixes.size(),
        "multisig input partial sigs: input proposals don't line up with prepared enote squash prefixes (bug).");
    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proposals.size() == input_masked_addresses.size(),
        "multisig input partial sigs: input proposals don't line up with masked addresses (bug).");
    CHECK_AND_ASSERT_THROW_MES(available_signers_as_filters.size() == all_input_init_sets.size(),
        "multisig input partial sigs: available signers as filters don't line up with input init sets (bug).");
    CHECK_AND_ASSERT_THROW_MES(signer_nonce_trackers.size() == all_input_init_sets.size(),
        "multisig input partial sigs: signer nonce trackers don't line up with input init sets (bug).");

    // prepare 1/threshold
    CHECK_AND_ASSERT_THROW_MES(signer_account.get_threshold() > 0,
        "multisig input partial sigs: multisig threshold is zero.");
    const rct::key one_div_threshold{invert(rct::d2h(signer_account.get_threshold()))};


    /// try to make the partial sig set
    std::vector<SpMultisigPubNonces> signer_pub_nonces_temp;
    signer_pub_nonces_temp.reserve(signer_account.get_threshold());

    crypto::secret_key x_temp;
    crypto::secret_key y_temp;
    crypto::secret_key z_e_temp;

    // 1. local signer's signing key for this group
    crypto::secret_key k_b_e;
    if (!signer_account.try_get_aggregate_signing_key(filter, k_b_e))
        throw;

    // 2. make a partial signature for each input
    new_partial_sig_set_out.m_partial_signatures.reserve(input_masked_addresses.size());

    for (std::size_t input_index{0};
        input_index < multisig_tx_proposal.m_input_proposals.size();
        ++input_index)
    {
        // collect nonces from all signers in this signing group
        signer_pub_nonces_temp.clear();
        for (std::size_t signer_index{0}; signer_index < all_input_init_sets.size(); ++signer_index)
        {
            if ((available_signers_as_filters[signer_index] & filter) == 0)
                continue;

            // indexing:
            // - this signer's init set
            // - select the input we are working on (via this input's masked address)
            // - select the nonces that line up with the signer's nonce tracker
            signer_pub_nonces_temp.emplace_back();
            if (!all_input_init_sets[signer_index].try_get_nonces(input_masked_addresses[input_index],
                    signer_nonce_trackers[signer_index],
                    signer_pub_nonces_temp.back()))
                throw;
        }

        // sanity check
        if (signer_pub_nonces_temp.size() != signer_account.get_threshold())
            throw;

        // prepare x: t_k + Hn(Ko, C) * k_mask
        sc_mul(to_bytes(x_temp), to_bytes(squash_prefixes[input_index]), to_bytes(enote_view_privkeys_g[input_index]));
        sc_add(to_bytes(x_temp),
            to_bytes(multisig_tx_proposal.m_input_proposals[input_index].m_address_mask),
            to_bytes(x_temp));

        // prepare y: Hn(Ko, C) * k_a
        sc_mul(to_bytes(y_temp), to_bytes(squash_prefixes[input_index]), to_bytes(enote_view_privkeys_x[input_index]));

        // prepare z_e: Hn(Ko, C) * ((1/threshold)*k_view_u + k_b_e)
        // note: each signer adds (1/threshold)*k_view_u so the sum works out
        sc_mul(to_bytes(z_e_temp), one_div_threshold.bytes, to_bytes(enote_view_privkeys_u[input_index]));
        sc_add(to_bytes(z_e_temp), to_bytes(z_e_temp), to_bytes(k_b_e));
        sc_mul(to_bytes(z_e_temp), to_bytes(squash_prefixes[input_index]), to_bytes(z_e_temp));

        // local signer's partial sig for this input
        new_partial_sig_set_out.m_partial_signatures.emplace_back();

        if (!try_make_sp_composition_multisig_partial_sig(
                multisig_tx_proposal.m_input_proof_proposals[input_index],
                x_temp,
                y_temp,
                z_e_temp,
                signer_pub_nonces_temp,
                filter,
                nonce_record_inout,
                new_partial_sig_set_out.m_partial_signatures.back()))
            throw;
    }

    // 3. copy miscellanea
    new_partial_sig_set_out.m_signer_id = signer_account.get_base_pubkey();  //local signer
    new_partial_sig_set_out.m_proposal_prefix = proposal_prefix;
    new_partial_sig_set_out.m_signer_set_filter = filter;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_v1_multisig_input_partial_sig_sets_v1(const multisig::multisig_account &signer_account,
    const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const rct::key &proposal_prefix,
    const rct::keyV &input_masked_addresses,
    const std::vector<multisig::signer_set_filter> &filter_permutations,
    const multisig::signer_set_filter local_signer_filter,
    const std::vector<crypto::public_key> &available_signers,
    const std::vector<SpMultisigInputInitSetV1> &all_input_init_sets,
    const multisig::signer_set_filter available_signers_filter,
    const std::vector<multisig::signer_set_filter> &available_signers_as_filters,
    const std::vector<crypto::secret_key> &squash_prefixes,
    const std::vector<crypto::secret_key> &enote_view_privkeys_g,
    const std::vector<crypto::secret_key> &enote_view_privkeys_x,
    const std::vector<crypto::secret_key> &enote_view_privkeys_u,
    SpMultisigNonceRecord &nonce_record_inout,
    std::vector<SpMultisigInputPartialSigSetV1> &input_partial_sig_sets_out)
{
    /// make partial signatures for every available group of signers of size threshold that includes the local signer
    CHECK_AND_ASSERT_THROW_MES(signer_account.multisig_is_ready(),
        "make multisig input partial sigs: signer account is not complete, so it can't make partial signatures.");

    // checks
    CHECK_AND_ASSERT_THROW_MES(available_signers.size() == available_signers_as_filters.size(),
        "make multisig input partial sigs: available signers don't line up with available signers as filters (bug).");

    // signer nonce trackers are pointers into the nonce vectors in each signer's init set
    // - a signer's nonce vectors line up 1:1 with the filters in 'filter_permutations' of which the signer is a member
    // - we want to track through each signers' vectors as we go through the full set of 'filter_permutations'
    std::vector<std::size_t> signer_nonce_trackers(available_signers.size(), 0);

    const std::uint32_t expected_num_partial_sig_sets{
            n_choose_k(available_signers.size() - 1, signer_account.get_threshold() - 1)
        };
    input_partial_sig_sets_out.clear();
    input_partial_sig_sets_out.reserve(expected_num_partial_sig_sets);
    std::uint32_t num_aborted_partial_sig_sets{0};

    for (const multisig::signer_set_filter filter : filter_permutations)
    {
        // for filters that contain only available signers (and include the local signer), make a partial signature set
        // - throw on failure so the partial sig set can be rolled back
        if ((filter & available_signers_filter) == filter &&
            (filter & local_signer_filter))
        {
            // if this throws, then the signer's nonces for this filter/proposal/input_set combo that were used before
            //   the throw will be completely lost; however, if it does throw then this signing attempt was futile to
            //   begin with (all or nothing)
            input_partial_sig_sets_out.emplace_back();
            try
            {
                attempt_make_v1_multisig_input_partial_sig_set_v1(signer_account,
                    multisig_tx_proposal,
                    proposal_prefix,
                    filter,
                    input_masked_addresses,
                    all_input_init_sets,
                    available_signers_as_filters,
                    signer_nonce_trackers,
                    squash_prefixes,
                    enote_view_privkeys_g,
                    enote_view_privkeys_x,
                    enote_view_privkeys_u,
                    nonce_record_inout,
                    input_partial_sig_sets_out.back());

                // final sanity check
                check_v1_multisig_input_partial_sig_semantics_v1(input_partial_sig_sets_out.back(),
                    signer_account.get_signers());
            }
            catch (...)
            {
                input_partial_sig_sets_out.pop_back();
                ++num_aborted_partial_sig_sets;
            }
        }

        // increment nonce trackers for all signers in this filter
        for (std::size_t signer_index{0}; signer_index < available_signers.size(); ++signer_index)
        {
            if (available_signers_as_filters[signer_index] & filter)
                ++signer_nonce_trackers[signer_index];
        }
    }

    // sanity check
    CHECK_AND_ASSERT_THROW_MES(expected_num_partial_sig_sets - num_aborted_partial_sig_sets ==
            input_partial_sig_sets_out.size(),
        "make multisig input partial sigs: did not produce expected number of partial sig sets (bug).");
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_public_input_proposal_semantics_v1(const SpMultisigPublicInputProposalV1 &public_input_proposal)
{
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(public_input_proposal.m_address_mask)),
        "multisig public input proposal: bad address mask (zero).");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(public_input_proposal.m_address_mask)) == 0,
        "multisig public input proposal: bad address mask (not canonical).");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(public_input_proposal.m_commitment_mask)),
        "multisig public input proposal: bad address mask (zero).");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(public_input_proposal.m_commitment_mask)) == 0,
        "multisig public input proposal: bad address mask (not canonical).");
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_public_input_proposal_v1(const SpEnoteV1 &enote,
    const crypto::x25519_pubkey &enote_ephemeral_pubkey,
    const rct::key &input_context,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMultisigPublicInputProposalV1 &proposal_out)
{
    // add components
    proposal_out.m_enote = enote;
    proposal_out.m_enote_ephemeral_pubkey = enote_ephemeral_pubkey;
    proposal_out.m_input_context = input_context;
    proposal_out.m_address_mask = address_mask;
    proposal_out.m_commitment_mask = commitment_mask;
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_public_input_proposal_v1(const SpEnoteRecordV1 &enote_record,
    const crypto::secret_key &address_mask,
    const crypto::secret_key &commitment_mask,
    SpMultisigPublicInputProposalV1 &proposal_out)
{
    make_v1_multisig_public_input_proposal_v1(enote_record.m_enote,
        enote_record.m_enote_ephemeral_pubkey,
        enote_record.m_input_context,
        address_mask,
        commitment_mask,
        proposal_out);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_tx_proposal_semantics_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::string &expected_version_string,
    const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance)
{
    /// multisig signing config checks

    // 1. proposal should contain expected tx version encoding
    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_version_string == expected_version_string,
        "multisig tx proposal: intended tx version encoding is invalid.");

    // 2. signer set filter must be valid (at least 'threshold' signers allowed, format is valid)
    CHECK_AND_ASSERT_THROW_MES(multisig::validate_aggregate_multisig_signer_set_filter(threshold,
            num_signers,
            multisig_tx_proposal.m_aggregate_signer_set_filter),
        "multisig tx proposal: invalid aggregate signer set filter.");


    /// input/output checks

    // 1. check the public input proposal semantics
    for (const SpMultisigPublicInputProposalV1 &public_input_proposal : multisig_tx_proposal.m_input_proposals)
        check_v1_multisig_public_input_proposal_semantics_v1(public_input_proposal);

    // 2. convert the proposal to a plain tx proposal and check its semantics (a comprehensive set of tests)
    SpTxProposalV1 tx_proposal;
    multisig_tx_proposal.get_v1_tx_proposal_v1(wallet_spend_pubkey, k_view_balance, tx_proposal);

    check_v1_tx_proposal_semantics_v1(tx_proposal, wallet_spend_pubkey, k_view_balance);

    // - get prefix from proposal
    rct::key proposal_prefix;
    tx_proposal.get_proposal_prefix(multisig_tx_proposal.m_version_string, k_view_balance, proposal_prefix);


    /// multisig-related input checks

    // 1. input proposals line up 1:1 with multisig input proof proposals, each input has a unique key image
    CHECK_AND_ASSERT_THROW_MES(tx_proposal.m_input_proposals.size() == multisig_tx_proposal.m_input_proof_proposals.size(),
        "multisig tx proposal: input proposals don't line up with input proposal proofs.");

    // 2. assess each input proposal
    SpEnoteImageV1 enote_image_temp;

    for (std::size_t input_index{0}; input_index < multisig_tx_proposal.m_input_proof_proposals.size(); ++input_index)
    {
        // a. input proof proposal messages all equal proposal prefix of core tx proposal
        CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proof_proposals[input_index].message == proposal_prefix,
            "multisig tx proposal: input proof proposal does not match the tx proposal (different proposal prefix).");

        // b. input proof proposal keys line up 1:1 and match with input proposals
        tx_proposal.m_input_proposals[input_index].get_enote_image_v1(enote_image_temp);

        CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proof_proposals[input_index].K ==
                enote_image_temp.m_core.m_masked_address,
            "multisig tx proposal: input proof proposal does not match input proposal (different proof keys).");

        // c. input proof proposal key images line up 1:1 and match with input proposals
        CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proof_proposals[input_index].KI ==
                enote_image_temp.m_core.m_key_image,
            "multisig tx proposal: input proof proposal does not match input proposal (different key images).");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_tx_proposal_v1(std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    std::vector<ExtraFieldElement> additional_memo_elements,
    const DiscretizedFee &tx_fee,
    std::string version_string,
    std::vector<SpMultisigPublicInputProposalV1> public_input_proposals,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpMultisigTxProposalV1 &proposal_out)
{
    // convert public input proposals to plain input proposals
    std::vector<SpInputProposalV1> plain_input_proposals;

    for (const SpMultisigPublicInputProposalV1 &public_input_proposal : public_input_proposals)
    {
        plain_input_proposals.emplace_back();
        public_input_proposal.get_input_proposal_v1(wallet_spend_pubkey, k_view_balance, plain_input_proposals.back());
    }

    // make a temporary normal tx proposal
    SpTxProposalV1 tx_proposal;
    make_v1_tx_proposal_v1(normal_payment_proposals,
        selfsend_payment_proposals,
        tx_fee,
        std::move(plain_input_proposals),
        additional_memo_elements,
        tx_proposal);

    // get proposal prefix
    rct::key proposal_prefix;
    tx_proposal.get_proposal_prefix(version_string, k_view_balance, proposal_prefix);

    // prepare composition proofs for each input (note: use the tx proposal to ensure proof proposals are sorted)
    proposal_out.m_input_proof_proposals.clear();
    proposal_out.m_input_proof_proposals.reserve(public_input_proposals.size());
    SpEnoteImageV1 enote_image_temp;

    for (const SpInputProposalV1 &input_proposal : tx_proposal.m_input_proposals)
    {
        input_proposal.get_enote_image_v1(enote_image_temp);

        proposal_out.m_input_proof_proposals.emplace_back(
                sp_composition_multisig_proposal(proposal_prefix,
                    enote_image_temp.m_core.m_masked_address,
                    enote_image_temp.m_core.m_key_image)
            );
    }

    // add miscellaneous components
    proposal_out.m_input_proposals = std::move(public_input_proposals);
    proposal_out.m_normal_payment_proposals = std::move(normal_payment_proposals);
    proposal_out.m_selfsend_payment_proposals = std::move(selfsend_payment_proposals);
    make_tx_extra(std::move(additional_memo_elements), proposal_out.m_partial_memo);
    proposal_out.m_tx_fee = tx_fee;
    proposal_out.m_aggregate_signer_set_filter = aggregate_signer_set_filter;
    proposal_out.m_version_string = std::move(version_string);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_v1_multisig_tx_proposal_for_transfer_v1(const jamtis::JamtisDestinationV1 &change_address,
    const jamtis::JamtisDestinationV1 &dummy_address,
    const InputSelectorV1 &local_user_input_selector,
    const FeeCalculator &tx_fee_calculator,
    const rct::xmr_amount fee_per_tx_weight,
    const std::size_t max_inputs,
    const sp::SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    const multisig::signer_set_filter aggregate_filter_of_requested_multisig_signers,
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals,
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals,
    TxExtra partial_memo_for_tx,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpMultisigTxProposalV1 &multisig_tx_proposal_out,
    std::unordered_map<crypto::key_image, std::uint64_t> &input_ledger_mappings_out)
{
    // 1. try to select inputs for the tx
    const OutputSetContextForInputSelectionV1 output_set_context{
            normal_payment_proposals,
            selfsend_payment_proposals
        };

    rct::xmr_amount reported_final_fee;
    std::list<ContextualRecordVariant> contextual_inputs;
    if (!try_get_input_set_v1(output_set_context,
            max_inputs,
            local_user_input_selector,
            fee_per_tx_weight,
            tx_fee_calculator,
            reported_final_fee,
            contextual_inputs))
        return false;

    // 2. separate into legacy and seraphis inputs
    std::list<LegacyContextualEnoteRecordV1> legacy_contextual_inputs;
    std::list<SpContextualEnoteRecordV1> sp_contextual_inputs;

    split_contextual_enote_record_variants(contextual_inputs, legacy_contextual_inputs, sp_contextual_inputs);
    CHECK_AND_ASSERT_THROW_MES(legacy_contextual_inputs.size() == 0, "for now, legacy inputs aren't fully supported.");

    // a. convert legacy inputs to legacy multisig input proposals (inputs to spend) (TODO)

    // b. convert seraphis inputs to seraphis multisig input proposals (inputs to spend)
    input_ledger_mappings_out.clear();

    std::vector<SpMultisigPublicInputProposalV1> public_input_proposals;
    public_input_proposals.reserve(sp_contextual_inputs.size());

    for (const SpContextualEnoteRecordV1 &contextual_input : sp_contextual_inputs)
    {
        // save input indices for making membership proofs
        input_ledger_mappings_out[contextual_input.m_record.m_key_image] = 
            contextual_input.m_origin_context.m_enote_ledger_index;

        // convert inputs to input proposals
        public_input_proposals.emplace_back();
        make_v1_multisig_public_input_proposal_v1(contextual_input.m_record,
            rct::rct2sk(rct::skGen()),
            rct::rct2sk(rct::skGen()),
            public_input_proposals.back());
    }

    // 4. get total input amount
    boost::multiprecision::uint128_t total_input_amount{0};
    SpInputProposalV1 input_proposal_temp;

    for (const SpMultisigPublicInputProposalV1 &public_input_proposal : public_input_proposals)
    {
        public_input_proposal.get_input_proposal_v1(wallet_spend_pubkey, k_view_balance, input_proposal_temp);
        total_input_amount += input_proposal_temp.get_amount();
    }

    // 5. finalize output set
    const DiscretizedFee discretized_transaction_fee{reported_final_fee};
    CHECK_AND_ASSERT_THROW_MES(discretized_transaction_fee == reported_final_fee,
        "make tx proposal for transfer (v1): the input selector fee was not properly discretized (bug).");

    finalize_v1_output_proposal_set_v1(total_input_amount,
        reported_final_fee,
        change_address,
        dummy_address,
        k_view_balance,
        normal_payment_proposals,
        selfsend_payment_proposals);

    CHECK_AND_ASSERT_THROW_MES(tx_fee_calculator.get_fee(fee_per_tx_weight,
                legacy_contextual_inputs.size(), sp_contextual_inputs.size(),
                normal_payment_proposals.size() + selfsend_payment_proposals.size()) ==
            reported_final_fee,
        "make tx proposal for transfer (v1): final fee is not consistent with input selector fee (bug).");

    // 6. get memo elements
    std::vector<ExtraFieldElement> extra_field_elements;
    CHECK_AND_ASSERT_THROW_MES(try_get_extra_field_elements(partial_memo_for_tx, extra_field_elements),
        "make tx proposal for transfer (v1): unable to extract memo field elements for tx proposal.");

    // 7. assemble into tx proposal
    std::string version_string;
    make_versioning_string(semantic_rules_version, version_string);

    make_v1_multisig_tx_proposal_v1(std::move(normal_payment_proposals),
        std::move(selfsend_payment_proposals),
        std::move(extra_field_elements),
        reported_final_fee,
        version_string,
        std::move(public_input_proposals),
        aggregate_filter_of_requested_multisig_signers,
        wallet_spend_pubkey,
        k_view_balance,
        multisig_tx_proposal_out);

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_input_init_set_semantics_v1(const SpMultisigInputInitSetV1 &input_init_set,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers)
{
    // input init's signer must be known and permitted by the aggregate filter
    CHECK_AND_ASSERT_THROW_MES(std::find(multisig_signers.begin(), multisig_signers.end(), input_init_set.m_signer_id) !=
        multisig_signers.end(), "multisig input initializer: initializer from unknown signer.");
    CHECK_AND_ASSERT_THROW_MES(multisig::signer_is_in_filter(input_init_set.m_signer_id,
            multisig_signers,
            input_init_set.m_aggregate_signer_set_filter),
        "multisig input initializer: signer is not eligible.");

    // signer set filter must be valid (at least 'threshold' signers allowed, format is valid)
    CHECK_AND_ASSERT_THROW_MES(multisig::validate_aggregate_multisig_signer_set_filter(threshold,
            multisig_signers.size(),
            input_init_set.m_aggregate_signer_set_filter),
        "multisig tx proposal: invalid aggregate signer set filter.");

    // for each enote image to sign, there should be one nonce set (signing attempt) per signer set that contains the signer
    // - there are 'num signers requested' choose 'threshold' total signer sets per enote image
    // - remove our signer, then choose 'threshold - 1' signers from the remaining 'num signers requested - 1'
    const std::uint32_t num_sets_with_signer_expected(
            n_choose_k(multisig::get_num_flags_set(input_init_set.m_aggregate_signer_set_filter) - 1, threshold - 1)
        );

    for (const auto &init : input_init_set.m_input_inits)
    {
        CHECK_AND_ASSERT_THROW_MES(init.second.size() == num_sets_with_signer_expected,
            "multisig input initializer: don't have expected number of nonce sets (one per signer set with signer).");
    }
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_input_init_set_v1(const crypto::public_key &signer_id,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &proposal_prefix,
    const rct::keyV &masked_addresses,
    const multisig::signer_set_filter aggregate_signer_set_filter,
    SpMultisigNonceRecord &nonce_record_inout,
    SpMultisigInputInitSetV1 &input_init_set_out)
{
    // set components
    input_init_set_out.m_signer_id = signer_id;
    input_init_set_out.m_proposal_prefix = proposal_prefix;
    input_init_set_out.m_aggregate_signer_set_filter = aggregate_signer_set_filter;

    // prepare input init nonce map
    const std::uint32_t num_sets_with_signer_expected{
            n_choose_k(multisig::get_num_flags_set(aggregate_signer_set_filter) - 1, threshold - 1)
        };

    input_init_set_out.m_input_inits.clear();
    for (const rct::key &masked_address : masked_addresses)
    {
        // enforce canonical proof keys
        // NOTE: This is only a sanity check, as the underlying onetime addresses could contain duplicates (just with
        //       different masks).
        CHECK_AND_ASSERT_THROW_MES(key_domain_is_prime_subgroup(masked_address),
            "multisig input initializer: found enote image address with non-canonical representation!");

        input_init_set_out.m_input_inits[masked_address].reserve(num_sets_with_signer_expected);
    }

    CHECK_AND_ASSERT_THROW_MES(input_init_set_out.m_input_inits.size() == masked_addresses.size(),
        "multisig input initializer: found duplicate masked address (only unique enote images allowed).");

    // add nonces for every possible signer set that includes the signer
    std::vector<multisig::signer_set_filter> filter_permutations;
    multisig::aggregate_multisig_signer_set_filter_to_permutations(threshold,
        multisig_signers.size(),
        aggregate_signer_set_filter,
        filter_permutations);

    for (const multisig::signer_set_filter filter : filter_permutations)
    {
        // ignore filters that don't include the signer
        if (!multisig::signer_is_in_filter(input_init_set_out.m_signer_id, multisig_signers, filter))
            continue;

        // add nonces for each enote image we want to attempt to sign with this signer set
        for (const rct::key &masked_address : masked_addresses)
        {
            // note: ignore failures to add nonces (using existing nonces is allowed)
            nonce_record_inout.try_add_nonces(proposal_prefix,
                masked_address,
                filter,
                sp_multisig_init(rct::pk2rct(crypto::get_U())));

            // record the nonce pubkeys (should not fail)
            input_init_set_out.m_input_inits[masked_address].emplace_back();
            CHECK_AND_ASSERT_THROW_MES(nonce_record_inout.try_get_recorded_nonce_pubkeys(proposal_prefix,
                    masked_address,
                    filter,
                    input_init_set_out.m_input_inits[masked_address].back()),
                "multisig input init: could not get nonce pubkeys from nonce record (bug).");
        }
    }

    // check that the input initializer is well-formed
    check_v1_multisig_input_init_set_semantics_v1(input_init_set_out, threshold, multisig_signers);
}
//-------------------------------------------------------------------------------------------------------------------
void make_v1_multisig_input_init_set_v1(const crypto::public_key &signer_id,
    const std::uint32_t threshold,
    const std::vector<crypto::public_key> &multisig_signers,
    const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::string &expected_version_string,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    SpMultisigNonceRecord &nonce_record_inout,
    SpMultisigInputInitSetV1 &input_init_set_out)
{
    // validate multisig tx proposal
    check_v1_multisig_tx_proposal_semantics_v1(multisig_tx_proposal,
        expected_version_string,
        threshold,
        multisig_signers.size(),
        wallet_spend_pubkey,
        k_view_balance);

    // make multisig input inits from a tx proposal
    CHECK_AND_ASSERT_THROW_MES(multisig_tx_proposal.m_input_proposals.size() > 0,
        "multisig input initializer: no inputs to initialize.");

    // make proposal prefix
    SpTxProposalV1 tx_proposal;
    rct::key proposal_prefix;
    multisig_tx_proposal.get_v1_tx_proposal_v1(wallet_spend_pubkey, k_view_balance, tx_proposal);
    tx_proposal.get_proposal_prefix(multisig_tx_proposal.m_version_string, k_view_balance, proposal_prefix);

    // prepare masked addresses
    rct::keyV masked_addresses;
    get_masked_addresses(tx_proposal.m_input_proposals, masked_addresses);

    make_v1_multisig_input_init_set_v1(signer_id,
        threshold,
        multisig_signers,
        proposal_prefix,
        masked_addresses,
        multisig_tx_proposal.m_aggregate_signer_set_filter,
        nonce_record_inout,
        input_init_set_out);
}
//-------------------------------------------------------------------------------------------------------------------
void check_v1_multisig_input_partial_sig_semantics_v1(const SpMultisigInputPartialSigSetV1 &input_partial_sig_set,
    const std::vector<crypto::public_key> &multisig_signers)
{
    // signer is in filter
    CHECK_AND_ASSERT_THROW_MES(multisig::signer_is_in_filter(input_partial_sig_set.m_signer_id,
            multisig_signers,
            input_partial_sig_set.m_signer_set_filter),
        "multisig input partial sig set: the signer is not a member of the signer group (or the filter is invalid).");

    // all inputs sign the same message
    for (const SpCompositionProofMultisigPartial &partial_sig : input_partial_sig_set.m_partial_signatures)
    {
        CHECK_AND_ASSERT_THROW_MES(partial_sig.message == input_partial_sig_set.m_proposal_prefix,
            "multisig input partial sig set: a partial signature's message does not match the set's proposal prefix.");
    }
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_v1_multisig_input_partial_sig_sets_v1(const multisig::multisig_account &signer_account,
    const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::string &expected_version_string,
    const SpMultisigInputInitSetV1 &local_input_init_set,
    std::vector<SpMultisigInputInitSetV1> other_input_init_sets,
    SpMultisigNonceRecord &nonce_record_inout,
    std::vector<SpMultisigInputPartialSigSetV1> &input_partial_sig_sets_out)
{
    CHECK_AND_ASSERT_THROW_MES(signer_account.multisig_is_ready(),
        "multisig input partial sigs: signer account is not complete, so it can't make partial signatures.");

    /// prepare pieces to use below

    // 1. misc. from account
    const crypto::secret_key &k_view_balance{signer_account.get_common_privkey()};
    const std::uint32_t threshold{signer_account.get_threshold()};
    const std::vector<crypto::public_key> &multisig_signers{signer_account.get_signers()};
    const crypto::public_key &local_signer_id{signer_account.get_base_pubkey()};

    // 2. wallet spend pubkey: k_vb X + k_m U
    rct::key wallet_spend_pubkey{rct::pk2rct(signer_account.get_multisig_pubkey())};
    extend_seraphis_spendkey_x(k_view_balance, wallet_spend_pubkey);

    // 3. validate multisig tx proposal
    // note: this check is effectively redundant because it is called when making the local input init set,
    //       so validating the local input init set (which was successfully created) with the tx proposal's proposal
    //       prefix should imply the multisig tx proposal here is valid; but, redundancy is good
    check_v1_multisig_tx_proposal_semantics_v1(multisig_tx_proposal,
        expected_version_string,
        threshold,
        multisig_signers.size(),
        wallet_spend_pubkey,
        k_view_balance);

    // 4. misc. from multisig tx proposal
    SpTxProposalV1 tx_proposal;
    multisig_tx_proposal.get_v1_tx_proposal_v1(wallet_spend_pubkey, k_view_balance, tx_proposal);

    // a. proposal prefix
    rct::key proposal_prefix;
    tx_proposal.get_proposal_prefix(multisig_tx_proposal.m_version_string, k_view_balance, proposal_prefix);

    // b. masked addresses
    rct::keyV input_masked_addresses;
    get_masked_addresses(tx_proposal.m_input_proposals, input_masked_addresses);

    // c. enote view privkeys (for signing)
    std::vector<crypto::secret_key> enote_view_privkeys_g;
    std::vector<crypto::secret_key> enote_view_privkeys_x;
    std::vector<crypto::secret_key> enote_view_privkeys_u;
    enote_view_privkeys_g.reserve(multisig_tx_proposal.m_input_proposals.size());
    enote_view_privkeys_x.reserve(multisig_tx_proposal.m_input_proposals.size());
    enote_view_privkeys_u.reserve(multisig_tx_proposal.m_input_proposals.size());

    for (const SpInputProposalV1 &input_proposal : tx_proposal.m_input_proposals)
    {
        enote_view_privkeys_g.emplace_back(input_proposal.m_core.m_enote_view_privkey_g);
        enote_view_privkeys_x.emplace_back(input_proposal.m_core.m_enote_view_privkey_x);
        enote_view_privkeys_u.emplace_back(input_proposal.m_core.m_enote_view_privkey_u);
    }

    // 5. filter permutations
    std::vector<multisig::signer_set_filter> filter_permutations;
    multisig::aggregate_multisig_signer_set_filter_to_permutations(threshold,
        multisig_signers.size(),
        multisig_tx_proposal.m_aggregate_signer_set_filter,
        filter_permutations);


    /// validate and assemble input inits
    std::vector<SpMultisigInputInitSetV1> all_input_init_sets;

    validate_and_prepare_input_inits_for_partial_sig_sets_v1(multisig_tx_proposal,
        threshold,
        multisig_signers,
        local_signer_id,
        input_masked_addresses,
        proposal_prefix,
        local_input_init_set,
        std::move(other_input_init_sets),
        all_input_init_sets);


    /// prepare for signing

    // 1. save local signer as filter
    multisig::signer_set_filter local_signer_filter;
    multisig::multisig_signer_to_filter(local_signer_id, multisig_signers, local_signer_filter);

    // 2. collect available signers
    std::vector<crypto::public_key> available_signers;
    available_signers.reserve(all_input_init_sets.size());

    for (const SpMultisigInputInitSetV1 &input_init_set : all_input_init_sets)
        available_signers.emplace_back(input_init_set.m_signer_id);

    // give up if not enough signers
    if (available_signers.size() < threshold)
        return false;

    // 3. available signers as a filter
    multisig::signer_set_filter available_signers_filter;
    multisig::multisig_signers_to_filter(available_signers, multisig_signers, available_signers_filter);

    // 4. available signers as individual filters
    std::vector<multisig::signer_set_filter> available_signers_as_filters;
    available_signers_as_filters.reserve(available_signers.size());

    for (const crypto::public_key &available_signer : available_signers)
    {
        available_signers_as_filters.emplace_back();
        multisig::multisig_signer_to_filter(available_signer, multisig_signers, available_signers_as_filters.back());
    }

    // 5. record input enote squash prefixes and enote view privkeys
    std::vector<crypto::secret_key> squash_prefixes;
    squash_prefixes.reserve(multisig_tx_proposal.m_input_proposals.size());

    for (const SpMultisigPublicInputProposalV1 &input_proposal : multisig_tx_proposal.m_input_proposals)
    {
        squash_prefixes.emplace_back();
        input_proposal.get_squash_prefix(squash_prefixes.back());
    }


    /// make partial signatures
    make_v1_multisig_input_partial_sig_sets_v1(signer_account,
        multisig_tx_proposal,
        proposal_prefix,
        input_masked_addresses,
        filter_permutations,
        local_signer_filter,
        available_signers,
        all_input_init_sets,
        available_signers_filter,
        available_signers_as_filters,
        squash_prefixes,
        enote_view_privkeys_g,
        enote_view_privkeys_x,
        enote_view_privkeys_u,
        nonce_record_inout,
        input_partial_sig_sets_out);

    if (input_partial_sig_sets_out.size() == 0)
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_v1_partial_input_v1(const SpInputProposal &input_proposal,
    const rct::key &expected_proposal_prefix,
    const std::vector<SpCompositionProofMultisigPartial> &input_proof_partial_sigs,
    SpPartialInputV1 &partial_input_out)
{
    try
    {
        // all partial sigs must sign the expected message
        for (const SpCompositionProofMultisigPartial &partial_sig : input_proof_partial_sigs)
        {
            CHECK_AND_ASSERT_THROW_MES(partial_sig.message == expected_proposal_prefix,
                "multisig make partial input: a partial signature's message does not match the expected proposal prefix.");
        }

        // assemble proof (will throw if partial sig assembly doesn't produce a valid proof)
        partial_input_out.m_image_proof.m_composition_proof = sp_composition_prove_multisig_final(input_proof_partial_sigs);

        // copy miscellaneous pieces
        input_proposal.get_enote_image_core(partial_input_out.m_input_image.m_core);
        partial_input_out.m_address_mask = input_proposal.m_address_mask;
        partial_input_out.m_commitment_mask = input_proposal.m_commitment_mask;
        partial_input_out.m_proposal_prefix = expected_proposal_prefix;
        input_proposal.get_enote_core(partial_input_out.m_input_enote_core);
        partial_input_out.m_input_amount = input_proposal.m_amount;
        partial_input_out.m_input_amount_blinding_factor = input_proposal.m_amount_blinding_factor;
    }
    catch (...)
    {
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_make_v1_partial_inputs_v1(const SpMultisigTxProposalV1 &multisig_tx_proposal,
    const std::vector<crypto::public_key> &multisig_signers,
    const rct::key &wallet_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    std::unordered_map<crypto::public_key, std::vector<SpMultisigInputPartialSigSetV1>> input_partial_sigs_per_signer,
    std::vector<SpPartialInputV1> &partial_inputs_out)
{
    // note: do not validate semantics of multisig tx proposal or partial sig sets here, because this function is
    //       just attempting to combine partial sig sets into partial inputs

    // get normal tx proposal
    SpTxProposalV1 tx_proposal;
    multisig_tx_proposal.get_v1_tx_proposal_v1(wallet_spend_pubkey, k_view_balance, tx_proposal);

    // collect masked addresses of input images
    // and map input proposals to their masked addresses for ease of use later
    std::unordered_set<rct::key> expected_masked_addresses;
    std::unordered_map<rct::key, SpInputProposalV1> mapped_input_proposals;
    SpEnoteImageV1 enote_image_temp;

    for (const SpInputProposalV1 &input_proposal : tx_proposal.m_input_proposals)
    {
        input_proposal.get_enote_image_v1(enote_image_temp);
        expected_masked_addresses.insert(enote_image_temp.m_core.m_masked_address);
        mapped_input_proposals[enote_image_temp.m_core.m_masked_address] = input_proposal;
    }

    // get expected proposal prefix
    rct::key expected_proposal_prefix;
    tx_proposal.get_proposal_prefix(multisig_tx_proposal.m_version_string, k_view_balance, expected_proposal_prefix);

    // filter the partial signatures into maps
    std::unordered_map<multisig::signer_set_filter, std::unordered_set<crypto::public_key>> collected_signers_per_filter;
    std::unordered_map<multisig::signer_set_filter,  //signing group
        std::unordered_map<rct::key,                 //masked address
            std::vector<SpCompositionProofMultisigPartial>>> collected_sigs_per_key_per_filter;

    for (auto &input_partial_sigs_for_signer : input_partial_sigs_per_signer)
    {
        for (SpMultisigInputPartialSigSetV1 &input_partial_sig : input_partial_sigs_for_signer.second)
        {
            // skip sig sets with unknown proposal prefixes
            if (!(input_partial_sig.m_proposal_prefix == expected_proposal_prefix))
                continue;

            // skip sig sets that are invalid
            try { check_v1_multisig_input_partial_sig_semantics_v1(input_partial_sig, multisig_signers); }
            catch (...) { continue; }

            // skip sig sets if their signer ids don't match the input signer ids
            if (!(input_partial_sig.m_signer_id == input_partial_sigs_for_signer.first))
                continue;

            // skip sig sets that look like duplicates (same signer group and signer)
            // - do this after checking sig set validity to avoid inserting invalid filters into the collected signers map
            if (collected_signers_per_filter[input_partial_sig.m_signer_set_filter].find(input_partial_sig.m_signer_id) !=
                    collected_signers_per_filter[input_partial_sig.m_signer_set_filter].end())
                continue;

            // record that this signer/filter combo has been used
            collected_signers_per_filter[input_partial_sig.m_signer_set_filter].insert(input_partial_sig.m_signer_id);

            // record the partial sigs
            for (SpCompositionProofMultisigPartial &partial_sig : input_partial_sig.m_partial_signatures)
            {
                // skip partial sigs with unknown masked addresses
                if (expected_masked_addresses.find(partial_sig.K) == expected_masked_addresses.end())
                    continue;

                collected_sigs_per_key_per_filter[input_partial_sig.m_signer_set_filter][partial_sig.K].emplace_back(
                    std::move(partial_sig));
            }
        }
    }

    // try to make one partial input per masked address
    partial_inputs_out.clear();
    partial_inputs_out.reserve(expected_masked_addresses.size());
    std::unordered_set<rct::key> masked_addresses_with_partial_inputs;

    for (const auto &signer_group_partial_sigs : collected_sigs_per_key_per_filter)
    {
        for (const auto &masked_address_partial_sigs : signer_group_partial_sigs.second)
        {
            // skip partial sig sets for masked addresses that already have a completed proof (from a different
            //   signer group)
            if (masked_addresses_with_partial_inputs.find(masked_address_partial_sigs.first) != 
                    masked_addresses_with_partial_inputs.end())
                continue;

            // try to make the partial input
            partial_inputs_out.emplace_back();

            if (!try_make_v1_partial_input_v1(mapped_input_proposals[masked_address_partial_sigs.first].m_core,
                    expected_proposal_prefix,
                    masked_address_partial_sigs.second,
                    partial_inputs_out.back()))
                partial_inputs_out.pop_back();
            else
                masked_addresses_with_partial_inputs.insert(masked_address_partial_sigs.first);
        }
    }

    if (partial_inputs_out.size() != expected_masked_addresses.size())
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp

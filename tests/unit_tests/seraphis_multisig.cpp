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

#include "common/container_helpers.h"
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "crypto/generators.h"
#include "cryptonote_basic/account_generators.h"
#include "cryptonote_basic/subaddress_index.h"
#include "multisig/multisig.h"
#include "multisig/multisig_account.h"
#include "multisig/multisig_account_era_conversion_msg.h"
#include "multisig/multisig_clsag.h"
#include "multisig/multisig_nonce_record.h"
#include "multisig/multisig_partial_cn_key_image_msg.h"
#include "multisig/multisig_signer_set_filter.h"
#include "multisig/multisig_signing_errors.h"
#include "multisig/multisig_signing_helper_types.h"
#include "multisig/multisig_sp_composition_proof.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "ringct/rctTypes.h"
#include "seraphis/jamtis_core_utils.h"
#include "seraphis/jamtis_destination.h"
#include "seraphis/jamtis_payment_proposal.h"
#include "seraphis/jamtis_support_types.h"
#include "seraphis/legacy_core_utils.h"
#include "seraphis/legacy_enote_utils.h"
#include "seraphis/sp_core_enote_utils.h"
#include "seraphis/tx_binned_reference_set.h"
#include "seraphis/tx_binned_reference_set_utils.h"
#include "seraphis/tx_builder_types.h"
#include "seraphis/tx_builder_types_multisig.h"
#include "seraphis/tx_builders_inputs.h"
#include "seraphis/tx_builders_mixed.h"
#include "seraphis/tx_builders_multisig.h"
#include "seraphis/tx_builders_outputs.h"
#include "seraphis/tx_component_types.h"
#include "seraphis/tx_contextual_enote_record_types.h"
#include "seraphis/tx_contextual_enote_record_utils.h"
#include "seraphis/tx_discretized_fee.h"
#include "seraphis/tx_enote_record_types.h"
#include "seraphis/tx_enote_record_utils.h"
#include "seraphis/tx_enote_scanning.h"
#include "seraphis/tx_enote_scanning_context_simple.h"
#include "seraphis/tx_extra.h"
#include "seraphis/tx_input_selection.h"
#include "seraphis/tx_input_selection_output_context_v1.h"
#include "seraphis/txtype_squashed_v1.h"
#include "seraphis_crypto/sp_composition_proof.h"
#include "seraphis_crypto/sp_crypto_utils.h"
#include "seraphis_mocks/seraphis_mocks.h"

#include "gtest/gtest.h"

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>


//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static crypto::secret_key make_secret_key()
{
    return rct::rct2sk(rct::skGen());
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_multisig_jamtis_mock_keys(const multisig::multisig_account &account,
    sp::jamtis::jamtis_mock_keys &keys_out)
{
    using namespace sp;
    using namespace jamtis;

    keys_out.k_m = rct::rct2sk(rct::Z); //master key is not known in multisig
    keys_out.k_vb = account.get_common_privkey();
    make_jamtis_unlockamounts_key(keys_out.k_vb, keys_out.xk_ua);
    make_jamtis_findreceived_key(keys_out.k_vb, keys_out.xk_fr);
    make_jamtis_generateaddress_secret(keys_out.k_vb, keys_out.s_ga);
    make_jamtis_ciphertag_secret(keys_out.s_ga, keys_out.s_ct);
    keys_out.K_1_base = rct::pk2rct(account.get_multisig_pubkey());
    extend_seraphis_spendkey_x(keys_out.k_vb, keys_out.K_1_base);
    crypto::x25519_scmul_base(keys_out.xk_ua, keys_out.xK_ua);
    crypto::x25519_scmul_key(keys_out.xk_fr, keys_out.xK_ua, keys_out.xK_fr);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_multisig_accounts(const cryptonote::account_generator_era account_era,
    const std::uint32_t threshold,
    const std::uint32_t num_signers,
    std::vector<multisig::multisig_account> &accounts_out)
{
    std::vector<crypto::public_key> signers;
    std::vector<multisig::multisig_kex_msg> current_round_msgs;
    std::vector<multisig::multisig_kex_msg> next_round_msgs;
    accounts_out.clear();
    accounts_out.reserve(num_signers);
    signers.reserve(num_signers);
    next_round_msgs.reserve(accounts_out.size());

    // create multisig accounts for each signer
    for (std::size_t account_index{0}; account_index < num_signers; ++account_index)
    {
        // create account [[ROUND 0]]
        accounts_out.emplace_back(account_era, make_secret_key(), make_secret_key());

        // collect signer
        signers.emplace_back(accounts_out.back().get_base_pubkey());

        // collect account's first kex msg
        next_round_msgs.emplace_back(accounts_out.back().get_next_kex_round_msg());
    }

    // perform key exchange rounds until the accounts are ready
    while (accounts_out.size() && !accounts_out[0].multisig_is_ready())
    {
        current_round_msgs = std::move(next_round_msgs);
        next_round_msgs.clear();
        next_round_msgs.reserve(accounts_out.size());

        for (multisig::multisig_account &account : accounts_out)
        {
            // initialize or update account
            if (!account.account_is_active())
                account.initialize_kex(threshold, signers, current_round_msgs);  //[[ROUND 1]]
            else
                account.kex_update(current_round_msgs);  //[[ROUND 2+]]

            next_round_msgs.emplace_back(account.get_next_kex_round_msg());
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void convert_multisig_accounts(const cryptonote::account_generator_era new_era,
    std::vector<multisig::multisig_account> &accounts_inout)
{
    if (accounts_inout.size() == 0 || new_era == accounts_inout[0].get_era())
        return;

    // collect messages
    std::vector<multisig::multisig_account_era_conversion_msg> conversion_msgs;
    conversion_msgs.reserve(accounts_inout.size());
    for (const multisig::multisig_account &account : accounts_inout)
        conversion_msgs.emplace_back(account.get_account_era_conversion_msg(new_era));

    // convert accounts to 'new_era'
    for (multisig::multisig_account &account : accounts_inout)
        get_multisig_account_with_new_generator_era(account, new_era, conversion_msgs, account);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void multisig_cn_key_image_recovery(const std::vector<multisig::multisig_account> &accounts,
    //[base key for key image : shared offset privkey material in base key]
    const std::unordered_map<crypto::public_key, crypto::secret_key> &saved_key_components,
    std::unordered_map<crypto::public_key, crypto::key_image> &recovered_key_images_out)
{
    // 1. prepare partial key image messages for the key image base keys from all multisig group members
    std::unordered_map<crypto::public_key,
        std::unordered_map<crypto::public_key, multisig::multisig_partial_cn_key_image_msg>> partial_ki_msgs;

    for (const multisig::multisig_account &account : accounts)
    {
        ASSERT_TRUE(account.get_era() == cryptonote::account_generator_era::cryptonote);

        for (const auto &saved_keys : saved_key_components)
        {
            EXPECT_NO_THROW((partial_ki_msgs[saved_keys.first][account.get_base_pubkey()] =
                    multisig::multisig_partial_cn_key_image_msg{
                            account.get_base_privkey(),
                            saved_keys.first,
                            account.get_multisig_privkeys()
                        }
                ));
        }
    }

    // 2. process the messages
    std::unordered_map<crypto::public_key, multisig::signer_set_filter> onetime_addresses_with_insufficient_partial_kis;
    std::unordered_map<crypto::public_key, multisig::signer_set_filter> onetime_addresses_with_invalid_partial_kis;
    std::unordered_map<crypto::public_key, crypto::public_key> recovered_key_image_cores;

    EXPECT_NO_THROW(multisig::multisig_recover_cn_keyimage_cores(accounts[0].get_threshold(),
        accounts[0].get_signers(),
        accounts[0].get_multisig_pubkey(),
        partial_ki_msgs,
        onetime_addresses_with_insufficient_partial_kis,
        onetime_addresses_with_invalid_partial_kis,
        recovered_key_image_cores));

    EXPECT_TRUE(onetime_addresses_with_insufficient_partial_kis.size() == 0);
    EXPECT_TRUE(onetime_addresses_with_invalid_partial_kis.size() == 0);

    // 3. add the shared offset component to each key image core
    for (const auto &recovered_key_image_core : recovered_key_image_cores)
    {
        EXPECT_TRUE(saved_key_components.find(recovered_key_image_core.first) != saved_key_components.end());

        // KI_shared_piece = shared_offset * Hp(core key)
        crypto::key_image KI_shared_piece;
        crypto::generate_key_image(recovered_key_image_core.first,
            saved_key_components.at(recovered_key_image_core.first),
            KI_shared_piece);

        // KI = shared_offset * Hp(core key) + k_multisig * Hp(core key)
        recovered_key_images_out[recovered_key_image_core.first] =
            rct::rct2ki(rct::addKeys(rct::ki2rct(KI_shared_piece), rct::pk2rct(recovered_key_image_core.second)));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool clsag_multisig_test(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const std::uint32_t ring_size)
{
    try
    {
        // we will make a CLSAG on the multisig pubkey plus multisig common key: (k_common + k_multisig) G

        // prepare cryptonote multisig accounts
        std::vector<multisig::multisig_account> accounts;
        make_multisig_accounts(cryptonote::account_generator_era::cryptonote, threshold, num_signers, accounts);
        if (accounts.size() == 0)
            return false;

        // K = (k_common + k_multisig) G
        const rct::key K{
                rct::addKeys(
                        rct::scalarmultBase(rct::sk2rct(accounts[0].get_common_privkey())),
                        rct::pk2rct(accounts[0].get_multisig_pubkey())
                    )
            };

        // obtain the corresponding key image: KI = (k_common + k_multisig) Hp(K)
        std::unordered_map<crypto::public_key, crypto::secret_key> saved_key_components;
        std::unordered_map<crypto::public_key, crypto::key_image> recovered_key_images_out;
        saved_key_components[rct::rct2pk(K)] = accounts[0].get_common_privkey();

        multisig_cn_key_image_recovery(accounts, saved_key_components, recovered_key_images_out);  //multisig KI ceremony

        EXPECT_TRUE(recovered_key_images_out.find(rct::rct2pk(K)) != recovered_key_images_out.end());
        const crypto::key_image KI{recovered_key_images_out.at(rct::rct2pk(K))};

        // C = x G + 1 H
        // C" = -z G + C
        // auxilliary CLSAG key: C - C" = z G
        const rct::key x{rct::skGen()};
        const rct::key z{rct::skGen()};
        const rct::key C{rct::commit(1, x)};
        rct::key masked_C;  //C" = C - z G
        rct::subKeys(masked_C, C, rct::scalarmultBase(z));

        // (1/threshold) * k_common
        // (1/threshold) * z
        const rct::key inv_threshold{sp::invert(rct::d2h(threshold))};
        rct::key k_common_chunk{rct::sk2rct(accounts[0].get_common_privkey())};
        rct::key z_chunk{z};
        sc_mul(k_common_chunk.bytes, inv_threshold.bytes, k_common_chunk.bytes);
        sc_mul(z_chunk.bytes, inv_threshold.bytes, z_chunk.bytes);

        // auxilliary key image: D = z Hp(K)
        crypto::key_image D;
        crypto::generate_key_image(rct::rct2pk(K), rct::rct2sk(z), D);

        // key image base: Hp(K)
        crypto::key_image KI_base;
        crypto::generate_key_image(rct::rct2pk(K), rct::rct2sk(rct::I), KI_base);

        // make random rings of size ring_size
        rct::ctkeyV ring_members;

        for (std::size_t ring_index{0}; ring_index < ring_size; ++ring_index)
            ring_members.emplace_back(rct::ctkey{rct::pkGen(), rct::pkGen()});

        // get random real signing index
        const std::uint32_t l{crypto::rand_idx<std::uint32_t>(ring_size)};

        // set real keys to sign in the rings
        ring_members[l] = rct::ctkey{.dest = K, .mask = C};

        // tx proposer: make proposal and specify which other signers should try to co-sign (all of them)
        const rct::key message{rct::zero()};
        multisig::CLSAGMultisigProposal proposal;
        multisig::make_clsag_multisig_proposal(message, ring_members, masked_C, KI, D, l, proposal);

        multisig::signer_set_filter aggregate_filter;
        multisig::multisig_signers_to_filter(accounts[0].get_signers(), accounts[0].get_signers(), aggregate_filter);

        // get signer group permutations (all signer groups that can complete a signature)
        std::vector<multisig::signer_set_filter> filter_permutations;
        multisig::aggregate_multisig_signer_set_filter_to_permutations(threshold,
            num_signers,
            aggregate_filter,
            filter_permutations);

        // each signer prepares for each signer group it is a member of
        std::vector<multisig::MultisigNonceRecord> signer_nonce_records(num_signers);

        for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
        {
            for (std::size_t filter_index{0}; filter_index < filter_permutations.size(); ++filter_index)
            {
                if (!multisig::signer_is_in_filter(accounts[signer_index].get_base_pubkey(),
                        accounts[signer_index].get_signers(),
                        filter_permutations[filter_index]))
                    continue;

                EXPECT_TRUE(signer_nonce_records[signer_index].try_add_nonces(proposal.message,
                    proposal.main_proof_key(),
                    filter_permutations[filter_index]));
            }
        }

        // complete and validate each signature attempt
        std::vector<multisig::CLSAGMultisigPartial> partial_sigs;
        std::vector<multisig::MultisigPubNonces> signer_pub_nonces_G;  //stored with *(1/8)
        std::vector<multisig::MultisigPubNonces> signer_pub_nonces_Hp;  //stored with *(1/8)
        crypto::secret_key k_e_temp;
        rct::clsag proof;

        for (const multisig::signer_set_filter filter : filter_permutations)
        {
            partial_sigs.clear();
            signer_pub_nonces_G.clear();
            signer_pub_nonces_Hp.clear();
            partial_sigs.reserve(threshold);
            signer_pub_nonces_G.reserve(threshold);
            signer_pub_nonces_Hp.reserve(threshold);

            // assemble nonce pubkeys for this signing attempt
            for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
            {
                if (!multisig::signer_is_in_filter(accounts[signer_index].get_base_pubkey(),
                        accounts[signer_index].get_signers(),
                        filter))
                    continue;

                EXPECT_TRUE(signer_nonce_records[signer_index].try_get_nonce_pubkeys_for_base(proposal.message,
                    proposal.main_proof_key(),
                    filter,
                    rct::G,
                    tools::add_element(signer_pub_nonces_G)));
                EXPECT_TRUE(signer_nonce_records[signer_index].try_get_nonce_pubkeys_for_base(proposal.message,
                    proposal.main_proof_key(),
                    filter,
                    rct::ki2rct(KI_base),
                    tools::add_element(signer_pub_nonces_Hp)));
            }

            // each signer partially signs for this attempt
            for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
            {
                // get signing privkey
                if (!accounts[signer_index].try_get_aggregate_signing_key(filter, k_e_temp))
                    continue;

                // include shared offset
                sc_add(to_bytes(k_e_temp), k_common_chunk.bytes, to_bytes(k_e_temp));

                // make partial signature
                EXPECT_TRUE(multisig::try_make_clsag_multisig_partial_sig(
                    proposal,
                    k_e_temp,
                    rct::rct2sk(z_chunk),
                    signer_pub_nonces_G,
                    signer_pub_nonces_Hp,
                    filter,
                    signer_nonce_records[signer_index],
                    tools::add_element(partial_sigs)));
            }

            // sanity checks
            EXPECT_TRUE(signer_pub_nonces_G.size() == threshold);
            EXPECT_TRUE(signer_pub_nonces_Hp.size() == threshold);
            EXPECT_TRUE(partial_sigs.size() == threshold);

            // make proof
            multisig::finalize_clsag_multisig_proof(partial_sigs, ring_members, masked_C, proof);

            // verify proof
            if (!rct::verRctCLSAGSimple(message, proof, ring_members, masked_C))
                return false;
        }
    }
    catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool composition_proof_multisig_test(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const crypto::secret_key &x)
{
    try
    {
        // prepare multisig accounts (for seraphis)
        // - use 'converted' accounts to verify that old cryptonote accounts can be converted to seraphis accounts that
        //   work
        std::vector<multisig::multisig_account> accounts;
        make_multisig_accounts(cryptonote::account_generator_era::cryptonote, threshold, num_signers, accounts);
        convert_multisig_accounts(cryptonote::account_generator_era::seraphis, accounts);
        if (accounts.size() == 0)
            return false;

        // make a seraphis composition proof pubkey: x G + y X + z U
        rct::key K{rct::pk2rct(accounts[0].get_multisig_pubkey())};  //start with base key: z U
        sp::extend_seraphis_spendkey_x(accounts[0].get_common_privkey(), K);  //+ y X
        sp::mask_key(x, K, K);  //+ x G

        // make the corresponding key image: (z/y) U
        crypto::key_image KI;
        sp::make_seraphis_key_image(accounts[0].get_common_privkey(), accounts[0].get_multisig_pubkey(), KI);

        // tx proposer: make proposal and specify which other signers should try to co-sign (all of them)
        const rct::key message{rct::zero()};
        multisig::SpCompositionProofMultisigProposal proposal;
        multisig::make_sp_composition_multisig_proposal(message, K, KI, proposal);
        multisig::signer_set_filter aggregate_filter;
        multisig::multisig_signers_to_filter(accounts[0].get_signers(), accounts[0].get_signers(), aggregate_filter);

        // get signer group permutations (all signer groups that can complete a signature)
        std::vector<multisig::signer_set_filter> filter_permutations;
        multisig::aggregate_multisig_signer_set_filter_to_permutations(threshold,
            num_signers,
            aggregate_filter,
            filter_permutations);

        // each signer prepares for each signer group it is a member of
        std::vector<multisig::MultisigNonceRecord> signer_nonce_records(num_signers);

        for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
        {
            for (std::size_t filter_index{0}; filter_index < filter_permutations.size(); ++filter_index)
            {
                if (!multisig::signer_is_in_filter(accounts[signer_index].get_base_pubkey(),
                        accounts[signer_index].get_signers(),
                        filter_permutations[filter_index]))
                    continue;

                EXPECT_TRUE(signer_nonce_records[signer_index].try_add_nonces(proposal.message,
                    proposal.K,
                    filter_permutations[filter_index]));
            }
        }

        // complete and validate each signature attempt
        std::vector<multisig::SpCompositionProofMultisigPartial> partial_sigs;
        std::vector<multisig::MultisigPubNonces> signer_pub_nonces;  //stored with *(1/8)
        crypto::secret_key z_temp;
        sp::SpCompositionProof proof;

        for (const multisig::signer_set_filter filter : filter_permutations)
        {
            signer_pub_nonces.clear();
            partial_sigs.clear();
            signer_pub_nonces.reserve(threshold);
            partial_sigs.reserve(threshold);

            // assemble nonce pubkeys for this signing attempt
            for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
            {
                if (!multisig::signer_is_in_filter(accounts[signer_index].get_base_pubkey(),
                        accounts[signer_index].get_signers(),
                        filter))
                    continue;

                EXPECT_TRUE(signer_nonce_records[signer_index].try_get_nonce_pubkeys_for_base(proposal.message,
                    proposal.K,
                    filter,
                    rct::pk2rct(crypto::get_U()),
                    tools::add_element(signer_pub_nonces)));
            }

            // each signer partially signs for this attempt
            for (std::size_t signer_index{0}; signer_index < num_signers; ++signer_index)
            {
                if (!accounts[signer_index].try_get_aggregate_signing_key(filter, z_temp))
                    continue;

                EXPECT_TRUE(multisig::try_make_sp_composition_multisig_partial_sig(
                    proposal,
                    x,
                    accounts[signer_index].get_common_privkey(),
                    z_temp,
                    signer_pub_nonces,
                    filter,
                    signer_nonce_records[signer_index],
                    tools::add_element(partial_sigs)));
            }

            // sanity checks
            EXPECT_TRUE(signer_pub_nonces.size() == threshold);
            EXPECT_TRUE(partial_sigs.size() == threshold);

            // make proof
            multisig::finalize_sp_composition_multisig_proof(partial_sigs, proof);

            // verify proof
            if (!sp::verify_sp_composition_proof(proof, message, K, KI))
                return false;
        }
    }
    catch (...) { return false; }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void refresh_user_enote_store_legacy_multisig(const std::vector<multisig::multisig_account> &accounts,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const sp::RefreshLedgerEnoteStoreConfig &refresh_config,
    const sp::MockLedgerContext &ledger_context,
    sp::SpEnoteStoreMockV1 &enote_store_inout)
{
    using namespace sp;

    ASSERT_TRUE(accounts.size() > 0);

    // 1. legacy view-only scan
    refresh_user_enote_store_legacy_intermediate(rct::pk2rct(accounts[0].get_multisig_pubkey()),
        legacy_subaddress_map,
        accounts[0].get_common_privkey(),
        LegacyScanMode::SCAN,
        refresh_config,
        ledger_context,
        enote_store_inout);

    // 2. prepare key image import cycle
    const std::uint64_t intermediate_height_pre_import_cycle{
            enote_store_inout.top_legacy_partialscanned_block_height()
        };

    // 3. export intermediate onetime addresses that need key images
    const auto &legacy_intermediate_records = enote_store_inout.legacy_intermediate_records();

    std::unordered_map<crypto::public_key, crypto::secret_key> saved_key_components;

    for (const auto &intermediate_record : legacy_intermediate_records)
    {
        rct::key onetime_address_temp;
        intermediate_record.second.get_onetime_address(onetime_address_temp);

        saved_key_components[rct::rct2pk(onetime_address_temp)] =
            intermediate_record.second.m_record.m_enote_view_privkey;
    }

    // 4. recover key images
    std::unordered_map<crypto::public_key, crypto::key_image> recovered_key_images;
    multisig_cn_key_image_recovery(accounts, saved_key_components, recovered_key_images);  //multisig KI ceremony

    // 5. import acquired key images (will fail if the onetime addresses and key images don't line up)
    for (const auto &recovered_key_image : recovered_key_images)
    {
        ASSERT_NO_THROW(enote_store_inout.import_legacy_key_image(recovered_key_image.second,
            rct::pk2rct(recovered_key_image.first)));
    }

    // 6. legacy key-image-refresh scan
    refresh_user_enote_store_legacy_intermediate(rct::pk2rct(accounts[0].get_multisig_pubkey()),
        legacy_subaddress_map,
        accounts[0].get_common_privkey(),
        LegacyScanMode::KEY_IMAGES_ONLY,
        refresh_config,
        ledger_context,
        enote_store_inout);

    // 7. check results of key image refresh scan
    ASSERT_TRUE(enote_store_inout.legacy_intermediate_records().size() == 0);

    // 8. update the legacy fullscan height to account for a complete view-only scan cycle with key image recovery
    ASSERT_NO_THROW(enote_store_inout.set_last_legacy_fullscan_height(intermediate_height_pre_import_cycle));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool legacy_multisig_input_is_ready_to_spend(const sp::LegacyMultisigInputProposalV1 &input_proposal,
    const sp::SpEnoteStoreMockV1 &enote_store,
    const std::uint64_t current_chain_height)
{
    // 1. get the legacy enote from the enote store
    sp::LegacyContextualEnoteRecordV1 contextual_record;
    if (!enote_store.try_get_legacy_enote_record(input_proposal.m_key_image, contextual_record))
        return false;

    // 2. expect the record obtained matches with the input proposal
    if (!input_proposal.matches_with(contextual_record.m_record))
        return false;

    // 3. expect that the enote is unspent
    if (contextual_record.m_spent_context.m_spent_status != sp::SpEnoteSpentStatus::UNSPENT)
        return false;

    // 4. expect the enote is spendable within the height specified
    if (sp::onchain_legacy_enote_is_locked(contextual_record.m_origin_context.m_block_height,
            contextual_record.m_record.m_unlock_time,
            current_chain_height,
            0,  //default spendable age: configurable
            0)) //current time: use system call
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool sp_multisig_input_is_ready_to_spend(const sp::SpMultisigInputProposalV1 &input_proposal,
    const sp::SpEnoteStoreMockV1 &enote_store,
    const std::unordered_set<sp::SpEnoteOriginStatus> &origin_statuses,
    const std::uint64_t current_chain_height,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance)
{
    // 1. convert to a normal input proposal so the key image is available
    sp::SpInputProposalV1 normal_input_proposal;
    input_proposal.get_input_proposal_v1(jamtis_spend_pubkey, k_view_balance, normal_input_proposal);

    // 2. get the legacy enote from the enote store
    sp::SpContextualEnoteRecordV1 contextual_record;
    if (!enote_store.try_get_sp_enote_record(normal_input_proposal.m_core.m_key_image, contextual_record))
        return false;

    // 3. expect the record obtained matches with the input proposal
    if (!input_proposal.matches_with(contextual_record.m_record))
        return false;

    // 4. expect that the enote has an allowed origin
    if (origin_statuses.find(contextual_record.m_origin_context.m_origin_status) == origin_statuses.end())
        return false;

    // 5. expect that the enote is unspent
    if (contextual_record.m_spent_context.m_spent_status != sp::SpEnoteSpentStatus::UNSPENT)
        return false;

    // 6. expect the enote is spendable within the height specified (only check when only onchain enotes are permitted)
    if (origin_statuses.size() == 1 &&
        origin_statuses.find(sp::SpEnoteOriginStatus::ONCHAIN) != origin_statuses.end() &&
        sp::onchain_sp_enote_is_locked(contextual_record.m_origin_context.m_block_height,
            current_chain_height,
            0))  //default spendable age: configurable
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool legacy_ring_members_are_ready_to_spend(const std::vector<std::uint64_t> &reference_set,
    const rct::ctkeyV &legacy_ring_members,
    const sp::MockLedgerContext &ledger_context)
{
    // 1. 'zero ring members' are always ready to spend
    if (reference_set.size() == 0)
        return true;

    // 2. consistency sanity check
    if (reference_set.size() != legacy_ring_members.size())
        return false;

    // 3. try to obtain copies of the ring members from the ledger
    // note: this should NOT succeed for ring members that are locked on-chain (the mock ledger context does not implement
    //       that)
    rct::ctkeyV proof_elements_recovered;
    try { ledger_context.get_reference_set_proof_elements_v1(reference_set, proof_elements_recovered); }
    catch (...) { return false;}

    // 4. expect the recovered proof elements to match the expected ring members
    if (legacy_ring_members.size() != proof_elements_recovered.size())
        return false;

    for (std::size_t ring_member_index{0}; ring_member_index < legacy_ring_members.size(); ++ring_member_index)
    {
        if (!(legacy_ring_members[ring_member_index].dest == proof_elements_recovered[ring_member_index].dest))
            return false;
        if (!(legacy_ring_members[ring_member_index].mask == proof_elements_recovered[ring_member_index].mask))
            return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void validate_multisig_tx_proposal(const sp::SpMultisigTxProposalV1 &multisig_tx_proposal,
    const sp::SpTxSquashedV1::SemanticRulesVersion semantic_rules_version,
    const std::uint32_t threshold,
    const std::size_t num_signers,
    const rct::key &legacy_spend_pubkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const crypto::secret_key &legacy_view_privkey,
    const rct::key &jamtis_spend_pubkey,
    const crypto::secret_key &k_view_balance,
    const sp::SpEnoteStoreMockV1 &enote_store,
    const sp::MockLedgerContext &ledger_context)
{
    using namespace sp;

    // 1. check that the multisig tx proposal is well-formed
    ASSERT_TRUE(try_simulate_tx_from_multisig_tx_proposal_v1(multisig_tx_proposal,
        semantic_rules_version,
        threshold,
        num_signers,
        legacy_spend_pubkey,
        legacy_subaddress_map,
        legacy_view_privkey,
        jamtis_spend_pubkey,
        k_view_balance));

    // 2. check that the proposal inputs are known by our enote store, are unspent, and will be unlocked by a specified
    //    block height
    // note: could also check if the proposed inputs have been confirmed up to N blocks
    // note2: these checks are only 'temporary' because the specified enotes may be spent at any time (or be reorged)
    for (const LegacyMultisigInputProposalV1 &legacy_multisig_input_proposal :
        multisig_tx_proposal.m_legacy_multisig_input_proposals)
    {
        ASSERT_TRUE(legacy_multisig_input_is_ready_to_spend(legacy_multisig_input_proposal,
            enote_store,
            enote_store.top_block_height()));
    }

    for (const SpMultisigInputProposalV1 &sp_multisig_input_proposal :
        multisig_tx_proposal.m_sp_multisig_input_proposals)
    {
        ASSERT_TRUE(sp_multisig_input_is_ready_to_spend(sp_multisig_input_proposal,
            enote_store,
            {SpEnoteOriginStatus::ONCHAIN, SpEnoteOriginStatus::UNCONFIRMED, SpEnoteOriginStatus::OFFCHAIN},
            enote_store.top_block_height(),
            jamtis_spend_pubkey,
            k_view_balance));
    }

    // 3. check that the legacy inputs' ring members are valid references from the ledger
    // note: a reorg can invalidate the result of these checks
    ASSERT_TRUE(multisig_tx_proposal.m_legacy_multisig_input_proposals.size() ==
        multisig_tx_proposal.m_legacy_input_proof_proposals.size());

    for (std::size_t legacy_input_index{0};
        legacy_input_index < multisig_tx_proposal.m_legacy_multisig_input_proposals.size();
        ++legacy_input_index)
    {
        ASSERT_TRUE(legacy_ring_members_are_ready_to_spend(
            multisig_tx_proposal.m_legacy_multisig_input_proposals[legacy_input_index].m_reference_set,
            multisig_tx_proposal.m_legacy_input_proof_proposals[legacy_input_index].ring_members,
            ledger_context));
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void print_multisig_errors(const std::list<multisig::MultisigSigningErrorVariant> &multisig_errors)
{
    for (const multisig::MultisigSigningErrorVariant &error : multisig_errors)
        std::cout << "Multisig Signing Error: " << error_message_ref(error) << '\n';
}
//-------------------------------------------------------------------------------------------------------------------
// v1: SpTxSquashedV1
//-------------------------------------------------------------------------------------------------------------------
static void seraphis_multisig_tx_v1_test(const std::uint32_t threshold,
    const std::uint32_t num_signers,
    const std::vector<std::uint32_t> &requested_signers,
    const std::vector<rct::xmr_amount> &legacy_in_amounts,
    const std::vector<rct::xmr_amount> &sp_in_amounts,
    const std::vector<rct::xmr_amount> &out_amounts_normal,
    const std::vector<rct::xmr_amount> &out_amounts_selfsend,
    const sp::DiscretizedFee &fee,
    const sp::SpTxSquashedV1::SemanticRulesVersion semantic_rules_version)
{
    using namespace sp;
    using namespace jamtis;

    ASSERT_TRUE(num_signers > 0);
    ASSERT_TRUE(requested_signers.size() >= threshold);
    ASSERT_TRUE(requested_signers.size() <= num_signers);
    for (const std::uint32_t requested_signer : requested_signers)
        ASSERT_TRUE(requested_signer < num_signers);

    // config
    const std::size_t max_inputs{10000};
    rct::xmr_amount specified_fee;
    ASSERT_TRUE(try_get_fee_value(fee, specified_fee));
    const std::size_t fee_per_tx_weight{specified_fee};
    const std::size_t legacy_ring_size{2};
    const std::size_t ref_set_decomp_m{2};
    const std::size_t ref_set_decomp_n{2};
    const std::size_t bin_radius{1};
    const std::size_t num_bin_members{2};

    const RefreshLedgerEnoteStoreConfig refresh_config{
            .m_reorg_avoidance_depth = 1,
            .m_max_chunk_size = 1,
            .m_max_partialscan_attempts = 0
        };

    const SpBinnedReferenceSetConfigV1 bin_config{
            .m_bin_radius = bin_radius,
            .m_num_bin_members = num_bin_members
        };

    // global
    MockLedgerContext ledger_context{0, 10000};

    std::string version_string;
    make_versioning_string(semantic_rules_version, version_string);


    /// 1) setup multisig accounts

    // a) make accounts
    std::vector<multisig::multisig_account> legacy_accounts;
    ASSERT_NO_THROW(make_multisig_accounts(cryptonote::account_generator_era::cryptonote,
        threshold,
        num_signers,
        legacy_accounts));
    std::vector<multisig::multisig_account> seraphis_accounts{legacy_accounts};
    ASSERT_NO_THROW(convert_multisig_accounts(cryptonote::account_generator_era::seraphis, seraphis_accounts));
    ASSERT_TRUE(legacy_accounts.size() == num_signers);
    ASSERT_TRUE(seraphis_accounts.size() == num_signers);
    ASSERT_TRUE(legacy_accounts[0].get_base_pubkey() == seraphis_accounts[0].get_base_pubkey());

    // b) get shared seraphis multisig wallet keys
    jamtis_mock_keys shared_sp_keys;
    ASSERT_NO_THROW(make_multisig_jamtis_mock_keys(seraphis_accounts[0], shared_sp_keys));

    // c) make an enote store for the multisig group
    SpEnoteStoreMockV1 enote_store{0, 0, 0};


    /// 2) fund the multisig address

    // a) make a legacy user address to receive funds
    rct::key legacy_subaddr_spendkey;
    rct::key legacy_subaddr_viewkey;
    cryptonote::subaddress_index legacy_subaddr_index;
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map;

    gen_legacy_subaddress(rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
        legacy_accounts[0].get_common_privkey(),
        legacy_subaddr_spendkey,
        legacy_subaddr_viewkey,
        legacy_subaddr_index);

    legacy_subaddress_map[legacy_subaddr_spendkey] = legacy_subaddr_index;

    // b) make a seraphis user address to receive funds
    address_index_t j;
    j.gen();
    JamtisDestinationV1 sp_user_address;

    ASSERT_NO_THROW(make_jamtis_destination_v1(shared_sp_keys.K_1_base,
        shared_sp_keys.xK_ua,
        shared_sp_keys.xK_fr,
        shared_sp_keys.s_ga,
        j,
        sp_user_address));

    // c) send legacy coinbase enotes to the address, padded so there are enough for legacy ring signatures
    std::vector<rct::xmr_amount> legacy_in_amounts_padded{legacy_in_amounts};

    if (legacy_in_amounts_padded.size() < legacy_ring_size)
        legacy_in_amounts_padded.resize(legacy_ring_size, 0);

    send_legacy_coinbase_amounts_to_user(legacy_in_amounts_padded,
        legacy_subaddr_spendkey,
        legacy_subaddr_viewkey,
        ledger_context);

    // d) send coinbase enotes to the address, padded so there are enough for seraphis membership proofs
    std::vector<rct::xmr_amount> sp_in_amounts_padded{sp_in_amounts};

    if (sp_in_amounts_padded.size() < compute_bin_width(bin_radius))
        sp_in_amounts_padded.resize(compute_bin_width(bin_radius), 0);

    send_sp_coinbase_amounts_to_user(sp_in_amounts_padded, sp_user_address, ledger_context);

    // e) recover balance
    refresh_user_enote_store_legacy_multisig(legacy_accounts,
        legacy_subaddress_map,
        refresh_config,
        ledger_context,
        enote_store);
    refresh_user_enote_store(shared_sp_keys, refresh_config, ledger_context, enote_store);

    // f) compute expected received amount
    boost::multiprecision::uint128_t total_input_amount{0};

    for (const rct::xmr_amount legacy_in_amount : legacy_in_amounts_padded)
        total_input_amount += legacy_in_amount;
    for (const rct::xmr_amount sp_in_amount : sp_in_amounts_padded)
        total_input_amount += sp_in_amount;

    // g) balance check
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == total_input_amount);


    /// 3) propose tx

    // a) prepare outputs

    // - normal payments
    std::vector<jamtis::JamtisPaymentProposalV1> normal_payment_proposals;
    normal_payment_proposals.reserve(out_amounts_normal.size());

    for (const rct::xmr_amount out_amount : out_amounts_normal)
        tools::add_element(normal_payment_proposals).gen(out_amount, 0);

    // - self-send payments
    std::vector<jamtis::JamtisPaymentProposalSelfSendV1> selfsend_payment_proposals;
    selfsend_payment_proposals.reserve(out_amounts_selfsend.size());

    for (const rct::xmr_amount out_amount : out_amounts_selfsend)
    {
        selfsend_payment_proposals.emplace_back(
                JamtisPaymentProposalSelfSendV1{
                    .m_destination = sp_user_address,
                    .m_amount = out_amount,
                    .m_type = JamtisSelfSendType::SELF_SPEND,
                    .m_enote_ephemeral_privkey = crypto::x25519_secret_key_gen(),
                    .m_partial_memo = TxExtra{}
                }
            );
    }

    // b) set requested signers filter
    std::vector<crypto::public_key> requested_signers_ids;
    requested_signers_ids.reserve(requested_signers.size());

    for (std::size_t signer_index{0}; signer_index < seraphis_accounts.size(); ++signer_index)
    {
        if (std::find(requested_signers.begin(), requested_signers.end(), signer_index) != requested_signers.end())
            requested_signers_ids.emplace_back(seraphis_accounts[signer_index].get_base_pubkey());
    }

    multisig::signer_set_filter aggregate_filter_of_requested_multisig_signers;
    multisig::multisig_signers_to_filter(requested_signers_ids,
        seraphis_accounts[0].get_signers(),
        aggregate_filter_of_requested_multisig_signers);

    // c) prepare inputs and finalize outputs
    const sp::InputSelectorMockV1 input_selector{enote_store};
    const sp::FeeCalculatorMockTrivial tx_fee_calculator;  //trivial fee calculator so we can use specified input fee

    std::list<LegacyContextualEnoteRecordV1> legacy_contextual_inputs;
    std::list<SpContextualEnoteRecordV1> sp_contextual_inputs;
    DiscretizedFee discretized_transaction_fee;
    ASSERT_NO_THROW(ASSERT_TRUE(try_prepare_inputs_and_outputs_for_transfer_v1(sp_user_address,
        sp_user_address,
        input_selector,
        tx_fee_calculator,
        fee_per_tx_weight,
        max_inputs,
        std::move(normal_payment_proposals),
        std::move(selfsend_payment_proposals),
        shared_sp_keys.k_vb,
        legacy_contextual_inputs,
        sp_contextual_inputs,
        normal_payment_proposals,
        selfsend_payment_proposals,
        discretized_transaction_fee)));

    // d) prepare for legacy input proofs
    // note: need legacy ring signature preps here because legacy multisig proofs include ledger references (the ring
    //       signature decoys must be taken from the chain); however, seraphis ledger mappings are NOT needed because
    //       seraphis multisig proofs only operate on seraphis enote images, which don't require ledger references
    std::unordered_map<crypto::key_image, LegacyMultisigRingSignaturePrepV1> mapped_legacy_multisig_ring_signature_preps;
    ASSERT_NO_THROW(ASSERT_TRUE(try_gen_legacy_multisig_ring_signature_preps_v1(legacy_contextual_inputs,
        legacy_ring_size,
        ledger_context,
        mapped_legacy_multisig_ring_signature_preps)));

    // e) make multisig tx proposal
    SpMultisigTxProposalV1 multisig_tx_proposal;
    ASSERT_NO_THROW(make_v1_multisig_tx_proposal_v1(legacy_contextual_inputs,
        sp_contextual_inputs,
        std::move(mapped_legacy_multisig_ring_signature_preps),
        semantic_rules_version,
        aggregate_filter_of_requested_multisig_signers,
        std::move(normal_payment_proposals),
        std::move(selfsend_payment_proposals),
        TxExtra{},
        discretized_transaction_fee,
        rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
        legacy_subaddress_map,
        legacy_accounts[0].get_common_privkey(),
        shared_sp_keys.K_1_base,
        shared_sp_keys.k_vb,
        multisig_tx_proposal));

    ASSERT_TRUE(multisig_tx_proposal.m_tx_fee == fee);

    // f) prove the multisig tx proposal is valid (this should be done by every signer who receives a multisig tx proposal
    //    from another group member)
    validate_multisig_tx_proposal(multisig_tx_proposal,
        semantic_rules_version,
        seraphis_accounts[0].get_threshold(),
        seraphis_accounts[0].get_signers().size(),
        rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
        legacy_subaddress_map,
        legacy_accounts[0].get_common_privkey(),
        shared_sp_keys.K_1_base,
        shared_sp_keys.k_vb,
        enote_store,
        ledger_context);


    /// 4) get seraphis input proof inits from all requested signers
    std::vector<multisig::MultisigNonceRecord> signer_nonce_records;
    std::unordered_map<crypto::public_key, std::unordered_map<rct::key, multisig::MultisigProofInitSetV1>>
        legacy_input_init_collections_per_signer;
    std::unordered_map<crypto::public_key, std::unordered_map<rct::key, multisig::MultisigProofInitSetV1>>
        sp_input_init_collections_per_signer;
    //signer_nonce_records.reserve(seraphis_accounts.size());  //nonce records are non-copyable, so .reserve() doesn't work

    for (std::size_t signer_index{0}; signer_index < seraphis_accounts.size(); ++signer_index)
    {
        signer_nonce_records.emplace_back();

        if (std::find(requested_signers.begin(), requested_signers.end(), signer_index) != requested_signers.end())
        {
            ASSERT_NO_THROW(make_v1_multisig_init_sets_for_inputs_v1(seraphis_accounts[signer_index].get_base_pubkey(),
                seraphis_accounts[signer_index].get_threshold(),
                seraphis_accounts[signer_index].get_signers(),
                multisig_tx_proposal,
                version_string,
                rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
                legacy_subaddress_map,
                legacy_accounts[0].get_common_privkey(),
                shared_sp_keys.K_1_base,
                shared_sp_keys.k_vb,
                signer_nonce_records.back(),
                legacy_input_init_collections_per_signer[seraphis_accounts[signer_index].get_base_pubkey()],
                sp_input_init_collections_per_signer[seraphis_accounts[signer_index].get_base_pubkey()]));
        }
        else
        {
            ASSERT_ANY_THROW(make_v1_multisig_init_sets_for_inputs_v1(seraphis_accounts[signer_index].get_base_pubkey(),
                seraphis_accounts[signer_index].get_threshold(),
                seraphis_accounts[signer_index].get_signers(),
                multisig_tx_proposal,
                version_string,
                rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
                legacy_subaddress_map,
                legacy_accounts[0].get_common_privkey(),
                shared_sp_keys.K_1_base,
                shared_sp_keys.k_vb,
                signer_nonce_records.back(),
                legacy_input_init_collections_per_signer[seraphis_accounts[signer_index].get_base_pubkey()],
                sp_input_init_collections_per_signer[seraphis_accounts[signer_index].get_base_pubkey()]));
        }
    }


    /// 5) get partial signatures from all requested signers
    std::unordered_map<crypto::public_key, std::vector<multisig::MultisigPartialSigSetV1>>
        legacy_input_partial_sigs_per_signer;
    std::unordered_map<crypto::public_key, std::vector<multisig::MultisigPartialSigSetV1>>
        sp_input_partial_sigs_per_signer;
    std::list<multisig::MultisigSigningErrorVariant> multisig_make_partial_sig_errors;

    for (std::size_t signer_index{0}; signer_index < seraphis_accounts.size(); ++signer_index)
    {
        multisig_make_partial_sig_errors.clear();

        if (std::find(requested_signers.begin(), requested_signers.end(), signer_index) != requested_signers.end())
        {
            ASSERT_NO_THROW(ASSERT_TRUE(try_make_v1_multisig_partial_sig_sets_for_legacy_inputs_v1(
                legacy_accounts[signer_index],
                multisig_tx_proposal,
                legacy_subaddress_map,
                shared_sp_keys.K_1_base,
                shared_sp_keys.k_vb,
                version_string,
                legacy_input_init_collections_per_signer[legacy_accounts[signer_index].get_base_pubkey()],
                //don't need to remove the local init (will be filtered out internally)
                legacy_input_init_collections_per_signer,
                multisig_make_partial_sig_errors,
                signer_nonce_records[signer_index],
                legacy_input_partial_sigs_per_signer[legacy_accounts[signer_index].get_base_pubkey()])));

            ASSERT_NO_THROW(ASSERT_TRUE(try_make_v1_multisig_partial_sig_sets_for_sp_inputs_v1(
                seraphis_accounts[signer_index],
                multisig_tx_proposal,
                rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
                legacy_subaddress_map,
                legacy_accounts[0].get_common_privkey(),
                version_string,
                sp_input_init_collections_per_signer[seraphis_accounts[signer_index].get_base_pubkey()],
                //don't need to remove the local init (will be filtered out internally)
                sp_input_init_collections_per_signer,
                multisig_make_partial_sig_errors,
                signer_nonce_records[signer_index],
                sp_input_partial_sigs_per_signer[seraphis_accounts[signer_index].get_base_pubkey()])));

            print_multisig_errors(multisig_make_partial_sig_errors);
        }
        else
        {
            ASSERT_ANY_THROW(
                    try_make_v1_multisig_partial_sig_sets_for_legacy_inputs_v1(legacy_accounts[signer_index],
                        multisig_tx_proposal,
                        legacy_subaddress_map,
                        shared_sp_keys.K_1_base,
                        shared_sp_keys.k_vb,
                        version_string,
                        legacy_input_init_collections_per_signer[legacy_accounts[signer_index].get_base_pubkey()],
                        //don't need to remove the local init (will be filtered out internally)
                        legacy_input_init_collections_per_signer,
                        multisig_make_partial_sig_errors,
                        signer_nonce_records[signer_index],
                        legacy_input_partial_sigs_per_signer[legacy_accounts[signer_index].get_base_pubkey()])
                    &&
                    try_make_v1_multisig_partial_sig_sets_for_sp_inputs_v1(seraphis_accounts[signer_index],
                        multisig_tx_proposal,
                        rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
                        legacy_subaddress_map,
                        legacy_accounts[0].get_common_privkey(),
                        version_string,
                        sp_input_init_collections_per_signer[seraphis_accounts[signer_index].get_base_pubkey()],
                        //don't need to remove the local init (will be filtered out internally)
                        sp_input_init_collections_per_signer,
                        multisig_make_partial_sig_errors,
                        signer_nonce_records[signer_index],
                        sp_input_partial_sigs_per_signer[seraphis_accounts[signer_index].get_base_pubkey()])
                );

            print_multisig_errors(multisig_make_partial_sig_errors);
        }
    }


    /// 6) any signer (or even a non-signer) can assemble partial signatures and complete txs
    /// note: even signers who didn't participate in making partial sigs can complete txs here

    // a) get legacy inputs and seraphis partial inputs
    std::vector<LegacyInputV1> legacy_inputs;
    std::vector<SpPartialInputV1> sp_partial_inputs;
    std::list<multisig::MultisigSigningErrorVariant> multisig_make_inputs_errors;

    ASSERT_NO_THROW(
            ASSERT_TRUE(try_make_inputs_for_multisig_v1(multisig_tx_proposal,
                seraphis_accounts[0].get_signers(),
                rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
                legacy_subaddress_map,
                legacy_accounts[0].get_common_privkey(),
                shared_sp_keys.K_1_base,
                shared_sp_keys.k_vb,
                legacy_input_partial_sigs_per_signer,
                sp_input_partial_sigs_per_signer,
                multisig_make_inputs_errors,
                legacy_inputs,
                sp_partial_inputs))
        );
    print_multisig_errors(multisig_make_inputs_errors);

    // b) build partial tx
    SpTxProposalV1 tx_proposal;
    multisig_tx_proposal.get_v1_tx_proposal_v1(rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
        legacy_subaddress_map,
        legacy_accounts[0].get_common_privkey(),
        shared_sp_keys.K_1_base,
        shared_sp_keys.k_vb,
        tx_proposal);

    SpPartialTxV1 partial_tx;
    ASSERT_NO_THROW(make_v1_partial_tx_v1(tx_proposal,
        std::move(legacy_inputs),
        std::move(sp_partial_inputs),
        version_string,
        rct::pk2rct(legacy_accounts[0].get_multisig_pubkey()),
        shared_sp_keys.K_1_base,
        shared_sp_keys.k_vb,
        partial_tx));

    // c) get ledger mappings for the seraphis input membership proofs
    // note: do this after making the partial tx to demo that seraphis inputs don't have to be on-chain until this point
    std::unordered_map<crypto::key_image, std::uint64_t> sp_input_ledger_mappings;
    ASSERT_TRUE(try_get_membership_proof_real_reference_mappings(sp_contextual_inputs, sp_input_ledger_mappings));

    // d) prepare for membership proofs
    // note: use ring size 2^2 = 4 for speed
    std::vector<SpMembershipProofPrepV1> membership_proof_preps;
    ASSERT_NO_THROW(make_mock_sp_membership_proof_preps_for_inputs_v1(sp_input_ledger_mappings,
        tx_proposal.m_sp_input_proposals,
        ref_set_decomp_n,
        ref_set_decomp_m,
        bin_config,
        ledger_context,
        membership_proof_preps));

    // e) make membership proofs
    std::vector<SpAlignableMembershipProofV1> alignable_membership_proofs;

    ASSERT_NO_THROW(make_v1_membership_proofs_v1(std::move(membership_proof_preps),
        alignable_membership_proofs));

    // f) complete tx
    SpTxSquashedV1 completed_tx;

    ASSERT_NO_THROW(make_seraphis_tx_squashed_v1(semantic_rules_version,
        partial_tx,
        std::move(alignable_membership_proofs),
        completed_tx));

    // - sanity check fee (should do this in production use-case, but can't do it here with the trivial fee calculator)
    //ASSERT_TRUE(completed_tx.m_fee == tx_fee_calculator.compute_fee(fee_per_tx_weight, completed_tx));

    // g) verify tx
    const TxValidationContextMock tx_validation_context{ledger_context};

    ASSERT_NO_THROW(ASSERT_TRUE(validate_tx(completed_tx, tx_validation_context)));

    // h) add tx to mock ledger
    ASSERT_NO_THROW(ASSERT_TRUE(try_add_tx_to_ledger(completed_tx, ledger_context)));


    /// 7) scan outputs for post-tx balance check

    // a) refresh enote store
    refresh_user_enote_store_legacy_multisig(legacy_accounts,
        legacy_subaddress_map,
        refresh_config,
        ledger_context,
        enote_store);
    refresh_user_enote_store(shared_sp_keys, refresh_config, ledger_context, enote_store);

    // b) compute expected spent amount
    boost::multiprecision::uint128_t total_spent_amount{0};

    for (const rct::xmr_amount out_amount : out_amounts_normal)
        total_spent_amount += out_amount;

    // c) balance check
    ASSERT_TRUE(enote_store.get_balance({SpEnoteOriginStatus::ONCHAIN},
        {SpEnoteSpentStatus::SPENT_ONCHAIN}) == total_input_amount - total_spent_amount - specified_fee);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_multisig, CLSAG_multisig)
{
    // test various account combinations
    EXPECT_TRUE(clsag_multisig_test(1, 2, 2));
    EXPECT_TRUE(clsag_multisig_test(1, 2, 3));
    EXPECT_TRUE(clsag_multisig_test(2, 2, 2));
    EXPECT_TRUE(clsag_multisig_test(1, 3, 2));
    EXPECT_TRUE(clsag_multisig_test(2, 3, 2));
    EXPECT_TRUE(clsag_multisig_test(3, 3, 2));
    EXPECT_TRUE(clsag_multisig_test(2, 4, 2));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_multisig, composition_proof_multisig)
{
    // test various account combinations
    EXPECT_TRUE(composition_proof_multisig_test(1, 2, make_secret_key()));
    EXPECT_TRUE(composition_proof_multisig_test(2, 2, make_secret_key()));
    EXPECT_TRUE(composition_proof_multisig_test(1, 3, make_secret_key()));
    EXPECT_TRUE(composition_proof_multisig_test(2, 3, make_secret_key()));
    EXPECT_TRUE(composition_proof_multisig_test(3, 3, make_secret_key()));
    EXPECT_TRUE(composition_proof_multisig_test(2, 4, make_secret_key()));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_multisig, txtype_squashed_v1)
{
    // parameters: threshold | num_signers | {requested_signers} | {legacy in amnts} | {sp in amnts} | {out amnts normal} |
    // {out amnts selfsend} | fee | semantic_rules_version

    const sp::SpTxSquashedV1::SemanticRulesVersion semantic_rules_version{
            sp::SpTxSquashedV1::SemanticRulesVersion::MOCK
        };

    // prepare fees to use (these should discretize perfectly)
    const sp::DiscretizedFee fee_zero{0};
    const sp::DiscretizedFee fee_one{1};
    EXPECT_TRUE(fee_zero == rct::xmr_amount{0});
    EXPECT_TRUE(fee_one == rct::xmr_amount{1});


    /// legacy inputs only

    // test M-of-N combos (and combinations of requested signers)
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 2, {0,1},     {2}, {}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 3, {0},       {2}, {}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 3, {1},       {2}, {}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 3, {0,2},     {2}, {}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(3, 3, {0,1,2},   {2}, {}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 4, {1,3},     {2}, {}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 4, {0,1,2,3}, {2}, {}, {1}, {}, fee_one, semantic_rules_version));

    // test various combinations of inputs/outputs
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {}, {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {}, {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {}, {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {}, { },   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {}, {2},   { },   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {}, {2},   { },   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {}, {2},   {0},   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2},   {}, {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {3},   {}, {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {3},   {}, {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {4},   {}, {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {4},   {}, {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {4},   {}, {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {4,4}, {}, {1,1}, {1,1}, fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {2,2,2}, {}, {1,1}, {1,1}, fee_one,  semantic_rules_version));


    /// seraphis inputs only

    // test M-of-N combos (and combinations of requested signers)
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 2, {0,1},     {}, {2}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 3, {0},       {}, {2}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 3, {1},       {}, {2}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 3, {0,2},     {}, {2}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(3, 3, {0,1,2},   {}, {2}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 4, {1,3},     {}, {2}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 4, {0,1,2,3}, {}, {2}, {1}, {}, fee_one, semantic_rules_version));

    // test various combinations of inputs/outputs
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {2},   {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {2},   {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {2},   {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {2},   { },   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {2},   {2},   { },   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {2},   {2},   { },   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {2},   {2},   {0},   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {2},   {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {3},   {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {3},   {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {4},   {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {4},   {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {4},   {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {}, {4,4}, {1,1}, {1,1}, fee_one,  semantic_rules_version));


    /// both seraphis and legacy inputs

    // test M-of-N combos (and combinations of requested signers)
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 2, {0,1},     {1}, {1}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 3, {0},       {1}, {1}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 3, {1},       {1}, {1}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 3, {0,2},     {1}, {1}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(3, 3, {0,1,2},   {1}, {1}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 4, {1,3},     {1}, {1}, {1}, {}, fee_one, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(2, 4, {0,1,2,3}, {1}, {1}, {1}, {}, fee_one, semantic_rules_version));

    // test various combinations of inputs/outputs
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {1},   {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {1},   {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {1},   {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {1},   { },   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {1},   {2},   { },   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {1},   {2},   { },   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {1},   {2},   {0},   fee_zero, semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {1},   {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {2},   {1},   { },   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {2},   {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {3},   {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {3},   {1},   {1},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1},   {3},   {1},   {0},   fee_one,  semantic_rules_version));
    EXPECT_NO_THROW(seraphis_multisig_tx_v1_test(1, 2, {0}, {1,1}, {2,2}, {1,1}, {1,1}, fee_one,  semantic_rules_version));
}
//-------------------------------------------------------------------------------------------------------------------

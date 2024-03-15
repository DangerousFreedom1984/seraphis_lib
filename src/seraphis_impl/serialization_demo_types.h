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

// Serializable types for seraphis transaction components and transactions (a demonstration).

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/legacy_enote_types.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/txtype_coinbase_v1.h"
#include "seraphis_main/txtype_squashed_v1.h"

#include "serialization/crypto.h"
#include "serialization/serialization.h"
#include "serialization/pair.h"

//third party headers

//standard headers
#include <vector>

//forward declarations


namespace sp
{
namespace serialization
{
/// serializable jamtis::address_index_t
struct ser_address_index_t final
{
    unsigned char bytes[sizeof(jamtis::address_index_t)];
};

/// serializable jamtis::address_tag_t
struct ser_address_tag_t final
{
    unsigned char bytes[sizeof(jamtis::address_tag_t)];
};

/// serializable jamtis::encrypted_address_tag_t
struct ser_encrypted_address_tag_t final
{
    unsigned char bytes[sizeof(jamtis::encrypted_address_tag_t)];
};

/// serializable jamtis::encoded_amount_t
struct ser_encoded_amount_t final
{
    unsigned char bytes[sizeof(jamtis::encoded_amount_t)];
};

/// serializable SpCoinbaseEnoteCore
struct ser_SpCoinbaseEnoteCore final
{
    /// Ko
    rct::key onetime_address;
    /// a
    rct::xmr_amount amount;

    BEGIN_SERIALIZE()
        FIELD(onetime_address)
        VARINT_FIELD(amount)
    END_SERIALIZE()
};

/// serializable SpEnoteCore
struct ser_SpEnoteCore final
{
    /// Ko
    rct::key onetime_address;
    /// C
    rct::key amount_commitment;

    BEGIN_SERIALIZE()
        FIELD(onetime_address)
        FIELD(amount_commitment)
    END_SERIALIZE()
};

/// serializable SpEnoteImageCore
struct ser_SpEnoteImageCore final
{
    /// K"
    rct::key masked_address;
    /// C"
    rct::key masked_commitment;
    /// KI
    crypto::key_image key_image;

    BEGIN_SERIALIZE()
        FIELD(masked_address)
        FIELD(masked_commitment)
        FIELD(key_image)
    END_SERIALIZE()
};

/// partially serializable BulletproofPlus2
struct ser_BulletproofPlus2_PARTIAL final
{
    //rct::keyV V;  (not serializable here)
    rct::key A, A1, B;
    rct::key r1, s1, d1;
    rct::keyV L, R;

    BEGIN_SERIALIZE()
        FIELD(A)
        FIELD(A1)
        FIELD(B)
        FIELD(r1)
        FIELD(s1)
        FIELD(d1)
        FIELD(L)
        FIELD(R)
    END_SERIALIZE()
};

/// partially serializable rct::clsag
struct ser_clsag_PARTIAL final
{
    rct::keyV s; // scalars
    rct::key c1;

    //rct::key I; // signing key image   (not serializable here)
    rct::key D; // commitment key image

    BEGIN_SERIALIZE()
        FIELD(s)
        FIELD(c1)
        FIELD(D)
    END_SERIALIZE()
};

/// serializable SpCompositionProof
struct ser_SpCompositionProof final
{
    // challenge
    rct::key c;
    // responses
    rct::key r_t1;
    rct::key r_t2;
    rct::key r_ki;
    // intermediate proof key
    rct::key K_t1;

    BEGIN_SERIALIZE()
        FIELD(c)
        FIELD(r_t1)
        FIELD(r_t2)
        FIELD(r_ki)
        FIELD(K_t1)
    END_SERIALIZE()
};

/// serializable GrootleProof
struct ser_GrootleProof final
{
    rct::key A;
    rct::key B;
    rct::keyM f;
    rct::keyV X;
    rct::key zA;
    rct::key z;

    BEGIN_SERIALIZE()
        FIELD(A)
        FIELD(B)
        FIELD(f)
        FIELD(X)
        FIELD(zA)
        FIELD(z)
    END_SERIALIZE()
};

/// partially serializable SpBinnedReferenceSetV1
struct ser_SpBinnedReferenceSetV1_PARTIAL final
{
    /// bin configuration details (shared by all bins)
    //SpBinnedReferenceSetConfigV1 bin_config;  (not serializable here)
    /// bin generator seed (shared by all bins)
    //rct::key bin_generator_seed;              (not serializable here)
    /// rotation factor (shared by all bins)
    std::uint16_t bin_rotation_factor;
    /// bin loci (serializable as index offsets)
    std::vector<std::uint64_t> bin_loci_COMPACT;

    BEGIN_SERIALIZE()
        VARINT_FIELD(bin_rotation_factor)
            static_assert(sizeof(bin_rotation_factor) == sizeof(ref_set_bin_dimension_v1_t), "");
        FIELD(bin_loci_COMPACT)
    END_SERIALIZE()
};

/// serializable LegacyEnoteImageV2
struct ser_LegacyEnoteImageV2 final
{
    /// masked commitment (aka 'pseudo-output commitment')
    rct::key masked_commitment;
    /// legacy key image
    crypto::key_image key_image;

    BEGIN_SERIALIZE()
        FIELD(masked_commitment)
        FIELD(key_image)
    END_SERIALIZE()
};

/// serializable SpEnoteImageV1
struct ser_SpEnoteImageV1 final
{
    /// enote image core
    ser_SpEnoteImageCore core;

    BEGIN_SERIALIZE()
        FIELD(core)
    END_SERIALIZE()
};

/// serializable SpCoinbaseEnoteV1
struct ser_SpCoinbaseEnoteV1 final
{
    /// enote core (one-time address, amount commitment)
    ser_SpCoinbaseEnoteCore core;

    /// addr_tag_enc
    ser_encrypted_address_tag_t addr_tag_enc;
    /// view_tag
    unsigned char view_tag;

    BEGIN_SERIALIZE()
        FIELD(core)
        FIELD(addr_tag_enc)    static_assert(sizeof(addr_tag_enc) == sizeof(jamtis::encrypted_address_tag_t), "");
        VARINT_FIELD(view_tag) static_assert(sizeof(view_tag) == sizeof(jamtis::view_tag_t), "");
    END_SERIALIZE()
};

/// serializable SpEnoteV1
struct ser_SpEnoteV1 final
{
    /// enote core (one-time address, amount commitment)
    ser_SpEnoteCore core;

    /// enc(a)
    ser_encoded_amount_t encoded_amount;
    /// addr_tag_enc
    ser_encrypted_address_tag_t addr_tag_enc;
    /// view_tag
    unsigned char view_tag;

    BEGIN_SERIALIZE()
        FIELD(core)
        FIELD(encoded_amount)  static_assert(sizeof(encoded_amount) == sizeof(jamtis::encoded_amount_t), "");
        FIELD(addr_tag_enc)    static_assert(sizeof(addr_tag_enc) == sizeof(jamtis::encrypted_address_tag_t), "");
        VARINT_FIELD(view_tag) static_assert(sizeof(view_tag) == sizeof(jamtis::view_tag_t), "");
    END_SERIALIZE()
};

/// partially serializable SpBalanceProofV1
struct ser_SpBalanceProofV1_PARTIAL final
{
    /// an aggregate set of BP+ proofs (partial serialization)
    ser_BulletproofPlus2_PARTIAL bpp2_proof_PARTIAL;
    /// the remainder blinding factor
    rct::key remainder_blinding_factor;

    BEGIN_SERIALIZE()
        FIELD(bpp2_proof_PARTIAL)
        FIELD(remainder_blinding_factor)
    END_SERIALIZE()
};

/// partially serializable LegacyRingSignatureV4
struct ser_LegacyRingSignatureV4_PARTIAL final
{
    /// a clsag proof
    ser_clsag_PARTIAL clsag_proof_PARTIAL;
    /// on-chain indices of the proof's ring members (serializable as index offsets)
    std::vector<std::uint64_t> reference_set_COMPACT;

    BEGIN_SERIALIZE()
        FIELD(clsag_proof_PARTIAL)
        FIELD(reference_set_COMPACT)
    END_SERIALIZE()
};

/// serializable SpImageProofV1
struct ser_SpImageProofV1 final
{
    /// a seraphis composition proof
    ser_SpCompositionProof composition_proof;

    BEGIN_SERIALIZE()
        FIELD(composition_proof)
    END_SERIALIZE()
};

/// partially serializable SpMembershipProofV1 (does not include config info)
struct ser_SpMembershipProofV1_PARTIAL final
{
    /// a grootle proof
    ser_GrootleProof grootle_proof;
    /// binned representation of ledger indices of enotes referenced by the proof
    ser_SpBinnedReferenceSetV1_PARTIAL binned_reference_set_PARTIAL;
    /// ref set size = n^m
    //std::size_t ref_set_decomp_n;  (not serializable here)
    //std::size_t ref_set_decomp_m;  (not serializable here)

    BEGIN_SERIALIZE()
        FIELD(grootle_proof)
        FIELD(binned_reference_set_PARTIAL)
    END_SERIALIZE()
};

/// serializable SpTxSupplementV1
struct ser_SpTxSupplementV1 final
{
    /// xKe: enote ephemeral pubkeys for outputs
    std::vector<crypto::x25519_pubkey> output_enote_ephemeral_pubkeys;
    /// tx memo
    std::vector<unsigned char> tx_extra;

    BEGIN_SERIALIZE()
        FIELD(output_enote_ephemeral_pubkeys)
        FIELD(tx_extra)
    END_SERIALIZE()
};

/// serializable SpTxCoinbaseV1
struct ser_SpTxCoinbaseV1 final
{
    /// semantic rules version
    SpTxCoinbaseV1::SemanticRulesVersion tx_semantic_rules_version;

    /// height of the block whose block reward this coinbase tx disperses
    std::uint64_t block_height;
    /// block reward dispersed by this coinbase tx
    rct::xmr_amount block_reward;
    /// tx outputs (new enotes)
    std::vector<ser_SpCoinbaseEnoteV1> outputs;
    /// supplemental data for tx
    ser_SpTxSupplementV1 tx_supplement;

    BEGIN_SERIALIZE()
        VARINT_FIELD(tx_semantic_rules_version)
        VARINT_FIELD(block_height)
        VARINT_FIELD(block_reward)
        FIELD(outputs)
        FIELD(tx_supplement)
    END_SERIALIZE()
};

/// serializable SpTxSquashedV1
struct ser_SpTxSquashedV1 final
{
    /// semantic rules version
    SpTxSquashedV1::SemanticRulesVersion tx_semantic_rules_version;

    /// legacy tx input images (spent legacy enotes)
    std::vector<ser_LegacyEnoteImageV2> legacy_input_images;
    /// seraphis tx input images (spent seraphis enotes)
    std::vector<ser_SpEnoteImageV1> sp_input_images;
    /// tx outputs (new enotes)
    std::vector<ser_SpEnoteV1> outputs;
    /// balance proof (balance proof and range proofs)
    ser_SpBalanceProofV1_PARTIAL balance_proof;
    /// ring signature proofs: membership and ownership/key-image-legitimacy for each legacy input
    std::vector<ser_LegacyRingSignatureV4_PARTIAL> legacy_ring_signatures;
    /// composition proofs: ownership/key-image-legitimacy for each seraphis input
    std::vector<ser_SpImageProofV1> sp_image_proofs;
    /// Grootle proofs on squashed enotes: membership for each seraphis input
    std::vector<ser_SpMembershipProofV1_PARTIAL> sp_membership_proofs;
    /// supplemental data for tx
    ser_SpTxSupplementV1 tx_supplement;
    /// the transaction fee (discretized representation)
    unsigned char tx_fee;

    BEGIN_SERIALIZE()
        VARINT_FIELD(tx_semantic_rules_version)
        FIELD(legacy_input_images)
        FIELD(sp_input_images)
        FIELD(outputs)
        FIELD(balance_proof)
        FIELD(legacy_ring_signatures)
        FIELD(sp_image_proofs)
        FIELD(sp_membership_proofs)
        FIELD(tx_supplement)
        VARINT_FIELD(tx_fee) static_assert(sizeof(tx_fee) == sizeof(DiscretizedFee), "");
    END_SERIALIZE()
};

/// serializable JamtisDestinationV1
struct ser_JamtisDestinationV1 final
{
    /// K_1 (address spend key)
    rct::key addr_K1;
    /// xK_2 (address view key)
    crypto::x25519_pubkey addr_K2;
    /// xK_3 (DH base key)
    crypto::x25519_pubkey addr_K3;
    /// addr_tag
    ser_address_tag_t addr_tag;

    BEGIN_SERIALIZE()
        FIELD(addr_K1)
        FIELD(addr_K2)
        FIELD(addr_K3)
        FIELD(addr_tag)    static_assert(sizeof(addr_tag) == sizeof(jamtis::address_tag_t), "");
    END_SERIALIZE()
};

/// serializable JamtisPaymentProposalV1
struct ser_JamtisPaymentProposalV1 final
{
    /// destination address
    ser_JamtisDestinationV1 destination;
    /// amount
    rct::xmr_amount amount;
    /// enote ephemeral private key
    crypto::x25519_scalar enote_ephemeral_privkey;
    /// memo elements
    std::vector<unsigned char> partial_memo;

    BEGIN_SERIALIZE()
        FIELD(destination)
        FIELD(amount)
        FIELD(enote_ephemeral_privkey)
        FIELD(partial_memo)
    END_SERIALIZE()
};

/// serializable JamtisPaymentProposalV1
struct ser_JamtisPaymentProposalSelfSendV1 final
{
    /// destination address
    ser_JamtisDestinationV1 destination;
    /// amount
    rct::xmr_amount amount;
    /// selfspend type
    unsigned char type;
    /// enote ephemeral private key
    crypto::x25519_scalar enote_ephemeral_privkey;
    /// memo elements
    std::vector<unsigned char> partial_memo;

    BEGIN_SERIALIZE()
        FIELD(destination)
        FIELD(amount)
        FIELD(type)
        FIELD(enote_ephemeral_privkey)
        FIELD(partial_memo)
    END_SERIALIZE()
};


// EnoteStore serialization

// LegacyEnote types
struct ser_LegacyEnoteV1 final
{
    /// Ko
    rct::key onetime_address;
    /// a
    rct::xmr_amount amount;

    BEGIN_SERIALIZE()
        FIELD(onetime_address)
        FIELD(amount)
    END_SERIALIZE()
};

struct ser_LegacyEnoteV2 final
{
    /// Ko
    rct::key onetime_address;
    /// C
    rct::key amount_commitment;
    /// enc(x)
    rct::key encoded_amount_blinding_factor;
    /// enc(a)
    rct::key encoded_amount;

    BEGIN_SERIALIZE()
        FIELD(onetime_address)
        FIELD(amount_commitment)
        FIELD(encoded_amount_blinding_factor)
        FIELD(encoded_amount)
    END_SERIALIZE()
};

struct ser_LegacyEnoteV3 final
{
    /// Ko
    rct::key onetime_address;
    /// C
    rct::key amount_commitment;
    /// enc(a)
    ser_encoded_amount_t encoded_amount;

    BEGIN_SERIALIZE()
        FIELD(onetime_address)
        FIELD(amount_commitment)
        FIELD(encoded_amount)
    END_SERIALIZE()
};


struct ser_LegacyEnoteV4 final
{
    /// Ko
    rct::key onetime_address;
    /// a
    rct::xmr_amount amount;
    /// view_tag
    unsigned char view_tag;

    BEGIN_SERIALIZE()
        FIELD(onetime_address)
        FIELD(amount)
        FIELD(view_tag)
    END_SERIALIZE()
};


struct ser_LegacyEnoteV5 final
{
    /// Ko
    rct::key onetime_address;
    /// C
    rct::key amount_commitment;
    /// enc(a)
    ser_encoded_amount_t encoded_amount;
    /// view_tag
    unsigned char view_tag;

    BEGIN_SERIALIZE()
        FIELD(onetime_address)
        FIELD(amount_commitment)
        FIELD(encoded_amount)
        FIELD(view_tag)
    END_SERIALIZE()
};
struct ser_SpEnoteOriginContextV1 final
{
    /// block index of tx (-1 if index is unknown)
    std::uint64_t block_index;
    /// timestamp of tx's block (-1 if timestamp is unknown)
    std::uint64_t block_timestamp;
    /// tx id of the tx (0 if tx is unknown)
    rct::key transaction_id;
    /// index of the enote in the tx's output set (-1 if index is unknown)
    std::uint64_t enote_tx_index;
    /// ledger index of the enote (-1 if index is unknown)
    std::uint64_t enote_ledger_index;
    /// origin status (off-chain by default)
    unsigned char origin_status;
    /// tx memo
    std::vector<unsigned char> tx_extra;

    BEGIN_SERIALIZE_OBJECT();
        FIELD(block_index);
        FIELD(block_timestamp);
        FIELD(transaction_id);
        FIELD(enote_tx_index);
        FIELD(enote_ledger_index);
        FIELD(origin_status);
        FIELD(tx_extra);
    END_SERIALIZE();
};

struct ser_SpEnoteSpentContextV1 final
{
    /// block index of tx where it was spent (-1 if unspent or index is unknown)
    std::uint64_t block_index;
    /// timestamp of tx's block (-1 if timestamp is unknown)
    std::uint64_t block_timestamp;
    /// tx id of the tx where it was spent (0 if unspent or tx is unknown)
    rct::key transaction_id;
    /// spent status (unspent by default)
    unsigned char spent_status;

    BEGIN_SERIALIZE_OBJECT();
        FIELD(block_index);
        FIELD(block_timestamp);
        FIELD(transaction_id);
        FIELD(spent_status);
    END_SERIALIZE();
};

using ser_LegacyEnoteVariant = tools::variant<ser_LegacyEnoteV1,ser_LegacyEnoteV2, ser_LegacyEnoteV3, ser_LegacyEnoteV4, ser_LegacyEnoteV5>;
struct ser_LegacyIntermediateEnoteRecord final
{
    /// original enote
    ser_LegacyEnoteVariant enote;
    /// the enote's ephemeral pubkey
    rct::key enote_ephemeral_pubkey;
    /// enote view privkey = [address: Hn(r K^v, t)] [subaddress (i): Hn(r K^{v,i}, t) + Hn(k^v, i)]
    crypto::secret_key enote_view_extension;
    /// a: amount
    rct::xmr_amount amount;
    /// x: amount blinding factor
    crypto::secret_key amount_blinding_factor;
    /// i: legacy address index (if true, then it's owned by a subaddress)
    boost::optional<cryptonote::subaddress_index> address_index;
    /// t: the enote's index in its transaction
    std::uint64_t tx_output_index;
    /// u: the enote's unlock time
    std::uint64_t unlock_time;

    BEGIN_SERIALIZE_OBJECT();
        FIELD(enote);
        FIELD(enote_ephemeral_pubkey);
        FIELD(enote_view_extension);
        FIELD(amount);
        FIELD(amount_blinding_factor);
        if (address_index)
            FIELD(address_index.get());
        FIELD(tx_output_index);
        FIELD(unlock_time);
    END_SERIALIZE();
};

struct ser_LegacyEnoteRecord final
{
    /// original enote
    ser_LegacyEnoteVariant enote;
    /// the enote's ephemeral pubkey
    rct::key enote_ephemeral_pubkey;
    /// enote view privkey = [address: Hn(r K^v, t)] [subaddress (i): Hn(r K^{v,i}, t) + Hn(k^v, i)]
    crypto::secret_key enote_view_extension;
    /// a: amount
    rct::xmr_amount amount;
    /// x: amount blinding factor
    crypto::secret_key amount_blinding_factor;
    /// KI: key image
    crypto::key_image key_image;
    /// i: legacy address index (if true, then it's owned by a subaddress)
    boost::optional<cryptonote::subaddress_index> address_index;
    /// t: the enote's index in its transaction
    std::uint64_t tx_output_index;
    /// u: the enote's unlock time
    std::uint64_t unlock_time;

    BEGIN_SERIALIZE_OBJECT();
        FIELD(enote);
        FIELD(enote_ephemeral_pubkey);
        FIELD(enote_view_extension);
        FIELD(amount);
        FIELD(amount_blinding_factor);
        FIELD(key_image)
        if (address_index)
            FIELD(address_index.get());
        FIELD(tx_output_index);
        FIELD(unlock_time);
    END_SERIALIZE();
};

struct ser_LegacyContextualIntermediateEnoteRecordV1 final
{
    /// info about the enote
    ser_LegacyIntermediateEnoteRecord intermediate_record;
    /// info about where the enote was found
    ser_SpEnoteOriginContextV1 origin_context;

    BEGIN_SERIALIZE_OBJECT();
        FIELD(intermediate_record);
        FIELD(origin_context);
    END_SERIALIZE();
};

struct ser_LegacyContextualEnoteRecordV1 final
{
    /// info about the enote
    ser_LegacyEnoteRecord record;
    /// info about where the enote was found
    ser_SpEnoteOriginContextV1 origin_context;
    /// info about where the enote was spent
    ser_SpEnoteSpentContextV1 spent_context;

    BEGIN_SERIALIZE_OBJECT();
        FIELD(record);
        FIELD(origin_context);
        FIELD(spent_context);
    END_SERIALIZE();
};


using ser_SpEnoteVariant = tools::variant<ser_SpCoinbaseEnoteV1, ser_SpEnoteV1>;
struct ser_SpEnoteRecordV1 final
{
    /// original enote
    ser_SpEnoteVariant enote;
    /// the enote's ephemeral pubkey
    crypto::x25519_pubkey enote_ephemeral_pubkey;
    /// context of the tx input(s) associated with this enote
    rct::key input_context;
    /// k_{g, sender} + k_{g, address}: enote view extension for G component
    crypto::secret_key enote_view_extension_g;
    /// k_{x, sender} + k_{x, address}: enote view extension for X component (excludes k_vb)
    crypto::secret_key enote_view_extension_x;
    /// k_{u, sender} + k_{u, address}: enote view extension for U component (excludes k_m)
    crypto::secret_key enote_view_extension_u;
    /// a: amount
    rct::xmr_amount amount;
    /// x: amount blinding factor
    crypto::secret_key amount_blinding_factor;
    /// KI: key image
    crypto::key_image key_image;
    /// j: jamtis address index
    ser_address_index_t address_index;
    /// jamtis enote type
    unsigned char type;

    BEGIN_SERIALIZE_OBJECT();
        FIELD(enote);
        FIELD(enote_ephemeral_pubkey);
        FIELD(input_context);
        FIELD(enote_view_extension_g);
        FIELD(enote_view_extension_x);
        FIELD(enote_view_extension_u);
        FIELD(amount);
        FIELD(amount_blinding_factor);
        FIELD(key_image);
        FIELD(address_index);
        FIELD(type);
    END_SERIALIZE();
};

struct ser_SpContextualEnoteRecordV1 final
{
    /// info about the enote
    ser_SpEnoteRecordV1 record;
    /// info about where the enote was found
    ser_SpEnoteOriginContextV1 origin_context;
    /// info about where the enote was spent
    ser_SpEnoteSpentContextV1 spent_context;

    BEGIN_SERIALIZE_OBJECT();
        FIELD(record);
        FIELD(origin_context);
        FIELD(spent_context);
    END_SERIALIZE();
};

struct ser_CheckpointCacheConfig final
{
    /// number of checkpoints that shouldn't be pruned
    std::uint64_t num_unprunable;
    /// maximum separation between checkpoints
    std::uint64_t max_separation;
    /// density factor for calibrating the decay rate of checkpoint density
    std::uint64_t density_factor;

    BEGIN_SERIALIZE_OBJECT();
        FIELD(num_unprunable);
        FIELD(max_separation);
        FIELD(density_factor);
    END_SERIALIZE();
};
struct ser_CheckpointCache final
{
    /// minimum checkpoint index
    std::uint64_t min_checkpoint_index;
    /// config
    ser_CheckpointCacheConfig config;
    /// window size
    std::uint64_t window_size;
    /// stored checkpoints
    std::map<std::uint64_t, rct::key> checkpoints;

    BEGIN_SERIALIZE_OBJECT();
        FIELD(min_checkpoint_index);
        FIELD(config);
        FIELD(window_size);
        FIELD(checkpoints);
    END_SERIALIZE();
};

struct ser_SpEnoteStore final
{
    /// legacy intermediate enotes: [ legacy identifier : legacy intermediate record ]
    std::unordered_map<rct::key, ser_LegacyContextualIntermediateEnoteRecordV1>
        legacy_intermediate_contextual_enote_records;
    /// legacy enotes: [ legacy identifier : legacy record ]
    std::unordered_map<rct::key, ser_LegacyContextualEnoteRecordV1> legacy_contextual_enote_records;
    /// seraphis enotes: [ seraphis KI : seraphis record ]
    std::unordered_map<crypto::key_image, ser_SpContextualEnoteRecordV1> sp_contextual_enote_records;
    /// saved legacy key images from txs with seraphis selfsends (i.e. from txs we created)
    /// [ legacy KI : spent context ]
    std::unordered_map<crypto::key_image, ser_SpEnoteSpentContextV1> legacy_key_images_in_sp_selfsends;
    /// legacy duplicate tracker for dealing with enotes that have duplicated key images
    /// [ Ko : [ legacy identifier ] ]
    std::unordered_map<rct::key, std::unordered_set<rct::key>> tracked_legacy_onetime_address_duplicates;
    /// legacy onetime addresses attached to known legacy enotes
    /// [ legacy KI : legacy Ko ]
    std::unordered_map<crypto::key_image, rct::key> legacy_key_images;
    /// cached block ids in range: [refresh index, end of known legacy-supporting chain]
    ser_CheckpointCache legacy_block_id_cache;
    /// cached block ids in range:
    ///   [max(refresh index, first seraphis-enabled block), end of known seraphis-supporting chain]
    ser_CheckpointCache sp_block_id_cache;
    /// highest block that was legacy partialscanned (view-scan only)
    std::uint64_t legacy_partialscan_index;
    /// highest block that was legacy fullscanned (view-scan + comprehensive key image checks)
    std::uint64_t legacy_fullscan_index;
    /// highest block that was seraphis view-balance scanned
    std::uint64_t sp_scanned_index;
    /// configuration value: default spendable age; an enote is considered 'spendable' in the next block if it is
    ///   on-chain and the next block's index is >= 'enote origin index + max(1, default_spendable_age)'; legacy
    ///   enotes also have an unlock_time attribute on top of the default spendable age
    std::uint64_t default_spendable_age;

    BEGIN_SERIALIZE_OBJECT();
        FIELD(legacy_intermediate_contextual_enote_records);
        FIELD(legacy_contextual_enote_records);
        FIELD(sp_contextual_enote_records);
        FIELD(legacy_key_images);
        FIELD(legacy_block_id_cache);
        FIELD(sp_block_id_cache);
        FIELD(legacy_partialscan_index);
        FIELD(legacy_fullscan_index);
        FIELD(sp_scanned_index);
        FIELD(default_spendable_age);
    END_SERIALIZE();
};

} //namespace serialization
} //namespace sp

BLOB_SERIALIZER(sp::serialization::ser_address_index_t);
BLOB_SERIALIZER(sp::serialization::ser_address_tag_t);
BLOB_SERIALIZER(sp::serialization::ser_encrypted_address_tag_t);
BLOB_SERIALIZER(sp::serialization::ser_encoded_amount_t);

BLOB_SERIALIZER(sp::serialization::ser_LegacyEnoteVariant);
BLOB_SERIALIZER(sp::serialization::ser_SpEnoteVariant);

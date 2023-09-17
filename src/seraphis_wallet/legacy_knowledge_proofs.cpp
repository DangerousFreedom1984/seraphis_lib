// Copyright (c) 2014-2023, The Monero Project
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
//

//paired header
#include "legacy_knowledge_proofs.h"

// local headers
#include "common/base58.h"
#include "common/i18n.h"
#include "common/unordered_containers_boost_serialization.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "cryptonote_basic/account_boost_serialization.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "device/device.hpp"
#include "net/abstract_http_client.h"
#include "net/http.h"
#include "net/http_client.h"
#include "ringct/rctTypes.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "rpc/core_rpc_server_error_codes.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_mocks/enote_finding_context_mocks.h"
#include "serialization/binary_utils.h"
#include "serialization/containers.h"
#include "serialization/crypto.h"
#include "serialization/pair.h"
#include "serialization/string.h"
#include "serialization/tuple.h"
#include "storages/http_abstract_invoke.h"
#include "wallet/wallet2_basic/wallet2_storage.h"
#include "wallet/wallet_errors.h"

// third party headers
#include <boost/archive/binary_iarchive.hpp>
#include <boost/optional/optional.hpp>
#include <boost/thread/pthread/recursive_mutex.hpp>
#include "boost/archive/portable_binary_iarchive.hpp"

// standard headers
#include <chrono>
#include <cstdint>
#include <string>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_wallet"

//----------------------------------------------------------------------------------------------------
/// Auxiliary Functions
//----------------------------------------------------------------------------------------------------
static bool get_pruned_tx(const cryptonote::COMMAND_RPC_GET_TRANSACTIONS::entry &entry,
    cryptonote::transaction &tx,
    crypto::hash &tx_hash)
{
    cryptonote::blobdata bd;

    // easy case if we have the whole tx
    if (!entry.as_hex.empty() || (!entry.prunable_as_hex.empty() && !entry.pruned_as_hex.empty()))
    {
        CHECK_AND_ASSERT_MES(epee::string_tools::parse_hexstr_to_binbuff(
                                 entry.as_hex.empty() ? entry.pruned_as_hex + entry.prunable_as_hex : entry.as_hex, bd),
            false,
            "Failed to parse tx data");
        CHECK_AND_ASSERT_MES(cryptonote::parse_and_validate_tx_from_blob(bd, tx), false, "Invalid tx data");
        tx_hash = cryptonote::get_transaction_hash(tx);
        // if the hash was given, check it matches
        CHECK_AND_ASSERT_MES(entry.tx_hash.empty() || epee::string_tools::pod_to_hex(tx_hash) == entry.tx_hash,
            false,
            "Response claims a different hash than the data yields");
        return true;
    }
    // case of a pruned tx with its prunable data hash
    if (!entry.pruned_as_hex.empty() && !entry.prunable_hash.empty())
    {
        crypto::hash ph;
        CHECK_AND_ASSERT_MES(
            epee::string_tools::hex_to_pod(entry.prunable_hash, ph), false, "Failed to parse prunable hash");
        CHECK_AND_ASSERT_MES(
            epee::string_tools::parse_hexstr_to_binbuff(entry.pruned_as_hex, bd), false, "Failed to parse pruned data");
        CHECK_AND_ASSERT_MES(parse_and_validate_tx_base_from_blob(bd, tx), false, "Invalid base tx data");
        // only v2 txes can calculate their txid after pruned
        if (bd[0] > 1)
        {
            tx_hash = cryptonote::get_pruned_transaction_hash(tx, ph);
        }
        else
        {
            // for v1, we trust the dameon
            CHECK_AND_ASSERT_MES(
                epee::string_tools::hex_to_pod(entry.tx_hash, tx_hash), false, "Failed to parse tx hash");
        }
        return true;
    }
    return false;
}
//----------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------
static bool is_out_to_acc(const cryptonote::account_public_address &address,
    const crypto::public_key &out_key,
    const crypto::key_derivation &derivation,
    const std::vector<crypto::key_derivation> &additional_derivations,
    const size_t output_index,
    const boost::optional<crypto::view_tag> &view_tag_opt,
    crypto::key_derivation &found_derivation)
{
    crypto::public_key derived_out_key;
    bool found = false;
    bool r;
    // first run quick check if output has matching view tag, otherwise output
    // should not belong to account
    if (cryptonote::out_can_be_to_acc(view_tag_opt, derivation, output_index))
    {
        // if view tag match, run slower check deriving output pub key and comparing
        // to expected
        r = crypto::derive_public_key(derivation, output_index, address.m_spend_public_key, derived_out_key);
        THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, "Failed to derive public key");
        if (out_key == derived_out_key)
        {
            found            = true;
            found_derivation = derivation;
        }
    }

    if (!found && !additional_derivations.empty())
    {
        const crypto::key_derivation &additional_derivation = additional_derivations[output_index];
        if (cryptonote::out_can_be_to_acc(view_tag_opt, additional_derivation, output_index))
        {
            r = crypto::derive_public_key(
                additional_derivation, output_index, address.m_spend_public_key, derived_out_key);
            THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, "Failed to derive public key");
            if (out_key == derived_out_key)
            {
                found            = true;
                found_derivation = additional_derivation;
            }
        }
    }
    return found;
}
//----------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------
static void check_tx_key_helper(const cryptonote::transaction &tx,
    const crypto::key_derivation &derivation,
    const std::vector<crypto::key_derivation> &additional_derivations,
    const cryptonote::account_public_address &address,
    uint64_t &received)
{
    received = 0;

    for (size_t n = 0; n < tx.vout.size(); ++n)
    {
        crypto::public_key output_public_key;
        if (!get_output_public_key(tx.vout[n], output_public_key))
            continue;

        crypto::key_derivation found_derivation;
        if (is_out_to_acc(address,
                output_public_key,
                derivation,
                additional_derivations,
                n,
                get_output_view_tag(tx.vout[n]),
                found_derivation))
        {
            uint64_t amount;
            if (tx.version == 1 || tx.rct_signatures.type == rct::RCTTypeNull)
            {
                amount = tx.vout[n].amount;
            }
            else
            {
                crypto::secret_key scalar1;
                crypto::derivation_to_scalar(found_derivation, n, scalar1);
                rct::ecdhTuple ecdh_info = tx.rct_signatures.ecdhInfo[n];
                rct::ecdhDecode(ecdh_info,
                    rct::sk2rct(scalar1),
                    tx.rct_signatures.type == rct::RCTTypeBulletproof2 || tx.rct_signatures.type == rct::RCTTypeCLSAG ||
                        tx.rct_signatures.type == rct::RCTTypeBulletproofPlus);
                const rct::key C = tx.rct_signatures.outPk[n].mask;
                rct::key Ctmp;
                THROW_WALLET_EXCEPTION_IF(
                    sc_check(ecdh_info.mask.bytes) != 0, tools::error::wallet_internal_error, "Bad ECDH input mask");
                THROW_WALLET_EXCEPTION_IF(sc_check(ecdh_info.amount.bytes) != 0,
                    tools::error::wallet_internal_error,
                    "Bad ECDH input amount");
                rct::addKeys2(Ctmp, ecdh_info.mask, ecdh_info.amount, rct::H);
                if (rct::equalKeys(C, Ctmp))
                    amount = rct::h2d(ecdh_info.amount);
                else
                    amount = 0;
            }
            received += amount;
        }
    }
}
//----------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------
static void throw_on_rpc_response_error(bool r,
    const epee::json_rpc::error &error,
    const std::string &status,
    const char *method)
{
    // Treat all RPC payment access errors the same, whether payment is actually required or not
    THROW_WALLET_EXCEPTION_IF(
        error.code == CORE_RPC_ERROR_CODE_INVALID_CLIENT, tools::error::deprecated_rpc_access, method);
    THROW_WALLET_EXCEPTION_IF(
        error.code, tools::error::wallet_coded_rpc_error, method, error.code, get_rpc_server_error_message(error.code));
    THROW_WALLET_EXCEPTION_IF(!r, tools::error::no_connection_to_daemon, method);
    // empty string -> not connection
    THROW_WALLET_EXCEPTION_IF(status.empty(), tools::error::no_connection_to_daemon, method);

    THROW_WALLET_EXCEPTION_IF(status == CORE_RPC_STATUS_BUSY, tools::error::daemon_busy, method);
    THROW_WALLET_EXCEPTION_IF(status == CORE_RPC_STATUS_PAYMENT_REQUIRED, tools::error::deprecated_rpc_access, method);
    // Deprecated RPC payment access endpoints would set status to "Client signature does not verify for <method>"
    THROW_WALLET_EXCEPTION_IF(
        status.compare(0, 16, "Client signature") == 0, tools::error::deprecated_rpc_access, method);
}
//----------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------
static bool get_tx_key(const crypto::hash &txid,
    const serializable_unordered_map<crypto::hash, crypto::secret_key> tx_keys_stored,
    const serializable_unordered_map<crypto::hash, std::vector<crypto::secret_key>> additional_tx_keys_stored,
    crypto::secret_key &tx_key,
    std::vector<crypto::secret_key> &additional_tx_keys)
{
    additional_tx_keys.clear();
    const std::unordered_map<crypto::hash, crypto::secret_key>::const_iterator i = tx_keys_stored.find(txid);
    if (i == tx_keys_stored.end())
        return false;
    tx_key = i->second;
    if (tx_key == crypto::null_skey)
        return false;
    const auto j = additional_tx_keys_stored.find(txid);
    if (j != additional_tx_keys_stored.end())
        additional_tx_keys = j->second;
    return true;
}
//----------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------
static bool is_spent(const wallet2_basic::transfer_details &td, bool strict)
{
    if (strict)
    {
        return td.m_spent && td.m_spent_height > 0;
    }
    else
    {
        return td.m_spent;
    }
}
//----------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------
static boost::optional<cryptonote::subaddress_index> get_subaddress_index(const cryptonote::account_public_address &address,
    const wallet2_basic::cache &wallet_cache)
{
    auto index = wallet_cache.m_subaddresses.find(address.m_spend_public_key);
    if (index == wallet_cache.m_subaddresses.end())
        return boost::none;
    return index->second;
}
//----------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------
static std::map<uint32_t, uint64_t> balance_per_subaddress(uint32_t index_major,
    bool strict,
    const wallet2_basic::cache &wallet_cache)
{
    std::map<uint32_t, uint64_t> amount_per_subaddr;
    for (const auto &td : wallet_cache.m_transfers)
    {
        if (td.m_subaddr_index.major == index_major && !is_spent(td, strict) && !td.m_frozen)
        {
            auto found = amount_per_subaddr.find(td.m_subaddr_index.minor);
            if (found == amount_per_subaddr.end())
                amount_per_subaddr[td.m_subaddr_index.minor] = td.amount();
            else
                found->second += td.amount();
        }
    }
    if (!strict)
    {
        for (const auto &utx : wallet_cache.m_unconfirmed_txs)
        {
            if (utx.second.m_subaddr_account == index_major &&
                utx.second.m_state != wallet2_basic::unconfirmed_transfer_details::failed)
            {
                // all changes go to 0-th subaddress (in the current subaddress account)
                auto found = amount_per_subaddr.find(0);
                if (found == amount_per_subaddr.end())
                    amount_per_subaddr[0] = utx.second.m_change;
                else
                    found->second += utx.second.m_change;

                // add transfers to same wallet
                for (const auto &dest : utx.second.m_dests)
                {
                    auto index = get_subaddress_index(dest.addr, wallet_cache);
                    if (index && (*index).major == index_major)
                    {
                        auto found = amount_per_subaddr.find((*index).minor);
                        if (found == amount_per_subaddr.end())
                            amount_per_subaddr[(*index).minor] = dest.amount;
                        else
                            found->second += dest.amount;
                    }
                }
            }
        }

        for (const auto &utx : wallet_cache.m_unconfirmed_payments)
        {
            if (utx.second.m_pd.m_subaddr_index.major == index_major)
            {
                amount_per_subaddr[utx.second.m_pd.m_subaddr_index.minor] += utx.second.m_pd.m_amount;
            }
        }
    }
    return amount_per_subaddr;
}
//----------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------
static uint64_t balance(uint32_t index_major, bool strict, const wallet2_basic::cache &wallet_cache)
{
    uint64_t amount = 0;
    for (const auto &i : balance_per_subaddress(index_major, strict, wallet_cache)) amount += i.second;
    return amount;
}
//----------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------
static uint64_t balance_all(bool strict, const wallet2_basic::cache &wallet_cache)
{
    uint64_t r = 0;
    for (uint32_t index_major = 0; index_major < wallet_cache.m_subaddress_labels.size(); ++index_major)
        r += balance(index_major, strict, wallet_cache);
    return r;
}

//----------------------------------------------------------------------------------------------------
// Legacy Knowledge Proofs
//----------------------------------------------------------------------------------------------------

std::string get_spend_proof_legacy(const crypto::hash &txid, const std::string &message,
    const wallet2_basic::cache &wallet_cache,
    const wallet2_basic::keys_data &wallet_keys_data,
    const std::unique_ptr<epee::net_utils::http::abstract_http_client> &http_client,
    const std::chrono::seconds &rpc_timeout)
{
    // 1. check if the wallet is not watch_only
    THROW_WALLET_EXCEPTION_IF(wallet_keys_data.m_watch_only,
        tools::error::wallet_internal_error,
        "get_spend_proof requires spend secret key and is not available for a watch-only wallet");

    // 2. fetch tx from daemon
    cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request req = AUTO_VAL_INIT(req);
    req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
    req.decode_as_json                         = false;
    req.prune                                  = true;
    cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response res = AUTO_VAL_INIT(res);
    bool r;
    {
        // const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
        r = epee::net_utils::invoke_http_json("/gettransactions", req, res, *http_client, rpc_timeout);
        THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, {}, res, "gettransactions");
        THROW_WALLET_EXCEPTION_IF(res.txs.size() != 1,
            tools::error::wallet_internal_error,
            "daemon returned wrong response for gettransactions, wrong txs count = " + std::to_string(res.txs.size()) +
                ", expected 1");
    }
    cryptonote::transaction tx;
    crypto::hash tx_hash;
    THROW_WALLET_EXCEPTION_IF(
        !get_pruned_tx(res.txs[0], tx, tx_hash), tools::error::wallet_internal_error, "Failed to get tx from daemon");

    std::vector<std::vector<crypto::signature>> signatures;

    // 3. get signature prefix hash
    std::string sig_prefix_data((const char *)&txid, sizeof(crypto::hash));
    sig_prefix_data += message;
    crypto::hash sig_prefix_hash;
    crypto::cn_fast_hash(sig_prefix_data.data(), sig_prefix_data.size(), sig_prefix_hash);

    // 4. Loop over all inputs
    for (size_t i = 0; i < tx.vin.size(); ++i)
    {
        const cryptonote::txin_to_key *const in_key = boost::get<cryptonote::txin_to_key>(std::addressof(tx.vin[i]));
        if (in_key == nullptr)
            continue;

        // 4.1 check if the key image belongs to us
        const auto found = wallet_cache.m_key_images.find(in_key->k_image);
        if (found == wallet_cache.m_key_images.end())
        {
            THROW_WALLET_EXCEPTION_IF(
                i > 0, tools::error::wallet_internal_error, "subset of key images belong to us, very weird!");
            THROW_WALLET_EXCEPTION_IF(true, tools::error::wallet_internal_error, "This tx wasn't generated by this wallet!");
        }

        // 4.2 derive the real output keypair
        const wallet2_basic::transfer_details &in_td          = wallet_cache.m_transfers[found->second];
        crypto::public_key in_tx_out_pkey      = in_td.get_public_key();
        const crypto::public_key in_tx_pub_key = get_tx_pub_key_from_extra(in_td.m_tx, in_td.m_pk_index);
        const std::vector<crypto::public_key> in_additionakl_tx_pub_keys =
            get_additional_tx_pub_keys_from_extra(in_td.m_tx);
        cryptonote::keypair in_ephemeral;
        crypto::key_image in_img;
        THROW_WALLET_EXCEPTION_IF(!generate_key_image_helper(wallet_keys_data.m_account.get_keys(),
                                      wallet_cache.m_subaddresses,
                                      in_tx_out_pkey,
                                      in_tx_pub_key,
                                      in_additionakl_tx_pub_keys,
                                      in_td.m_internal_output_index,
                                      in_ephemeral,
                                      in_img,
                                      wallet_keys_data.m_account.get_device()),
            tools::error::wallet_internal_error,
            "failed to generate key image");
        THROW_WALLET_EXCEPTION_IF(in_key->k_image != in_img, tools::error::wallet_internal_error, "key image mismatch");

        // 4.3 get output pubkeys in the ring
        const std::vector<uint64_t> absolute_offsets =
            cryptonote::relative_output_offsets_to_absolute(in_key->key_offsets);
        const size_t ring_size = in_key->key_offsets.size();
        THROW_WALLET_EXCEPTION_IF(
            absolute_offsets.size() != ring_size, tools::error::wallet_internal_error, "absolute offsets size is wrong");
        cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::request req = AUTO_VAL_INIT(req);
        req.outputs.resize(ring_size);
        for (size_t j = 0; j < ring_size; ++j)
        {
            req.outputs[j].amount = in_key->amount;
            req.outputs[j].index  = absolute_offsets[j];
        }
        cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::response res = AUTO_VAL_INIT(res);
        bool r;
        {
            // const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
            r = epee::net_utils::invoke_http_bin("/get_outs.bin", req, res, *http_client, rpc_timeout);
            THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "get_outs.bin", tools::error::get_outs_error, res.status);
            THROW_WALLET_EXCEPTION_IF(res.outs.size() != ring_size,
                tools::error::wallet_internal_error,
                "daemon returned wrong response for get_outs.bin, wrong amounts count = " +
                    std::to_string(res.outs.size()) + ", expected " + std::to_string(ring_size));
        }

        // 4.4 copy pubkey pointers
        std::vector<const crypto::public_key *> p_output_keys;
        for (const cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::outkey &out : res.outs) p_output_keys.push_back(&out.key);

        // 4.5 figure out real output index and secret key
        size_t sec_index = -1;
        for (size_t j = 0; j < ring_size; ++j)
        {
            if (res.outs[j].key == in_ephemeral.pub)
            {
                sec_index = j;
                break;
            }
        }
        THROW_WALLET_EXCEPTION_IF(sec_index >= ring_size, tools::error::wallet_internal_error, "secret index not found");

        // 4.6 generate ring sig for this input
        signatures.push_back(std::vector<crypto::signature>());
        std::vector<crypto::signature> &sigs = signatures.back();
        sigs.resize(in_key->key_offsets.size());
        crypto::generate_ring_signature(
            sig_prefix_hash, in_key->k_image, p_output_keys, in_ephemeral.sec, sec_index, sigs.data());
    }

    // 5. Encode proof
    std::string sig_str = "SpendProofV1";
    for (const std::vector<crypto::signature> &ring_sig : signatures)
        for (const crypto::signature &sig : ring_sig)
            sig_str += tools::base58::encode(std::string((const char *)&sig, sizeof(crypto::signature)));
    return sig_str;
}
//----------------------------------------------------------------------------------------------------
bool check_spend_proof_legacy(const crypto::hash &txid, const std::string &message, const std::string &sig_str,
    const std::unique_ptr<epee::net_utils::http::abstract_http_client> &http_client,
    const std::chrono::seconds &rpc_timeout)
{
    // 1. Check header
    const std::string header = "SpendProofV1";
    const size_t header_len  = header.size();
    THROW_WALLET_EXCEPTION_IF(sig_str.size() < header_len || sig_str.substr(0, header_len) != header,
        tools::error::wallet_internal_error,
        "Signature header check error");

    // 2. fetch tx from daemon
    cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request req = AUTO_VAL_INIT(req);
    req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
    req.decode_as_json                         = false;
    req.prune                                  = true;
    cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response res = AUTO_VAL_INIT(res);
    bool r;
    {
        // const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
        r = epee::net_utils::invoke_http_json("/gettransactions", req, res, *http_client, rpc_timeout);
        THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, {}, res, "gettransactions");
        THROW_WALLET_EXCEPTION_IF(res.txs.size() != 1,
            tools::error::wallet_internal_error,
            "daemon returned wrong response for gettransactions, wrong txs count = " + std::to_string(res.txs.size()) +
                ", expected 1");
    }

    cryptonote::transaction tx;
    crypto::hash tx_hash;
    THROW_WALLET_EXCEPTION_IF(
        !get_pruned_tx(res.txs[0], tx, tx_hash), tools::error::wallet_internal_error, "failed to get tx from daemon");

    // 3. check signature size
    size_t num_sigs = 0;
    for (size_t i = 0; i < tx.vin.size(); ++i)
    {
        const cryptonote::txin_to_key *const in_key = boost::get<cryptonote::txin_to_key>(std::addressof(tx.vin[i]));
        if (in_key != nullptr)
            num_sigs += in_key->key_offsets.size();
    }
    std::vector<std::vector<crypto::signature>> signatures = {std::vector<crypto::signature>(1)};
    const size_t sig_len =
        tools::base58::encode(std::string((const char *)&signatures[0][0], sizeof(crypto::signature))).size();
    if (sig_str.size() != header_len + num_sigs * sig_len)
    {
        return false;
    }

    // 4. decode base58
    signatures.clear();
    size_t offset = header_len;
    for (size_t i = 0; i < tx.vin.size(); ++i)
    {
        const cryptonote::txin_to_key *const in_key = boost::get<cryptonote::txin_to_key>(std::addressof(tx.vin[i]));
        if (in_key == nullptr)
            continue;
        signatures.resize(signatures.size() + 1);
        signatures.back().resize(in_key->key_offsets.size());
        for (size_t j = 0; j < in_key->key_offsets.size(); ++j)
        {
            std::string sig_decoded;
            THROW_WALLET_EXCEPTION_IF(!tools::base58::decode(sig_str.substr(offset, sig_len), sig_decoded),
                tools::error::wallet_internal_error,
                "Signature decoding error");
            THROW_WALLET_EXCEPTION_IF(sizeof(crypto::signature) != sig_decoded.size(),
                tools::error::wallet_internal_error,
                "Signature decoding error");
            memcpy(&signatures.back()[j], sig_decoded.data(), sizeof(crypto::signature));
            offset += sig_len;
        }
    }

    // 5. get signature prefix hash
    std::string sig_prefix_data((const char *)&txid, sizeof(crypto::hash));
    sig_prefix_data += message;
    crypto::hash sig_prefix_hash;
    crypto::cn_fast_hash(sig_prefix_data.data(), sig_prefix_data.size(), sig_prefix_hash);

    std::vector<std::vector<crypto::signature>>::const_iterator sig_iter = signatures.cbegin();

    // 6. Loop over all inputs
    for (size_t i = 0; i < tx.vin.size(); ++i)
    {
        const cryptonote::txin_to_key *const in_key = boost::get<cryptonote::txin_to_key>(std::addressof(tx.vin[i]));
        if (in_key == nullptr)
            continue;

        // 6.1 get output pubkeys in the ring
        cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::request req = AUTO_VAL_INIT(req);
        const std::vector<uint64_t> absolute_offsets =
            cryptonote::relative_output_offsets_to_absolute(in_key->key_offsets);
        req.outputs.resize(absolute_offsets.size());
        for (size_t j = 0; j < absolute_offsets.size(); ++j)
        {
            req.outputs[j].amount = in_key->amount;
            req.outputs[j].index  = absolute_offsets[j];
        }
        cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::response res = AUTO_VAL_INIT(res);
        bool r;
        {
            // const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
            r = epee::net_utils::invoke_http_bin("/get_outs.bin", req, res, *http_client, rpc_timeout);
            THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "get_outs.bin", tools::error::get_outs_error, res.status);
            THROW_WALLET_EXCEPTION_IF(res.outs.size() != req.outputs.size(),
                tools::error::wallet_internal_error,
                "daemon returned wrong response for get_outs.bin, wrong amounts count = " +
                    std::to_string(res.outs.size()) + ", expected " + std::to_string(req.outputs.size()));
        }

        // 6.2 copy pointers
        std::vector<const crypto::public_key *> p_output_keys;
        for (const cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::outkey &out : res.outs) p_output_keys.push_back(&out.key);

        // 6.3 check this ring
        if (!crypto::check_ring_signature(sig_prefix_hash, in_key->k_image, p_output_keys, sig_iter->data()))
            return false;
        ++sig_iter;
    }
    THROW_WALLET_EXCEPTION_IF(
        sig_iter != signatures.cend(), tools::error::wallet_internal_error, "Signature iterator didn't reach the end");
    return true;
}
//----------------------------------------------------------------------------------------------------
std::string get_tx_proof_legacy(const crypto::hash &txid,
    const cryptonote::account_public_address &address,
    bool is_subaddress,
    const std::string &message,
    const wallet2_basic::cache &wallet_cache,
    const wallet2_basic::keys_data &wallet_keys_data,
    const std::unique_ptr<epee::net_utils::http::abstract_http_client> &http_client,
    const std::chrono::seconds &rpc_timeout,
    hw::device &hwdev)
{
    // 1. fetch tx pubkey from the daemon
    cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request req;
    cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response res;
    req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
    req.decode_as_json = false;
    req.prune          = true;

    bool ok;
    {

        //   const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
        ok = epee::net_utils::invoke_http_json("/gettransactions", req, res, *http_client);
        THROW_WALLET_EXCEPTION_IF(!ok || (res.txs.size() != 1 && res.txs_as_hex.size() != 1),
            tools::error::wallet_internal_error,
            "Failed to get transaction from daemon");
    }

    cryptonote::transaction tx;
    crypto::hash tx_hash;
    if (res.txs.size() == 1)
    {
        ok = get_pruned_tx(res.txs.front(), tx, tx_hash);
        THROW_WALLET_EXCEPTION_IF(!ok, tools::error::wallet_internal_error, "Failed to parse transaction from daemon");
    }
    else
    {
        cryptonote::blobdata tx_data;
        ok = epee::string_tools::parse_hexstr_to_binbuff(res.txs_as_hex.front(), tx_data);
        THROW_WALLET_EXCEPTION_IF(!ok, tools::error::wallet_internal_error, "Failed to parse transaction from daemon");
        THROW_WALLET_EXCEPTION_IF(!cryptonote::parse_and_validate_tx_from_blob(tx_data, tx),
            tools::error::wallet_internal_error,
            "Failed to validate transaction from daemon");
        tx_hash = cryptonote::get_transaction_hash(tx);
    }

    THROW_WALLET_EXCEPTION_IF(
        tx_hash != txid, tools::error::wallet_internal_error, "Failed to get the right transaction from daemon");

    // 2. determine if the address is found in the subaddress hash table (i.e. whether the proof is outbound or inbound)
    crypto::secret_key tx_key = crypto::null_skey;
    std::vector<crypto::secret_key> additional_tx_keys;
    const bool is_out = wallet_cache.m_subaddresses.count(address.m_spend_public_key) == 0;
    if (is_out)
    {
        THROW_WALLET_EXCEPTION_IF(
            !get_tx_key(txid, wallet_cache.m_tx_keys, wallet_cache.m_additional_tx_keys, tx_key, additional_tx_keys),
            tools::error::wallet_internal_error,
            "Tx secret key wasn't found in the wallet file.");
    }

    // 3. get proof
    return get_tx_proof_legacy(
        tx, tx_key, additional_tx_keys, address, is_subaddress, message, wallet_cache, wallet_keys_data,hwdev);
}
//----------------------------------------------------------------------------------------------------
std::string get_tx_proof_legacy(const cryptonote::transaction &tx,
    const crypto::secret_key &tx_key,
    const std::vector<crypto::secret_key> &additional_tx_keys,
    const cryptonote::account_public_address &address,
    bool is_subaddress,
    const std::string &message,
    const wallet2_basic::cache &wallet_cache,
    const wallet2_basic::keys_data &wallet_keys_data,
    hw::device &hwdev)
{
    rct::key aP;
    // 1. determine if the address is found in the subaddress hash table (i.e. whether the proof is outbound or inbound)
    const bool is_out = wallet_cache.m_subaddresses.count(address.m_spend_public_key) == 0;

    // 2. get prefix hash
    const crypto::hash txid = cryptonote::get_transaction_hash(tx);
    std::string prefix_data((const char *)&txid, sizeof(crypto::hash));
    prefix_data += message;
    crypto::hash prefix_hash;
    crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

    std::vector<crypto::public_key> shared_secret;
    std::vector<crypto::signature> sig;
    std::string sig_str;

    // 3. get proof
    if (is_out)
    {
        // out_proof
        const size_t num_sigs = 1 + additional_tx_keys.size();
        shared_secret.resize(num_sigs);
        sig.resize(num_sigs);

        hwdev.scalarmultKey(aP, rct::pk2rct(address.m_view_public_key), rct::sk2rct(tx_key));
        shared_secret[0] = rct::rct2pk(aP);
        crypto::public_key tx_pub_key;
        if (is_subaddress)
        {
            hwdev.scalarmultKey(aP, rct::pk2rct(address.m_spend_public_key), rct::sk2rct(tx_key));
            tx_pub_key = rct2pk(aP);
            hwdev.generate_tx_proof(prefix_hash,
                tx_pub_key,
                address.m_view_public_key,
                address.m_spend_public_key,
                shared_secret[0],
                tx_key,
                sig[0]);
        }
        else
        {
            hwdev.secret_key_to_public_key(tx_key, tx_pub_key);
            hwdev.generate_tx_proof(
                prefix_hash, tx_pub_key, address.m_view_public_key, boost::none, shared_secret[0], tx_key, sig[0]);
        }
        for (size_t i = 1; i < num_sigs; ++i)
        {
            hwdev.scalarmultKey(aP, rct::pk2rct(address.m_view_public_key), rct::sk2rct(additional_tx_keys[i - 1]));
            shared_secret[i] = rct::rct2pk(aP);
            if (is_subaddress)
            {
                hwdev.scalarmultKey(
                    aP, rct::pk2rct(address.m_spend_public_key), rct::sk2rct(additional_tx_keys[i - 1]));
                tx_pub_key = rct2pk(aP);
                hwdev.generate_tx_proof(prefix_hash,
                    tx_pub_key,
                    address.m_view_public_key,
                    address.m_spend_public_key,
                    shared_secret[i],
                    additional_tx_keys[i - 1],
                    sig[i]);
            }
            else
            {
                hwdev.secret_key_to_public_key(additional_tx_keys[i - 1], tx_pub_key);
                hwdev.generate_tx_proof(prefix_hash,
                    tx_pub_key,
                    address.m_view_public_key,
                    boost::none,
                    shared_secret[i],
                    additional_tx_keys[i - 1],
                    sig[i]);
            }
        }
        sig_str = std::string("OutProofV2");
    }
    else
    {
        // in_proof
        crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
        THROW_WALLET_EXCEPTION_IF(
            tx_pub_key == crypto::null_pkey, tools::error::wallet_internal_error, "Tx pubkey was not found");

        std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(tx);
        const size_t num_sigs                                  = 1 + additional_tx_pub_keys.size();
        shared_secret.resize(num_sigs);
        sig.resize(num_sigs);

        const crypto::secret_key &a = wallet_keys_data.m_account.get_keys().m_view_secret_key;
        hwdev.scalarmultKey(aP, rct::pk2rct(tx_pub_key), rct::sk2rct(a));
        shared_secret[0] = rct2pk(aP);
        if (is_subaddress)
        {
            hwdev.generate_tx_proof(prefix_hash,
                address.m_view_public_key,
                tx_pub_key,
                address.m_spend_public_key,
                shared_secret[0],
                a,
                sig[0]);
        }
        else
        {
            hwdev.generate_tx_proof(
                prefix_hash, address.m_view_public_key, tx_pub_key, boost::none, shared_secret[0], a, sig[0]);
        }
        for (size_t i = 1; i < num_sigs; ++i)
        {
            hwdev.scalarmultKey(aP, rct::pk2rct(additional_tx_pub_keys[i - 1]), rct::sk2rct(a));
            shared_secret[i] = rct2pk(aP);
            if (is_subaddress)
            {
                hwdev.generate_tx_proof(prefix_hash,
                    address.m_view_public_key,
                    additional_tx_pub_keys[i - 1],
                    address.m_spend_public_key,
                    shared_secret[i],
                    a,
                    sig[i]);
            }
            else
            {
                hwdev.generate_tx_proof(prefix_hash,
                    address.m_view_public_key,
                    additional_tx_pub_keys[i - 1],
                    boost::none,
                    shared_secret[i],
                    a,
                    sig[i]);
            }
        }
        sig_str = std::string("InProofV2");
    }
    const size_t num_sigs = shared_secret.size();

    // 4. check if this address actually received any funds
    crypto::key_derivation derivation;
    THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(shared_secret[0], rct::rct2sk(rct::I), derivation),
        tools::error::wallet_internal_error,
        "Failed to generate key derivation");
    std::vector<crypto::key_derivation> additional_derivations(num_sigs - 1);
    for (size_t i = 1; i < num_sigs; ++i)
        THROW_WALLET_EXCEPTION_IF(
            !crypto::generate_key_derivation(shared_secret[i], rct::rct2sk(rct::I), additional_derivations[i - 1]),
            tools::error::wallet_internal_error,
            "Failed to generate key derivation");
    uint64_t received;
    check_tx_key_helper(tx, derivation, additional_derivations, address, received);
    THROW_WALLET_EXCEPTION_IF(!received, tools::error::wallet_internal_error, tr("No funds received in this tx."));

    // 5. concatenate all signature strings
    for (size_t i = 0; i < num_sigs; ++i)
        sig_str += tools::base58::encode(std::string((const char *)&shared_secret[i], sizeof(crypto::public_key))) +
                   tools::base58::encode(std::string((const char *)&sig[i], sizeof(crypto::signature)));
    return sig_str;
}
//----------------------------------------------------------------------------------------------------
bool check_tx_proof_legacy(const crypto::hash &txid,
    const cryptonote::account_public_address &address,
    bool is_subaddress,
    const std::string &message,
    const std::string &sig_str,
    uint64_t &received,
    bool &in_pool,
    uint64_t &confirmations,
    const std::unique_ptr<epee::net_utils::http::abstract_http_client> &http_client,
    const std::chrono::seconds &rpc_timeout)
{
    // 1. fetch tx from daemon
    cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request req;
    cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response res;
    req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
    req.decode_as_json = false;
    req.prune          = true;

    bool ok;
    {
        ok = epee::net_utils::invoke_http_json("/gettransactions", req, res, *http_client);
        THROW_WALLET_EXCEPTION_IF(!ok || (res.txs.size() != 1 && res.txs_as_hex.size() != 1),
            tools::error::wallet_internal_error,
            "Failed to get transaction from daemon");
    }

    cryptonote::transaction tx;
    crypto::hash tx_hash;
    if (res.txs.size() == 1)
    {
        ok = get_pruned_tx(res.txs.front(), tx, tx_hash);
        THROW_WALLET_EXCEPTION_IF(!ok, tools::error::wallet_internal_error, "Failed to parse transaction from daemon");
    }
    else
    {
        cryptonote::blobdata tx_data;
        ok = epee::string_tools::parse_hexstr_to_binbuff(res.txs_as_hex.front(), tx_data);
        THROW_WALLET_EXCEPTION_IF(!ok, tools::error::wallet_internal_error, "Failed to parse transaction from daemon");
        THROW_WALLET_EXCEPTION_IF(!cryptonote::parse_and_validate_tx_from_blob(tx_data, tx),
            tools::error::wallet_internal_error,
            "Failed to validate transaction from daemon");
        tx_hash = cryptonote::get_transaction_hash(tx);
    }

    THROW_WALLET_EXCEPTION_IF(
        tx_hash != txid, tools::error::wallet_internal_error, "Failed to get the right transaction from daemon");

    // 2. Check proof
    if (!check_tx_proof_legacy(tx, address, is_subaddress, message, sig_str, received))
        return false;

    // 3. Get block height
    in_pool                   = res.txs.front().in_pool;
    confirmations             = 0;
    std::uint64_t conf_height = res.txs.front().block_height;
    cryptonote::COMMAND_RPC_GET_HEIGHT::request reqh;
    cryptonote::COMMAND_RPC_GET_HEIGHT::response resph;
    if (!in_pool)
    {
        epee::net_utils::invoke_http_json("/get_height", reqh, resph, *http_client);
        uint64_t bc_height = resph.height;
        confirmations      = bc_height - conf_height;
    }

    return true;
}
//----------------------------------------------------------------------------------------------------
bool check_tx_proof_legacy(const cryptonote::transaction &tx,
    const cryptonote::account_public_address &address,
    bool is_subaddress,
    const std::string &message,
    const std::string &sig_str,
    uint64_t &received)
{
    // 1. Get proof type and version
    // InProofV1, InProofV2, OutProofV1, OutProofV2
    const bool is_out        = sig_str.substr(0, 3) == "Out";
    const std::string header = is_out ? sig_str.substr(0, 10) : sig_str.substr(0, 9);
    int version              = 2;  // InProofV2
    if (is_out && sig_str.substr(8, 2) == "V1")
        version = 1;  // OutProofV1
    else if (is_out)
        version = 2;  // OutProofV2
    else if (sig_str.substr(7, 2) == "V1")
        version = 1;  // InProofV1

    const size_t header_len = header.size();
    THROW_WALLET_EXCEPTION_IF(sig_str.size() < header_len || sig_str.substr(0, header_len) != header,
        tools::error::wallet_internal_error,
        "Signature header check error");

    // 2. Decode base58
    std::vector<crypto::public_key> shared_secret(1);
    std::vector<crypto::signature> sig(1);
    const size_t pk_len =
        tools::base58::encode(std::string((const char *)&shared_secret[0], sizeof(crypto::public_key))).size();
    const size_t sig_len  = tools::base58::encode(std::string((const char *)&sig[0], sizeof(crypto::signature))).size();
    const size_t num_sigs = (sig_str.size() - header_len) / (pk_len + sig_len);
    THROW_WALLET_EXCEPTION_IF(sig_str.size() != header_len + num_sigs * (pk_len + sig_len),
        tools::error::wallet_internal_error,
        "Wrong signature size");
    shared_secret.resize(num_sigs);
    sig.resize(num_sigs);
    for (size_t i = 0; i < num_sigs; ++i)
    {
        std::string pk_decoded;
        std::string sig_decoded;
        const size_t offset = header_len + i * (pk_len + sig_len);
        THROW_WALLET_EXCEPTION_IF(!tools::base58::decode(sig_str.substr(offset, pk_len), pk_decoded),
            tools::error::wallet_internal_error,
            "Signature decoding error");
        THROW_WALLET_EXCEPTION_IF(!tools::base58::decode(sig_str.substr(offset + pk_len, sig_len), sig_decoded),
            tools::error::wallet_internal_error,
            "Signature decoding error");
        THROW_WALLET_EXCEPTION_IF(
            sizeof(crypto::public_key) != pk_decoded.size() || sizeof(crypto::signature) != sig_decoded.size(),
            tools::error::wallet_internal_error,
            "Signature decoding error");
        memcpy(&shared_secret[i], pk_decoded.data(), sizeof(crypto::public_key));
        memcpy(&sig[i], sig_decoded.data(), sizeof(crypto::signature));
    }

    crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
    THROW_WALLET_EXCEPTION_IF(
        tx_pub_key == crypto::null_pkey, tools::error::wallet_internal_error, "Tx pubkey was not found");

    std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(tx);
    THROW_WALLET_EXCEPTION_IF(additional_tx_pub_keys.size() + 1 != num_sigs,
        tools::error::wallet_internal_error,
        "Signature size mismatch with additional tx pubkeys");

    const crypto::hash txid = cryptonote::get_transaction_hash(tx);
    std::string prefix_data((const char *)&txid, sizeof(crypto::hash));
    prefix_data += message;
    crypto::hash prefix_hash;
    crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

    // 3. Check signature
    std::vector<int> good_signature(num_sigs, 0);
    if (is_out)
    {
        good_signature[0] = is_subaddress ? crypto::check_tx_proof(prefix_hash,
                                                tx_pub_key,
                                                address.m_view_public_key,
                                                address.m_spend_public_key,
                                                shared_secret[0],
                                                sig[0],
                                                version)
                                          : crypto::check_tx_proof(prefix_hash,
                                                tx_pub_key,
                                                address.m_view_public_key,
                                                boost::none,
                                                shared_secret[0],
                                                sig[0],
                                                version);

        for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
        {
            good_signature[i + 1] = is_subaddress ? crypto::check_tx_proof(prefix_hash,
                                                        additional_tx_pub_keys[i],
                                                        address.m_view_public_key,
                                                        address.m_spend_public_key,
                                                        shared_secret[i + 1],
                                                        sig[i + 1],
                                                        version)
                                                  : crypto::check_tx_proof(prefix_hash,
                                                        additional_tx_pub_keys[i],
                                                        address.m_view_public_key,
                                                        boost::none,
                                                        shared_secret[i + 1],
                                                        sig[i + 1],
                                                        version);
        }
    }
    else
    {
        good_signature[0] = is_subaddress ? crypto::check_tx_proof(prefix_hash,
                                                address.m_view_public_key,
                                                tx_pub_key,
                                                address.m_spend_public_key,
                                                shared_secret[0],
                                                sig[0],
                                                version)
                                          : crypto::check_tx_proof(prefix_hash,
                                                address.m_view_public_key,
                                                tx_pub_key,
                                                boost::none,
                                                shared_secret[0],
                                                sig[0],
                                                version);

        for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
        {
            good_signature[i + 1] = is_subaddress ? crypto::check_tx_proof(prefix_hash,
                                                        address.m_view_public_key,
                                                        additional_tx_pub_keys[i],
                                                        address.m_spend_public_key,
                                                        shared_secret[i + 1],
                                                        sig[i + 1],
                                                        version)
                                                  : crypto::check_tx_proof(prefix_hash,
                                                        address.m_view_public_key,
                                                        additional_tx_pub_keys[i],
                                                        boost::none,
                                                        shared_secret[i + 1],
                                                        sig[i + 1],
                                                        version);
        }
    }

    if (std::any_of(good_signature.begin(), good_signature.end(), [](int i) { return i > 0; }))
    {
        // 4. Obtain key derivation by multiplying scalar 1 to the shared secret
        crypto::key_derivation derivation;
        if (good_signature[0])
            THROW_WALLET_EXCEPTION_IF(
                !crypto::generate_key_derivation(shared_secret[0], rct::rct2sk(rct::I), derivation),
                tools::error::wallet_internal_error,
                "Failed to generate key derivation");

        std::vector<crypto::key_derivation> additional_derivations(num_sigs - 1);
        for (size_t i = 1; i < num_sigs; ++i)
            if (good_signature[i])
                THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(
                                              shared_secret[i], rct::rct2sk(rct::I), additional_derivations[i - 1]),
                    tools::error::wallet_internal_error,
                    "Failed to generate key derivation");

        check_tx_key_helper(tx, derivation, additional_derivations, address, received);
        return true;
    }
    return false;
}
//----------------------------------------------------------------------------------------------------
std::string get_reserve_proof_legacy(const boost::optional<std::pair<uint32_t, uint64_t>> &account_minreserve,
    const std::string &message,
    const wallet2_basic::cache &wallet_cache,
    const wallet2_basic::keys_data &wallet_keys_data)
{
    // 1. initial checks
    THROW_WALLET_EXCEPTION_IF(wallet_keys_data.m_watch_only || wallet_keys_data.m_multisig,
        tools::error::wallet_internal_error,
        "Reserve proof can only be generated by a full wallet");
    THROW_WALLET_EXCEPTION_IF(
        balance_all(true, wallet_cache) == 0, tools::error::wallet_internal_error, "Zero balance");
    THROW_WALLET_EXCEPTION_IF(
        account_minreserve && balance(account_minreserve->first, true, wallet_cache) < account_minreserve->second,
        tools::error::wallet_internal_error,
        "Not enough balance in this account for the requested minimum reserve amount");

    // 2. determine which outputs to include in the proof
    std::vector<size_t> selected_transfers;
    for (size_t i = 0; i < wallet_cache.m_transfers.size(); ++i)
    {
        const wallet2_basic::transfer_details &td = wallet_cache.m_transfers[i];
        if (!is_spent(td, true) && !td.m_frozen &&
            (!account_minreserve || account_minreserve->first == td.m_subaddr_index.major))
            selected_transfers.push_back(i);
    }

    if (account_minreserve)
    {
        THROW_WALLET_EXCEPTION_IF(account_minreserve->second == 0,
            tools::error::wallet_internal_error,
            "Proved amount must be greater than 0");
        // minimize the number of outputs included in the proof, by only picking the N largest outputs that can cover
        // the requested min reserve amount
        std::sort(selected_transfers.begin(),
            selected_transfers.end(),
            [&](const size_t a, const size_t b)
            { return wallet_cache.m_transfers[a].amount() > wallet_cache.m_transfers[b].amount(); });
        while (selected_transfers.size() >= 2 &&
               wallet_cache.m_transfers[selected_transfers[1]].amount() >= account_minreserve->second)
            selected_transfers.erase(selected_transfers.begin());
        size_t sz      = 0;
        uint64_t total = 0;
        while (total < account_minreserve->second)
        {
            total += wallet_cache.m_transfers[selected_transfers[sz]].amount();
            ++sz;
        }
        selected_transfers.resize(sz);
    }

    // 3. compute signature prefix hash
    std::string prefix_data = message;
    prefix_data.append((const char *)&wallet_keys_data.m_account.get_keys().m_account_address,
        sizeof(cryptonote::account_public_address));
    for (size_t i = 0; i < selected_transfers.size(); ++i)
    {
        prefix_data.append(
            (const char *)&wallet_cache.m_transfers[selected_transfers[i]].m_key_image, sizeof(crypto::key_image));
    }
    crypto::hash prefix_hash;
    crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

    // 4. generate proof entries
    std::vector<reserve_proof_entry_legacy> proofs(selected_transfers.size());
    std::unordered_set<cryptonote::subaddress_index> subaddr_indices = {{0, 0}};
    for (size_t i = 0; i < selected_transfers.size(); ++i)
    {
        const wallet2_basic::transfer_details &td = wallet_cache.m_transfers[selected_transfers[i]];
        reserve_proof_entry_legacy &proof         = proofs[i];
        proof.txid                                = td.m_txid;
        proof.index_in_tx                         = td.m_internal_output_index;
        proof.key_image                           = td.m_key_image;
        subaddr_indices.insert(td.m_subaddr_index);

        // 4.1 get tx pub key
        const crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(td.m_tx, td.m_pk_index);
        THROW_WALLET_EXCEPTION_IF(
            tx_pub_key == crypto::null_pkey, tools::error::wallet_internal_error, "The tx public key isn't found");
        const std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(td.m_tx);

        // 4.2 determine which tx pub key was used for deriving the output key
        const crypto::public_key *tx_pub_key_used = &tx_pub_key;
        for (int i = 0; i < 2; ++i)
        {
            proof.shared_secret = rct::rct2pk(rct::scalarmultKey(
                rct::pk2rct(*tx_pub_key_used), rct::sk2rct(wallet_keys_data.m_account.get_keys().m_view_secret_key)));
            crypto::key_derivation derivation;
            THROW_WALLET_EXCEPTION_IF(
                !crypto::generate_key_derivation(proof.shared_secret, rct::rct2sk(rct::I), derivation),
                tools::error::wallet_internal_error,
                "Failed to generate key derivation");
            crypto::public_key subaddress_spendkey;
            THROW_WALLET_EXCEPTION_IF(
                !derive_subaddress_public_key(td.get_public_key(), derivation, proof.index_in_tx, subaddress_spendkey),
                tools::error::wallet_internal_error,
                "Failed to derive subaddress public key");
            if (wallet_cache.m_subaddresses.count(subaddress_spendkey) == 1)
                break;
            THROW_WALLET_EXCEPTION_IF(additional_tx_pub_keys.empty(),
                tools::error::wallet_internal_error,
                "Normal tx pub key doesn't derive the expected output, while the additional tx pub keys are empty");
            THROW_WALLET_EXCEPTION_IF(i == 1,
                tools::error::wallet_internal_error,
                "Neither normal tx pub key nor additional tx pub key derive the expected output key");
            tx_pub_key_used = &additional_tx_pub_keys[proof.index_in_tx];
        }

        // 4.3 generate signature for shared secret
        crypto::generate_tx_proof(prefix_hash,
            wallet_keys_data.m_account.get_keys().m_account_address.m_view_public_key,
            *tx_pub_key_used,
            boost::none,
            proof.shared_secret,
            wallet_keys_data.m_account.get_keys().m_view_secret_key,
            proof.shared_secret_sig);

        // 4.4 derive ephemeral secret key
        crypto::key_image ki;
        cryptonote::keypair ephemeral;
        const bool r = cryptonote::generate_key_image_helper(wallet_keys_data.m_account.get_keys(),
            wallet_cache.m_subaddresses,
            td.get_public_key(),
            tx_pub_key,
            additional_tx_pub_keys,
            td.m_internal_output_index,
            ephemeral,
            ki,
            wallet_keys_data.m_account.get_device());
        THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, "Failed to generate key image");
        THROW_WALLET_EXCEPTION_IF(ephemeral.pub != td.get_public_key(),
            tools::error::wallet_internal_error,
            "Derived public key doesn't agree with the stored one");

        // 4.5 generate signature for key image
        const std::vector<const crypto::public_key *> pubs = {&ephemeral.pub};
        crypto::generate_ring_signature(
            prefix_hash, td.m_key_image, &pubs[0], 1, ephemeral.sec, 0, &proof.key_image_sig);
    }

    // 5. collect all subaddress spend keys that received those outputs and generate their signatures
    serializable_unordered_map<crypto::public_key, crypto::signature> subaddr_spendkeys;
    for (const cryptonote::subaddress_index &index : subaddr_indices)
    {
        crypto::secret_key subaddr_spend_skey = wallet_keys_data.m_account.get_keys().m_spend_secret_key;
        if (!index.is_zero())
        {
            crypto::secret_key m = wallet_keys_data.m_account.get_device().get_subaddress_secret_key(
                wallet_keys_data.m_account.get_keys().m_view_secret_key, index);
            crypto::secret_key tmp = subaddr_spend_skey;
            sc_add((unsigned char *)&subaddr_spend_skey, (unsigned char *)&m, (unsigned char *)&tmp);
        }
        crypto::public_key subaddr_spend_pkey;
        secret_key_to_public_key(subaddr_spend_skey, subaddr_spend_pkey);
        crypto::generate_signature(
            prefix_hash, subaddr_spend_pkey, subaddr_spend_skey, subaddr_spendkeys[subaddr_spend_pkey]);
    }

    // 6. serialize & encode
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    THROW_WALLET_EXCEPTION_IF(
        !::serialization::serialize(ar, proofs), tools::error::wallet_internal_error, "Failed to serialize proof");
    THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar, subaddr_spendkeys),
        tools::error::wallet_internal_error,
        "Failed to serialize proof");
    std::string sig_str{"ReserveProofV2" + tools::base58::encode(oss.str())};
    if (!sig_str.empty())
        CHECK_AND_ASSERT_THROW_MES(epee::file_io_utils::save_string_to_file("monero_reserve_proof_legacy", sig_str),
            "get_reserve_proof: failed to save string to file");
    return sig_str;
}
//----------------------------------------------------------------------------------------------------
bool check_reserve_proof_legacy(const cryptonote::account_public_address &address,
    const std::string &message,
    const std::string &sig_str,
    uint64_t &total,
    uint64_t &spent,
    const std::unique_ptr<epee::net_utils::http::abstract_http_client> &http_client,
    const std::chrono::seconds &rpc_timeout)
{
    // **** Need to check connection here?
    // uint32_t rpc_version;
    // THROW_WALLET_EXCEPTION_IF(!check_connection(&rpc_version),
    //     tools::error::wallet_internal_error,
    //     "Failed to connect to daemon: " + get_daemon_address());
    // THROW_WALLET_EXCEPTION_IF(
    //     rpc_version < MAKE_CORE_RPC_VERSION(1, 0), tools::error::wallet_internal_error, "Daemon RPC version is too
    //     old");

    // 1. check header
    static constexpr char header_v1[] = "ReserveProofV1";
    static constexpr char header_v2[] = "ReserveProofV2";  // assumes same length as header_v1
    THROW_WALLET_EXCEPTION_IF(
        !boost::string_ref{sig_str}.starts_with(header_v1) && !boost::string_ref{sig_str}.starts_with(header_v2),
        tools::error::wallet_internal_error,
        "Signature header check error");
    int version = 2;  // assume newest version
    if (boost::string_ref{sig_str}.starts_with(header_v1))
        version = 1;
    else if (boost::string_ref{sig_str}.starts_with(header_v2))
        version = 2;

    // 2. decode signature
    std::string sig_decoded;
    THROW_WALLET_EXCEPTION_IF(!tools::base58::decode(sig_str.substr(std::strlen(header_v1)), sig_decoded),
        tools::error::wallet_internal_error,
        "Signature decoding error");

    bool loaded = false;
    std::vector<reserve_proof_entry_legacy> proofs;
    serializable_unordered_map<crypto::public_key, crypto::signature> subaddr_spendkeys;
    try
    {
        binary_archive<false> ar{epee::strspan<std::uint8_t>(sig_decoded)};
        if (::serialization::serialize_noeof(ar, proofs))
            if (::serialization::serialize_noeof(ar, subaddr_spendkeys))
                if (::serialization::check_stream_state(ar))
                    loaded = true;
    }
    catch (...)
    {
    }
    // *** dont check wallet deprecated formats
    if (!loaded)  // && m_load_deprecated_formats)
    {
        std::istringstream iss(sig_decoded);
        boost::archive::portable_binary_iarchive ar(iss);
        ar >> proofs >> subaddr_spendkeys.parent();
    }

    THROW_WALLET_EXCEPTION_IF(subaddr_spendkeys.count(address.m_spend_public_key) == 0,
        tools::error::wallet_internal_error,
        "The given address isn't found in the proof");

    // 3. compute signature prefix hash
    std::string prefix_data = message;
    prefix_data.append((const char *)&address, sizeof(cryptonote::account_public_address));
    for (size_t i = 0; i < proofs.size(); ++i)
    {
        prefix_data.append((const char *)&proofs[i].key_image, sizeof(crypto::key_image));
    }
    crypto::hash prefix_hash;
    crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

    // 4. fetch txs from daemon
    cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request gettx_req;
    cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response gettx_res;
    for (size_t i = 0; i < proofs.size(); ++i)
        gettx_req.txs_hashes.push_back(epee::string_tools::pod_to_hex(proofs[i].txid));
    gettx_req.decode_as_json = false;
    gettx_req.prune          = true;

    {
        // const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
        bool ok = epee::net_utils::invoke_http_json("/gettransactions", gettx_req, gettx_res, *http_client);
        THROW_WALLET_EXCEPTION_IF(!ok || gettx_res.txs.size() != proofs.size(),
            tools::error::wallet_internal_error,
            "Failed to get transaction from daemon");
    }

    // 5. check spent status
    cryptonote::COMMAND_RPC_IS_KEY_IMAGE_SPENT::request kispent_req;
    cryptonote::COMMAND_RPC_IS_KEY_IMAGE_SPENT::response kispent_res;
    for (size_t i = 0; i < proofs.size(); ++i)
        kispent_req.key_images.push_back(epee::string_tools::pod_to_hex(proofs[i].key_image));

    bool ok;
    {
        // const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
        ok = epee::net_utils::invoke_http_json(
            "/is_key_image_spent", kispent_req, kispent_res, *http_client, rpc_timeout);
        THROW_WALLET_EXCEPTION_IF(!ok || kispent_res.spent_status.size() != proofs.size(),
            tools::error::wallet_internal_error,
            "Failed to get key image spent status from daemon");
    }

    total = spent = 0;
    // 6. check each proof 
    for (size_t i = 0; i < proofs.size(); ++i)
    {
        const reserve_proof_entry_legacy &proof = proofs[i];
        THROW_WALLET_EXCEPTION_IF(gettx_res.txs[i].in_pool, tools::error::wallet_internal_error, "Tx is unconfirmed");

        cryptonote::transaction tx;
        crypto::hash tx_hash;
        ok = get_pruned_tx(gettx_res.txs[i], tx, tx_hash);
        THROW_WALLET_EXCEPTION_IF(!ok, tools::error::wallet_internal_error, "Failed to parse transaction from daemon");

        THROW_WALLET_EXCEPTION_IF(tx_hash != proof.txid,
            tools::error::wallet_internal_error,
            "Failed to get the right transaction from daemon");

        THROW_WALLET_EXCEPTION_IF(
            proof.index_in_tx >= tx.vout.size(), tools::error::wallet_internal_error, "index_in_tx is out of bound");

        crypto::public_key output_public_key;
        THROW_WALLET_EXCEPTION_IF(!get_output_public_key(tx.vout[proof.index_in_tx], output_public_key),
            tools::error::wallet_internal_error,
            "Output key wasn't found");

        // 6.1 get tx pub key
        const crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
        THROW_WALLET_EXCEPTION_IF(
            tx_pub_key == crypto::null_pkey, tools::error::wallet_internal_error, "The tx public key isn't found");
        const std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(tx);

        // 6.2 check signature for shared secret
        ok = crypto::check_tx_proof(prefix_hash,
            address.m_view_public_key,
            tx_pub_key,
            boost::none,
            proof.shared_secret,
            proof.shared_secret_sig,
            version);
        if (!ok && additional_tx_pub_keys.size() == tx.vout.size())
            ok = crypto::check_tx_proof(prefix_hash,
                address.m_view_public_key,
                additional_tx_pub_keys[proof.index_in_tx],
                boost::none,
                proof.shared_secret,
                proof.shared_secret_sig,
                version);
        if (!ok)
            return false;

        // 6.3 check signature for key image
        const std::vector<const crypto::public_key *> pubs = {&output_public_key};
        ok = crypto::check_ring_signature(prefix_hash, proof.key_image, &pubs[0], 1, &proof.key_image_sig);
        if (!ok)
            return false;

        // 6.4 check if the address really received the fund
        crypto::key_derivation derivation;
        THROW_WALLET_EXCEPTION_IF(
            !crypto::generate_key_derivation(proof.shared_secret, rct::rct2sk(rct::I), derivation),
            tools::error::wallet_internal_error,
            "Failed to generate key derivation");
        crypto::public_key subaddr_spendkey;
        THROW_WALLET_EXCEPTION_IF(
            !crypto::derive_subaddress_public_key(output_public_key, derivation, proof.index_in_tx, subaddr_spendkey),
            tools::error::wallet_internal_error,
            "Failed to derive subaddress public key");
        THROW_WALLET_EXCEPTION_IF(subaddr_spendkeys.count(subaddr_spendkey) == 0,
            tools::error::wallet_internal_error,
            "The address doesn't seem to have received the fund");

        // 6.5 check amount
        uint64_t amount = tx.vout[proof.index_in_tx].amount;
        if (amount == 0)
        {
            // decode rct
            crypto::secret_key shared_secret;
            crypto::derivation_to_scalar(derivation, proof.index_in_tx, shared_secret);
            rct::ecdhTuple ecdh_info = tx.rct_signatures.ecdhInfo[proof.index_in_tx];
            rct::ecdhDecode(ecdh_info,
                rct::sk2rct(shared_secret),
                tx.rct_signatures.type == rct::RCTTypeBulletproof2 || tx.rct_signatures.type == rct::RCTTypeCLSAG ||
                    tx.rct_signatures.type == rct::RCTTypeBulletproofPlus);
            amount = rct::h2d(ecdh_info.amount);
        }
        total += amount;
        if (kispent_res.spent_status[i])
            spent += amount;
    }

    // 7. check signatures for all subaddress spend keys
    for (const auto &i : subaddr_spendkeys)
    {
        if (!crypto::check_signature(prefix_hash, i.first, i.second))
            return false;
    }
    return true;
}


/// Using enote scanner with EnoteStore injection into functions
/// TODO: Solve the problem of the node connection 

// // Copyright (c) 2014-2023, The Monero Project
// //
// // All rights reserved.
// //
// // Redistribution and use in source and binary forms, with or without modification, are
// // permitted provided that the following conditions are met:
// //
// // 1. Redistributions of source code must retain the above copyright notice, this list of
// //    conditions and the following disclaimer.
// //
// // 2. Redistributions in binary form must reproduce the above copyright notice, this list
// //    of conditions and the following disclaimer in the documentation and/or other
// //    materials provided with the distribution.
// //
// // 3. Neither the name of the copyright holder nor the names of its contributors may be
// //    used to endorse or promote products derived from this software without specific
// //    prior written permission.
// //
// // THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// // EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// // MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// // THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// // SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// // PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// // INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// // STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// // THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// //

// #include "legacy_knowledge_proofs.h"

// #include <boost/thread/pthread/recursive_mutex.hpp>
// #include <cstdint>
// #include <string>

// #include "common/base58.h"
// #include "common/i18n.h"
// #include "crypto/crypto.h"
// #include "crypto/hash.h"

// // #include "net/parse.h"
// #include "cryptonote_basic/cryptonote_basic.h"
// #include "cryptonote_basic/cryptonote_format_utils.h"
// #include "device/device.hpp"
// #include "net/http.h"
// #include "net/http_client.h"
// #include "ringct/rctTypes.h"
// #include "rpc/core_rpc_server_commands_defs.h"
// #include "rpc/core_rpc_server_error_codes.h"
// #include "seraphis_impl/enote_store.h"
// #include "seraphis_main/contextual_enote_record_types.h"
// #include "seraphis_mocks/enote_finding_context_mocks.h"
// #include "storages/http_abstract_invoke.h"
// #include "wallet/wallet_errors.h"

// //----------------------------------------------------------------------------------------------------
// std::string generate_legacy_spend_proof(const std::string &message,
//     const crypto::hash &txid,
//     const crypto::secret_key &spend_key,
//     const sp::SpEnoteStore &enote_store)
// {
//     // 1. Connection to node and tx query
//     // CHANGE NODE CONNECTION
//     // ----------------------
//     epee::net_utils::http::http_simple_client http_client;
//     constexpr const std::chrono::seconds rpc_timeout = std::chrono::minutes(3) + std::chrono::seconds(30);

//     http_client.set_server("127.0.0.1:18081", boost::none);
//     http_client.connect(rpc_timeout);
//     // ----------------------

//     cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request req = AUTO_VAL_INIT(req);
//     req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
//     req.decode_as_json                                     = true;
//     req.prune                                              = true;
//     cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response res = AUTO_VAL_INIT(res);
//     bool r;

//     r = epee::net_utils::invoke_http_json("/gettransactions", req, res, http_client, rpc_timeout);
//     THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, "Failed to get transaction from daemon");

//     cryptonote::transaction tx;
//     crypto::hash tx_hash;
//     THROW_WALLET_EXCEPTION_IF(
//         !get_pruned_tx(res.txs[0], tx, tx_hash), tools::error::wallet_internal_error, "Failed to get tx from daemon");

//     // 2. Get signature prefix hash
//     std::string sig_prefix_data((const char *)&txid, sizeof(crypto::hash));
//     sig_prefix_data += message;
//     crypto::hash sig_prefix_hash;
//     crypto::cn_fast_hash(sig_prefix_data.data(), sig_prefix_data.size(), sig_prefix_hash);

//     std::vector<std::vector<crypto::signature>> signatures;

//     // 3. Loop over all inputs
//     for (size_t i = 0; i < tx.vin.size(); i++)
//     {
//         const cryptonote::txin_to_key *const in_key = boost::get<cryptonote::txin_to_key>(std::addressof(tx.vin[i]));
//         if (in_key == nullptr)
//             continue;
//         // 3.1 Check if the key image belongs to us
//         if (!enote_store.has_enote_with_key_image(in_key->k_image))
//         {
//             THROW_WALLET_EXCEPTION_IF(
//                 true, tools::error::wallet_internal_error, "This tx wasn't generated by this wallet!");
//         }

//         // 3.2 Derive the real output keypair
//         sp::LegacyContextualEnoteRecordV1 contextual_record;
//         enote_store.try_get_legacy_enote_record(in_key->k_image, contextual_record);
//         rct::key pub_key_enote = sp::onetime_address_ref(contextual_record.record.enote);
//         crypto::secret_key sec_key_enote;
//         sc_add(to_bytes(sec_key_enote), to_bytes(contextual_record.record.enote_view_extension), to_bytes(spend_key));
//         THROW_WALLET_EXCEPTION_IF(in_key->k_image != contextual_record.record.key_image,
//             tools::error::wallet_internal_error,
//             "key image mismatch");

//         // 3.3 Get output pubkeys in the ring
//         const std::vector<uint64_t> absolute_offsets =
//             cryptonote::relative_output_offsets_to_absolute(in_key->key_offsets);
//         const size_t ring_size = in_key->key_offsets.size();
//         THROW_WALLET_EXCEPTION_IF(absolute_offsets.size() != ring_size,
//             tools::error::wallet_internal_error,
//             "absolute offsets size is wrong");
//         cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::request req = AUTO_VAL_INIT(req);
//         req.outputs.resize(ring_size);
//         for (size_t j = 0; j < ring_size; ++j)
//         {
//             req.outputs[j].amount = in_key->amount;
//             req.outputs[j].index  = absolute_offsets[j];
//         }
//         cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::response res = AUTO_VAL_INIT(res);
//         {
//             r = epee::net_utils::invoke_http_bin("/get_outs.bin", req, res, http_client, rpc_timeout);
//             THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "get_outs.bin", tools::error::get_outs_error, res.status);
//             THROW_WALLET_EXCEPTION_IF(res.outs.size() != ring_size,
//                 tools::error::wallet_internal_error,
//                 "daemon returned wrong response for "
//                 "get_outs.bin, wrong amounts count = " +
//                     std::to_string(res.outs.size()) + ", expected " + std::to_string(ring_size));
//         }

//         // 3.4 Copy pubkey pointers
//         std::vector<const crypto::public_key *> p_output_keys;
//         for (const cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::outkey &out : res.outs) p_output_keys.push_back(&out.key);

//         // 3.5 Figure out real output index and secret key
//         size_t sec_index = -1;
//         for (size_t j = 0; j < ring_size; ++j)
//         {
//             if ((rct::key &)res.outs[j].key == pub_key_enote)
//             {
//                 sec_index = j;
//                 break;
//             }
//         }
//         THROW_WALLET_EXCEPTION_IF(
//             sec_index >= ring_size, tools::error::wallet_internal_error, "secret index not found");

//         // 3.6 Generate ring sig for this input
//         signatures.push_back(std::vector<crypto::signature>());
//         std::vector<crypto::signature> &sigs = signatures.back();
//         sigs.resize(in_key->key_offsets.size());
//         crypto::generate_ring_signature(
//             sig_prefix_hash, in_key->k_image, p_output_keys, sec_key_enote, sec_index, sigs.data());
//     }

//     // 4. Finalize signature
//     std::string sig_str = "SpendProofV1";
//     for (const std::vector<crypto::signature> &ring_sig : signatures)
//         for (const crypto::signature &sig : ring_sig)
//             sig_str += tools::base58::encode(std::string((const char *)&sig, sizeof(crypto::signature)));
//     return sig_str;
// }
// //----------------------------------------------------------------------------------------------------
// bool check_legacy_spend_proof(const crypto::hash &txid, const std::string &message, const std::string &sig_str)
// {
//     // 1. Fetch tx from daemon
//     // CHANGE NODE CONNECTION
//     // ----------------------
//     epee::net_utils::http::http_simple_client http_client;
//     constexpr const std::chrono::seconds rpc_timeout = std::chrono::minutes(3) + std::chrono::seconds(30);

//     http_client.set_server("127.0.0.1:18081", boost::none);
//     http_client.connect(rpc_timeout);
//     // ----------------------

//     const std::string header = "SpendProofV1";
//     const size_t header_len  = header.size();
//     THROW_WALLET_EXCEPTION_IF(sig_str.size() < header_len || sig_str.substr(0, header_len) != header,
//         tools::error::wallet_internal_error,
//         "Signature header check error");

//     cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request req = AUTO_VAL_INIT(req);
//     req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
//     req.decode_as_json                                     = false;
//     req.prune                                              = true;
//     cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response res = AUTO_VAL_INIT(res);
//     bool r;
//     {
//         r = epee::net_utils::invoke_http_json("/gettransactions", req, res, http_client, rpc_timeout);
//         THROW_ON_RPC_RESPONSE_ERROR_GENERIC(r, {}, res, "gettransactions");
//         THROW_WALLET_EXCEPTION_IF(res.txs.size() != 1,
//             tools::error::wallet_internal_error,
//             "daemon returned wrong response for gettransactions, wrong txs count "
//             "= " +
//                 std::to_string(res.txs.size()) + ", expected 1");
//     }

//     cryptonote::transaction tx;
//     crypto::hash tx_hash;
//     THROW_WALLET_EXCEPTION_IF(
//         !get_pruned_tx(res.txs[0], tx, tx_hash), tools::error::wallet_internal_error, "failed to get tx from daemon");

//     // 2. Check signature size
//     size_t num_sigs = 0;
//     for (size_t i = 0; i < tx.vin.size(); ++i)
//     {
//         const cryptonote::txin_to_key *const in_key = boost::get<cryptonote::txin_to_key>(std::addressof(tx.vin[i]));
//         if (in_key != nullptr)
//             num_sigs += in_key->key_offsets.size();
//     }
//     std::vector<std::vector<crypto::signature>> signatures = {std::vector<crypto::signature>(1)};
//     const size_t sig_len =
//         tools::base58::encode(std::string((const char *)&signatures[0][0], sizeof(crypto::signature))).size();
//     if (sig_str.size() != header_len + num_sigs * sig_len)
//     {
//         return false;
//     }

//     // 3. Decode base58
//     signatures.clear();
//     size_t offset = header_len;
//     for (size_t i = 0; i < tx.vin.size(); ++i)
//     {
//         const cryptonote::txin_to_key *const in_key = boost::get<cryptonote::txin_to_key>(std::addressof(tx.vin[i]));
//         if (in_key == nullptr)
//             continue;
//         signatures.resize(signatures.size() + 1);
//         signatures.back().resize(in_key->key_offsets.size());
//         for (size_t j = 0; j < in_key->key_offsets.size(); ++j)
//         {
//             std::string sig_decoded;
//             THROW_WALLET_EXCEPTION_IF(!tools::base58::decode(sig_str.substr(offset, sig_len), sig_decoded),
//                 tools::error::wallet_internal_error,
//                 "Signature decoding error");
//             THROW_WALLET_EXCEPTION_IF(sizeof(crypto::signature) != sig_decoded.size(),
//                 tools::error::wallet_internal_error,
//                 "Signature decoding error");
//             memcpy(&signatures.back()[j], sig_decoded.data(), sizeof(crypto::signature));
//             offset += sig_len;
//         }
//     }

//     // 4. Get signature prefix hash
//     std::string sig_prefix_data((const char *)&txid, sizeof(crypto::hash));
//     sig_prefix_data += message;
//     crypto::hash sig_prefix_hash;
//     crypto::cn_fast_hash(sig_prefix_data.data(), sig_prefix_data.size(), sig_prefix_hash);

//     // 5. Loop over signatures
//     std::vector<std::vector<crypto::signature>>::const_iterator sig_iter = signatures.cbegin();
//     for (size_t i = 0; i < tx.vin.size(); ++i)
//     {
//         const cryptonote::txin_to_key *const in_key = boost::get<cryptonote::txin_to_key>(std::addressof(tx.vin[i]));
//         if (in_key == nullptr)
//             continue;

//         // 5.1 Get output pubkeys in the ring
//         cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::request req = AUTO_VAL_INIT(req);
//         const std::vector<uint64_t> absolute_offsets =
//             cryptonote::relative_output_offsets_to_absolute(in_key->key_offsets);
//         req.outputs.resize(absolute_offsets.size());
//         for (size_t j = 0; j < absolute_offsets.size(); ++j)
//         {
//             req.outputs[j].amount = in_key->amount;
//             req.outputs[j].index  = absolute_offsets[j];
//         }
//         cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::response res = AUTO_VAL_INIT(res);
//         bool r;
//         r = epee::net_utils::invoke_http_bin("/get_outs.bin", req, res, http_client, rpc_timeout);
//         THROW_ON_RPC_RESPONSE_ERROR(r, {}, res, "get_outs.bin", tools::error::get_outs_error, res.status);
//         THROW_WALLET_EXCEPTION_IF(res.outs.size() != req.outputs.size(),
//             tools::error::wallet_internal_error,
//             "daemon returned wrong response for "
//             "get_outs.bin, wrong amounts count = " +
//                 std::to_string(res.outs.size()) + ", expected " + std::to_string(req.outputs.size()));

//         // 5.2 Copy pointers
//         std::vector<const crypto::public_key *> p_output_keys;
//         for (const cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::outkey &out : res.outs) p_output_keys.push_back(&out.key);

//         // 5.3 Check this ring
//         if (!crypto::check_ring_signature(sig_prefix_hash, in_key->k_image, p_output_keys, sig_iter->data()))
//             return false;
//         ++sig_iter;
//     }
//     THROW_WALLET_EXCEPTION_IF(
//         sig_iter != signatures.cend(), tools::error::wallet_internal_error, "Signature iterator didn't reach the end");
//     return true;
// }
// //----------------------------------------------------------------------------------------------------
// std::string generate_legacy_inproof(const crypto::hash &txid,
//     const rct::key &spend_public_key,
//     const rct::key &view_public_key,
//     const crypto::secret_key &secret_view_key,
//     bool is_subaddress,
//     const std::string &message)
// {
//     // 1. Fetch tx from daemon
//     // CHANGE NODE CONNECTION
//     // ----------------------
//     epee::net_utils::http::http_simple_client http_client;
//     constexpr const std::chrono::seconds rpc_timeout = std::chrono::minutes(3) + std::chrono::seconds(30);

//     http_client.set_server("127.0.0.1:18081", boost::none);
//     http_client.connect(rpc_timeout);
//     // ----------------------

//     cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request req;
//     cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response res;
//     req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
//     req.decode_as_json = false;
//     req.prune          = true;

//     bool ok;
//     {
//         ok = epee::net_utils::invoke_http_json("/gettransactions", req, res, http_client);
//         THROW_WALLET_EXCEPTION_IF(!ok || (res.txs.size() != 1 && res.txs_as_hex.size() != 1),
//             tools::error::wallet_internal_error,
//             "Failed to get transaction from daemon");
//     }

//     cryptonote::transaction tx;
//     crypto::hash tx_hash;
//     if (res.txs.size() == 1)
//     {
//         ok = get_pruned_tx(res.txs.front(), tx, tx_hash);
//         THROW_WALLET_EXCEPTION_IF(!ok, tools::error::wallet_internal_error, "Failed to parse transaction from daemon");
//     }
//     else
//     {
//         cryptonote::blobdata tx_data;
//         ok = epee::string_tools::parse_hexstr_to_binbuff(res.txs_as_hex.front(), tx_data);
//         THROW_WALLET_EXCEPTION_IF(!ok, tools::error::wallet_internal_error, "Failed to parse transaction from daemon");
//         THROW_WALLET_EXCEPTION_IF(!cryptonote::parse_and_validate_tx_from_blob(tx_data, tx),
//             tools::error::wallet_internal_error,
//             "Failed to validate transaction from daemon");
//         tx_hash = cryptonote::get_transaction_hash(tx);
//     }

//     THROW_WALLET_EXCEPTION_IF(
//         tx_hash != txid, tools::error::wallet_internal_error, "Failed to get the right transaction from daemon");

//     std::string prefix_data((const char *)&txid, sizeof(crypto::hash));
//     prefix_data += message;
//     crypto::hash prefix_hash;
//     crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

//     // 2. Prepare device
//     // CHANGE DEVICE
//     // ----------------------
//     hw::device &hwdev = hw::get_device("default");
//     // ----------------------
//     rct::key aP;
//     std::vector<crypto::public_key> shared_secret;
//     std::vector<crypto::signature> sig;
//     std::string sig_str;

//     // 3. Get signature
//     {
//         crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
//         THROW_WALLET_EXCEPTION_IF(
//             tx_pub_key == crypto::null_pkey, tools::error::wallet_internal_error, "Tx pubkey was not found");

//         std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(tx);
//         const size_t num_sigs                                  = 1 + additional_tx_pub_keys.size();
//         shared_secret.resize(num_sigs);
//         sig.resize(num_sigs);

//         const crypto::secret_key &a = secret_view_key;
//         hwdev.scalarmultKey(aP, rct::pk2rct(tx_pub_key), rct::sk2rct(a));
//         shared_secret[0] = rct2pk(aP);
//         if (is_subaddress)
//         {
//             hwdev.generate_tx_proof(prefix_hash,
//                 rct::rct2pk(view_public_key),
//                 tx_pub_key,
//                 rct::rct2pk(spend_public_key),
//                 shared_secret[0],
//                 a,
//                 sig[0]);
//         }
//         else
//         {
//             hwdev.generate_tx_proof(
//                 prefix_hash, rct::rct2pk(view_public_key), tx_pub_key, boost::none, shared_secret[0], a, sig[0]);
//         }
//         for (size_t i = 1; i < num_sigs; ++i)
//         {
//             hwdev.scalarmultKey(aP, rct::pk2rct(additional_tx_pub_keys[i - 1]), rct::sk2rct(a));
//             shared_secret[i] = rct2pk(aP);
//             if (is_subaddress)
//             {
//                 hwdev.generate_tx_proof(prefix_hash,
//                     rct::rct2pk(view_public_key),
//                     additional_tx_pub_keys[i - 1],
//                     rct::rct2pk(spend_public_key),
//                     shared_secret[i],
//                     a,
//                     sig[i]);
//             }
//             else
//             {
//                 hwdev.generate_tx_proof(prefix_hash,
//                     rct::rct2pk(view_public_key),
//                     additional_tx_pub_keys[i - 1],
//                     boost::none,
//                     shared_secret[i],
//                     a,
//                     sig[i]);
//             }
//         }
//         sig_str = std::string("InProofV2");
//     }

//     const size_t num_sigs = shared_secret.size();

//     // 4. Check if this address actually received any funds
//     crypto::key_derivation derivation;
//     THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(shared_secret[0], rct::rct2sk(rct::I), derivation),
//         tools::error::wallet_internal_error,
//         "Failed to generate key derivation");
//     std::vector<crypto::key_derivation> additional_derivations(num_sigs - 1);
//     for (size_t i = 1; i < num_sigs; ++i)
//         THROW_WALLET_EXCEPTION_IF(
//             !crypto::generate_key_derivation(shared_secret[i], rct::rct2sk(rct::I), additional_derivations[i - 1]),
//             tools::error::wallet_internal_error,
//             "Failed to generate key derivation");
//     uint64_t received;
//     cryptonote::account_public_address address{rct::rct2pk(spend_public_key), rct::rct2pk(view_public_key)};
//     check_tx_key_helper(tx, derivation, additional_derivations, address, received);
//     THROW_WALLET_EXCEPTION_IF(!received, tools::error::wallet_internal_error, tr("No funds received in this tx."));

//     // 5. Concatenate all signature strings
//     for (size_t i = 0; i < num_sigs; ++i)
//         sig_str += tools::base58::encode(std::string((const char *)&shared_secret[i], sizeof(crypto::public_key))) +
//                    tools::base58::encode(std::string((const char *)&sig[i], sizeof(crypto::signature)));
//     return sig_str;
// }
// //----------------------------------------------------------------------------------------------------
// bool check_tx_proof(const crypto::hash &txid,
//     const cryptonote::account_public_address &address,
//     bool is_subaddress,
//     const std::string &message,
//     const std::string &sig_str,
//     uint64_t &received,
//     bool &in_pool,
//     uint64_t &confirmations)
// {
//     // 1. Fetch tx from daemon
//     // CHANGE NODE CONNECTION
//     // ----------------------
//     epee::net_utils::http::http_simple_client http_client;
//     constexpr const std::chrono::seconds rpc_timeout = std::chrono::minutes(3) + std::chrono::seconds(30);

//     http_client.set_server("127.0.0.1:18081", boost::none);
//     http_client.connect(rpc_timeout);
//     // ----------------------

//     cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request req;
//     cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response res;
//     req.txs_hashes.push_back(epee::string_tools::pod_to_hex(txid));
//     req.decode_as_json = false;
//     req.prune          = true;

//     bool ok;
//     {
//         ok = epee::net_utils::invoke_http_json("/gettransactions", req, res, http_client);
//         THROW_WALLET_EXCEPTION_IF(!ok || (res.txs.size() != 1 && res.txs_as_hex.size() != 1),
//             tools::error::wallet_internal_error,
//             "Failed to get transaction from daemon");
//     }

//     cryptonote::transaction tx;
//     crypto::hash tx_hash;
//     if (res.txs.size() == 1)
//     {
//         ok = get_pruned_tx(res.txs.front(), tx, tx_hash);
//         THROW_WALLET_EXCEPTION_IF(!ok, tools::error::wallet_internal_error, "Failed to parse transaction from daemon");
//     }
//     else
//     {
//         cryptonote::blobdata tx_data;
//         ok = epee::string_tools::parse_hexstr_to_binbuff(res.txs_as_hex.front(), tx_data);
//         THROW_WALLET_EXCEPTION_IF(!ok, tools::error::wallet_internal_error, "Failed to parse transaction from daemon");
//         THROW_WALLET_EXCEPTION_IF(!cryptonote::parse_and_validate_tx_from_blob(tx_data, tx),
//             tools::error::wallet_internal_error,
//             "Failed to validate transaction from daemon");
//         tx_hash = cryptonote::get_transaction_hash(tx);
//     }

//     THROW_WALLET_EXCEPTION_IF(
//         tx_hash != txid, tools::error::wallet_internal_error, "Failed to get the right transaction from daemon");

//     // 2. Check proof
//     if (!check_tx_proof(tx, address, is_subaddress, message, sig_str, received))
//         return false;

//     // 3. Get block height
//     in_pool                   = res.txs.front().in_pool;
//     confirmations             = 0;
//     std::uint64_t conf_height = res.txs.front().block_height;
//     cryptonote::COMMAND_RPC_GET_HEIGHT::request reqh;
//     cryptonote::COMMAND_RPC_GET_HEIGHT::response resph;
//     if (!in_pool)
//     {
//         epee::net_utils::invoke_http_json("/get_height", reqh, resph, http_client);
//         uint64_t bc_height = resph.height;
//         confirmations      = bc_height - conf_height;
//     }

//     return true;
// }
// //----------------------------------------------------------------------------------------------------
// bool check_tx_proof(const cryptonote::transaction &tx,
//     const cryptonote::account_public_address &address,
//     bool is_subaddress,
//     const std::string &message,
//     const std::string &sig_str,
//     uint64_t &received)
// {
//     // 1. Get proof type and version
//     // InProofV1, InProofV2, OutProofV1, OutProofV2
//     const bool is_out        = sig_str.substr(0, 3) == "Out";
//     const std::string header = is_out ? sig_str.substr(0, 10) : sig_str.substr(0, 9);
//     int version              = 2;  // InProofV2
//     if (is_out && sig_str.substr(8, 2) == "V1")
//         version = 1;  // OutProofV1
//     else if (is_out)
//         version = 2;  // OutProofV2
//     else if (sig_str.substr(7, 2) == "V1")
//         version = 1;  // InProofV1

//     const size_t header_len = header.size();
//     THROW_WALLET_EXCEPTION_IF(sig_str.size() < header_len || sig_str.substr(0, header_len) != header,
//         tools::error::wallet_internal_error,
//         "Signature header check error");

//     // 2. Decode base58
//     std::vector<crypto::public_key> shared_secret(1);
//     std::vector<crypto::signature> sig(1);
//     const size_t pk_len =
//         tools::base58::encode(std::string((const char *)&shared_secret[0], sizeof(crypto::public_key))).size();
//     const size_t sig_len  = tools::base58::encode(std::string((const char *)&sig[0], sizeof(crypto::signature))).size();
//     const size_t num_sigs = (sig_str.size() - header_len) / (pk_len + sig_len);
//     THROW_WALLET_EXCEPTION_IF(sig_str.size() != header_len + num_sigs * (pk_len + sig_len),
//         tools::error::wallet_internal_error,
//         "Wrong signature size");
//     shared_secret.resize(num_sigs);
//     sig.resize(num_sigs);
//     for (size_t i = 0; i < num_sigs; ++i)
//     {
//         std::string pk_decoded;
//         std::string sig_decoded;
//         const size_t offset = header_len + i * (pk_len + sig_len);
//         THROW_WALLET_EXCEPTION_IF(!tools::base58::decode(sig_str.substr(offset, pk_len), pk_decoded),
//             tools::error::wallet_internal_error,
//             "Signature decoding error");
//         THROW_WALLET_EXCEPTION_IF(!tools::base58::decode(sig_str.substr(offset + pk_len, sig_len), sig_decoded),
//             tools::error::wallet_internal_error,
//             "Signature decoding error");
//         THROW_WALLET_EXCEPTION_IF(
//             sizeof(crypto::public_key) != pk_decoded.size() || sizeof(crypto::signature) != sig_decoded.size(),
//             tools::error::wallet_internal_error,
//             "Signature decoding error");
//         memcpy(&shared_secret[i], pk_decoded.data(), sizeof(crypto::public_key));
//         memcpy(&sig[i], sig_decoded.data(), sizeof(crypto::signature));
//     }

//     crypto::public_key tx_pub_key = get_tx_pub_key_from_extra(tx);
//     THROW_WALLET_EXCEPTION_IF(
//         tx_pub_key == crypto::null_pkey, tools::error::wallet_internal_error, "Tx pubkey was not found");

//     std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(tx);
//     THROW_WALLET_EXCEPTION_IF(additional_tx_pub_keys.size() + 1 != num_sigs,
//         tools::error::wallet_internal_error,
//         "Signature size mismatch with additional tx pubkeys");

//     const crypto::hash txid = cryptonote::get_transaction_hash(tx);
//     std::string prefix_data((const char *)&txid, sizeof(crypto::hash));
//     prefix_data += message;
//     crypto::hash prefix_hash;
//     crypto::cn_fast_hash(prefix_data.data(), prefix_data.size(), prefix_hash);

//     // 3. Check signature
//     std::vector<int> good_signature(num_sigs, 0);
//     if (is_out)
//     {
//         good_signature[0] = is_subaddress ? crypto::check_tx_proof(prefix_hash,
//                                                 tx_pub_key,
//                                                 address.m_view_public_key,
//                                                 address.m_spend_public_key,
//                                                 shared_secret[0],
//                                                 sig[0],
//                                                 version)
//                                           : crypto::check_tx_proof(prefix_hash,
//                                                 tx_pub_key,
//                                                 address.m_view_public_key,
//                                                 boost::none,
//                                                 shared_secret[0],
//                                                 sig[0],
//                                                 version);

//         for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
//         {
//             good_signature[i + 1] = is_subaddress ? crypto::check_tx_proof(prefix_hash,
//                                                         additional_tx_pub_keys[i],
//                                                         address.m_view_public_key,
//                                                         address.m_spend_public_key,
//                                                         shared_secret[i + 1],
//                                                         sig[i + 1],
//                                                         version)
//                                                   : crypto::check_tx_proof(prefix_hash,
//                                                         additional_tx_pub_keys[i],
//                                                         address.m_view_public_key,
//                                                         boost::none,
//                                                         shared_secret[i + 1],
//                                                         sig[i + 1],
//                                                         version);
//         }
//     }
//     else
//     {
//         good_signature[0] = is_subaddress ? crypto::check_tx_proof(prefix_hash,
//                                                 address.m_view_public_key,
//                                                 tx_pub_key,
//                                                 address.m_spend_public_key,
//                                                 shared_secret[0],
//                                                 sig[0],
//                                                 version)
//                                           : crypto::check_tx_proof(prefix_hash,
//                                                 address.m_view_public_key,
//                                                 tx_pub_key,
//                                                 boost::none,
//                                                 shared_secret[0],
//                                                 sig[0],
//                                                 version);

//         for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
//         {
//             good_signature[i + 1] = is_subaddress ? crypto::check_tx_proof(prefix_hash,
//                                                         address.m_view_public_key,
//                                                         additional_tx_pub_keys[i],
//                                                         address.m_spend_public_key,
//                                                         shared_secret[i + 1],
//                                                         sig[i + 1],
//                                                         version)
//                                                   : crypto::check_tx_proof(prefix_hash,
//                                                         address.m_view_public_key,
//                                                         additional_tx_pub_keys[i],
//                                                         boost::none,
//                                                         shared_secret[i + 1],
//                                                         sig[i + 1],
//                                                         version);
//         }
//     }

//     if (std::any_of(good_signature.begin(), good_signature.end(), [](int i) { return i > 0; }))
//     {
//         // 4. Obtain key derivation by multiplying scalar 1 to the shared secret
//         crypto::key_derivation derivation;
//         if (good_signature[0])
//             THROW_WALLET_EXCEPTION_IF(
//                 !crypto::generate_key_derivation(shared_secret[0], rct::rct2sk(rct::I), derivation),
//                 tools::error::wallet_internal_error,
//                 "Failed to generate key derivation");

//         std::vector<crypto::key_derivation> additional_derivations(num_sigs - 1);
//         for (size_t i = 1; i < num_sigs; ++i)
//             if (good_signature[i])
//                 THROW_WALLET_EXCEPTION_IF(!crypto::generate_key_derivation(
//                                               shared_secret[i], rct::rct2sk(rct::I), additional_derivations[i - 1]),
//                     tools::error::wallet_internal_error,
//                     "Failed to generate key derivation");

//         check_tx_key_helper(tx, derivation, additional_derivations, address, received);
//         return true;
//     }
//     return false;
// }
// //----------------------------------------------------------------------------------------------------
// bool get_pruned_tx(const cryptonote::COMMAND_RPC_GET_TRANSACTIONS::entry &entry,
//     cryptonote::transaction &tx,
//     crypto::hash &tx_hash)
// {
//     cryptonote::blobdata bd;

//     // easy case if we have the whole tx
//     if (!entry.as_hex.empty() || (!entry.prunable_as_hex.empty() && !entry.pruned_as_hex.empty()))
//     {
//         CHECK_AND_ASSERT_MES(epee::string_tools::parse_hexstr_to_binbuff(
//                                  entry.as_hex.empty() ? entry.pruned_as_hex + entry.prunable_as_hex : entry.as_hex, bd),
//             false,
//             "Failed to parse tx data");
//         CHECK_AND_ASSERT_MES(cryptonote::parse_and_validate_tx_from_blob(bd, tx), false, "Invalid tx data");
//         tx_hash = cryptonote::get_transaction_hash(tx);
//         // if the hash was given, check it matches
//         CHECK_AND_ASSERT_MES(entry.tx_hash.empty() || epee::string_tools::pod_to_hex(tx_hash) == entry.tx_hash,
//             false,
//             "Response claims a different hash than the data yields");
//         return true;
//     }
//     // case of a pruned tx with its prunable data hash
//     if (!entry.pruned_as_hex.empty() && !entry.prunable_hash.empty())
//     {
//         crypto::hash ph;
//         CHECK_AND_ASSERT_MES(
//             epee::string_tools::hex_to_pod(entry.prunable_hash, ph), false, "Failed to parse prunable hash");
//         CHECK_AND_ASSERT_MES(
//             epee::string_tools::parse_hexstr_to_binbuff(entry.pruned_as_hex, bd), false, "Failed to parse pruned data");
//         CHECK_AND_ASSERT_MES(parse_and_validate_tx_base_from_blob(bd, tx), false, "Invalid base tx data");
//         // only v2 txes can calculate their txid after pruned
//         if (bd[0] > 1)
//         {
//             tx_hash = cryptonote::get_pruned_transaction_hash(tx, ph);
//         }
//         else
//         {
//             // for v1, we trust the dameon
//             CHECK_AND_ASSERT_MES(
//                 epee::string_tools::hex_to_pod(entry.tx_hash, tx_hash), false, "Failed to parse tx hash");
//         }
//         return true;
//     }
//     return false;
// }
// //----------------------------------------------------------------------------------------------------
// void check_tx_key_helper(const cryptonote::transaction &tx,
//     const crypto::key_derivation &derivation,
//     const std::vector<crypto::key_derivation> &additional_derivations,
//     const cryptonote::account_public_address &address,
//     uint64_t &received)
// {
//     received = 0;

//     for (size_t n = 0; n < tx.vout.size(); ++n)
//     {
//         crypto::public_key output_public_key;
//         if (!get_output_public_key(tx.vout[n], output_public_key))
//             continue;

//         crypto::key_derivation found_derivation;
//         if (is_out_to_acc(address,
//                 output_public_key,
//                 derivation,
//                 additional_derivations,
//                 n,
//                 get_output_view_tag(tx.vout[n]),
//                 found_derivation))
//         {
//             uint64_t amount;
//             if (tx.version == 1 || tx.rct_signatures.type == rct::RCTTypeNull)
//             {
//                 amount = tx.vout[n].amount;
//             }
//             else
//             {
//                 crypto::secret_key scalar1;
//                 crypto::derivation_to_scalar(found_derivation, n, scalar1);
//                 rct::ecdhTuple ecdh_info = tx.rct_signatures.ecdhInfo[n];
//                 rct::ecdhDecode(ecdh_info,
//                     rct::sk2rct(scalar1),
//                     tx.rct_signatures.type == rct::RCTTypeBulletproof2 || tx.rct_signatures.type == rct::RCTTypeCLSAG ||
//                         tx.rct_signatures.type == rct::RCTTypeBulletproofPlus);
//                 const rct::key C = tx.rct_signatures.outPk[n].mask;
//                 rct::key Ctmp;
//                 THROW_WALLET_EXCEPTION_IF(
//                     sc_check(ecdh_info.mask.bytes) != 0, tools::error::wallet_internal_error, "Bad ECDH input mask");
//                 THROW_WALLET_EXCEPTION_IF(sc_check(ecdh_info.amount.bytes) != 0,
//                     tools::error::wallet_internal_error,
//                     "Bad ECDH input amount");
//                 rct::addKeys2(Ctmp, ecdh_info.mask, ecdh_info.amount, rct::H);
//                 if (rct::equalKeys(C, Ctmp))
//                     amount = rct::h2d(ecdh_info.amount);
//                 else
//                     amount = 0;
//             }
//             received += amount;
//         }
//     }
// }
// //----------------------------------------------------------------------------------------------------
// bool is_out_to_acc(const cryptonote::account_public_address &address,
//     const crypto::public_key &out_key,
//     const crypto::key_derivation &derivation,
//     const std::vector<crypto::key_derivation> &additional_derivations,
//     const size_t output_index,
//     const boost::optional<crypto::view_tag> &view_tag_opt,
//     crypto::key_derivation &found_derivation)
// {
//     crypto::public_key derived_out_key;
//     bool found = false;
//     bool r;
//     // first run quick check if output has matching view tag, otherwise output
//     // should not belong to account
//     if (cryptonote::out_can_be_to_acc(view_tag_opt, derivation, output_index))
//     {
//         // if view tag match, run slower check deriving output pub key and comparing
//         // to expected
//         r = crypto::derive_public_key(derivation, output_index, address.m_spend_public_key, derived_out_key);
//         THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, "Failed to derive public key");
//         if (out_key == derived_out_key)
//         {
//             found            = true;
//             found_derivation = derivation;
//         }
//     }

//     if (!found && !additional_derivations.empty())
//     {
//         const crypto::key_derivation &additional_derivation = additional_derivations[output_index];
//         if (cryptonote::out_can_be_to_acc(view_tag_opt, additional_derivation, output_index))
//         {
//             r = crypto::derive_public_key(
//                 additional_derivation, output_index, address.m_spend_public_key, derived_out_key);
//             THROW_WALLET_EXCEPTION_IF(!r, tools::error::wallet_internal_error, "Failed to derive public key");
//             if (out_key == derived_out_key)
//             {
//                 found            = true;
//                 found_derivation = additional_derivation;
//             }
//         }
//     }
//     return found;
// }
// //----------------------------------------------------------------------------------------------------
// void throw_on_rpc_response_error(bool r,
//     const epee::json_rpc::error &error,
//     const std::string &status,
//     const char *method)
// {
//     // Treat all RPC payment access errors the same, whether payment is actually required or not
//     THROW_WALLET_EXCEPTION_IF(
//         error.code == CORE_RPC_ERROR_CODE_INVALID_CLIENT, tools::error::deprecated_rpc_access, method);
//     THROW_WALLET_EXCEPTION_IF(
//         error.code, tools::error::wallet_coded_rpc_error, method, error.code, get_rpc_server_error_message(error.code));
//     THROW_WALLET_EXCEPTION_IF(!r, tools::error::no_connection_to_daemon, method);
//     // empty string -> not connection
//     THROW_WALLET_EXCEPTION_IF(status.empty(), tools::error::no_connection_to_daemon, method);

//     THROW_WALLET_EXCEPTION_IF(status == CORE_RPC_STATUS_BUSY, tools::error::daemon_busy, method);
//     THROW_WALLET_EXCEPTION_IF(status == CORE_RPC_STATUS_PAYMENT_REQUIRED, tools::error::deprecated_rpc_access, method);
//     // Deprecated RPC payment access endpoints would set status to "Client signature does not verify for <method>"
//     THROW_WALLET_EXCEPTION_IF(
//         status.compare(0, 16, "Client signature") == 0, tools::error::deprecated_rpc_access, method);
// }
// //----------------------------------------------------------------------------------------------------

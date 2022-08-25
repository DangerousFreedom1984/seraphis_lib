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
#include "jamtis_address_tag_utils.h"

//local headers
#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "seraphis_config_temp.h"
extern "C"
{
#include "crypto/twofish.h"
}
#include "jamtis_support_types.h"
#include "memwipe.h"
#include "misc_language.h"
#include "ringct/rctTypes.h"
#include "sp_crypto_utils.h"
#include "sp_hash_functions.h"
#include "sp_transcript.h"

//third party headers

//standard headers


namespace sp
{
namespace jamtis
{
/// secret for encrypting address tags
using encrypted_address_tag_secret_t = encrypted_address_tag_t;
static_assert(sizeof(encrypted_address_tag_secret_t) == sizeof(address_tag_t), "");

/// helper for encrypting/decrypting with the Blowfish block cipher
struct Blowfish_LR_wrapper
{
    unsigned char *bytes_ref;

    std::uint32_t* L_addr() { return reinterpret_cast<std::uint32_t*>(bytes_ref); }
    std::uint32_t* R_addr() { return reinterpret_cast<std::uint32_t*>(bytes_ref + 4); }
};

/// block size
constexpr std::size_t TWOFISH_BLOCK_SIZE{16};

//-------------------------------------------------------------------------------------------------------------------
// encryption_secret = truncate_to_addr_tag_size(H_32(q, Ko))
//-------------------------------------------------------------------------------------------------------------------
static encrypted_address_tag_secret_t get_encrypted_address_tag_secret(const rct::key &sender_receiver_secret,
    const rct::key &onetime_address)
{
    static_assert(sizeof(encrypted_address_tag_secret_t) <= 32, "");

    // temp_encryption_secret = H_32(q, Ko)
    SpKDFTranscript transcript{config::HASH_KEY_JAMTIS_ENCRYPTED_ADDRESS_TAG, 2 * sizeof(rct::key)};
    transcript.append("q", sender_receiver_secret);
    transcript.append("Ko", onetime_address);

    rct::key temp_encryption_secret;
    sp_hash_to_32(transcript, temp_encryption_secret.bytes);

    // truncate to desired size of the secret
    encrypted_address_tag_secret_t encryption_secret;
    memcpy(encryption_secret.bytes, temp_encryption_secret.bytes, sizeof(encrypted_address_tag_secret_t));

    return encryption_secret;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
jamtis_address_tag_cipher_context::jamtis_address_tag_cipher_context(const rct::key &cipher_key)
{
    Twofish_initialise();
    Twofish_prepare_key(cipher_key.bytes, sizeof(rct::key), &(m_twofish_key));
}
//-------------------------------------------------------------------------------------------------------------------
jamtis_address_tag_cipher_context::~jamtis_address_tag_cipher_context()
{
    memwipe(&m_twofish_key, sizeof(Twofish_key));
}
//-------------------------------------------------------------------------------------------------------------------
// pseudo-CBC encryption (equivalent to CBC ciphertext stealing, but more intuitive)
// - given a plaintext that isn't a multiple of the cipher block size, use an 'overlapping' chained block cipher
// - example
//     block size: 4 bits
//     plaintext: 1111111
//     blocks:    [111[1]111]  (the 4th bit overlaps)
//     cipher block 1:      [010[0]111]  (first 4 bits ciphered)
//     xor non-overlapping: [010[0]101]  (last 3 bits xord with first three)
//     cipher block 2:      [010[1]110]  (last 4 bits ciphered)
//-------------------------------------------------------------------------------------------------------------------
address_tag_t jamtis_address_tag_cipher_context::cipher(const address_index_t &j) const
{
    // concatenate index and MAC
    address_tag_t addr_tag{j};

    // expect address index to fit in one Twofish block (16 bytes), and for there to be no more than 2 Twofish blocks
    static_assert(sizeof(address_index_t) <= TWOFISH_BLOCK_SIZE &&
            sizeof(address_tag_t) >= TWOFISH_BLOCK_SIZE &&
            sizeof(address_tag_t) <= 2 * TWOFISH_BLOCK_SIZE,
        "");

    // encrypt the first block
    unsigned char temp_cipher[TWOFISH_BLOCK_SIZE];
    memcpy(temp_cipher, addr_tag.bytes, TWOFISH_BLOCK_SIZE);
    Twofish_encrypt_block(&m_twofish_key, temp_cipher, temp_cipher);
    memcpy(addr_tag.bytes, temp_cipher, TWOFISH_BLOCK_SIZE);

    static constexpr std::size_t nonoverlapping_width{sizeof(address_tag_t) - TWOFISH_BLOCK_SIZE};
    if (nonoverlapping_width > 0)
    {
        // XOR the non-overlapping pieces
        for (std::size_t offset_index{0}; offset_index < nonoverlapping_width; ++offset_index)
        {
            addr_tag.bytes[offset_index + TWOFISH_BLOCK_SIZE] ^= addr_tag.bytes[offset_index];
        }

        // encrypt the second block (pseudo-CBC mode)
        memcpy(temp_cipher, addr_tag.bytes + nonoverlapping_width, TWOFISH_BLOCK_SIZE);
        Twofish_encrypt_block(&m_twofish_key, temp_cipher, temp_cipher);
        memcpy(addr_tag.bytes + nonoverlapping_width, temp_cipher, TWOFISH_BLOCK_SIZE);
    }

    return addr_tag;
}
//-------------------------------------------------------------------------------------------------------------------
bool jamtis_address_tag_cipher_context::try_decipher(address_tag_t addr_tag, address_index_t &j_out) const
{
    // expect one of the following
    // A) address tag is exactly one block
    // B) address tag fits in 2 blocks and index equals one block
    static_assert(
            (
                sizeof(address_tag_t) == TWOFISH_BLOCK_SIZE
            ) ||
            (
                sizeof(address_index_t) == TWOFISH_BLOCK_SIZE &&
                sizeof(address_tag_t) > TWOFISH_BLOCK_SIZE &&
                sizeof(address_tag_t) <= 2 * TWOFISH_BLOCK_SIZE
            ),
        "");

    // decrypt the second block
    static constexpr std::size_t nonoverlapping_width{sizeof(address_tag_t) - TWOFISH_BLOCK_SIZE};

    unsigned char temp_cipher[TWOFISH_BLOCK_SIZE];
    memcpy(temp_cipher, addr_tag.bytes + nonoverlapping_width, TWOFISH_BLOCK_SIZE);
    Twofish_decrypt_block(&m_twofish_key, temp_cipher, temp_cipher);
    memcpy(addr_tag.bytes + nonoverlapping_width, temp_cipher, TWOFISH_BLOCK_SIZE);    

    // XOR the non-overlapping pieces
    for (std::size_t offset_index{0}; offset_index < nonoverlapping_width; ++offset_index)
    {
        addr_tag.bytes[offset_index + TWOFISH_BLOCK_SIZE] ^= addr_tag.bytes[offset_index];
    }

    // check the mac
    address_index_t j_temp;

    if (!try_get_address_index(addr_tag, j_temp))
        return false;

    // decrypt the remaining bytes (if there are any)
    if (nonoverlapping_width > 0)
    {
        // decrypt the first block
        memcpy(temp_cipher, addr_tag.bytes, TWOFISH_BLOCK_SIZE);
        Twofish_decrypt_block(&m_twofish_key, temp_cipher, temp_cipher);
        memcpy(addr_tag.bytes, temp_cipher, TWOFISH_BLOCK_SIZE);
    }

    // extract the index j
    if (!try_get_address_index(addr_tag, j_out))
        return false;

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_address_index(const address_tag_t &addr_tag, address_index_t &j_out)
{
    // addr_tag -> {j, MAC}
    address_tag_MAC_t mac{};
    memcpy(&j_out, addr_tag.bytes, ADDRESS_INDEX_BYTES);
    memcpy(&mac, addr_tag.bytes + ADDRESS_INDEX_BYTES, ADDRESS_TAG_MAC_BYTES);

    return mac == address_tag_MAC_t{};
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t cipher_address_index(const jamtis_address_tag_cipher_context &cipher_context, const address_index_t &j)
{
    return cipher_context.cipher(j);
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t cipher_address_index(const rct::key &cipher_key, const address_index_t &j)
{
    // prepare to encrypt the index and MAC
    const jamtis_address_tag_cipher_context cipher_context{cipher_key};

    // encrypt it
    return cipher_address_index(cipher_context, j);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_decipher_address_index(const jamtis_address_tag_cipher_context &cipher_context,
    const address_tag_t &addr_tag,
    address_index_t &j_out)
{
    return cipher_context.try_decipher(addr_tag, j_out);
}
//-------------------------------------------------------------------------------------------------------------------
bool try_decipher_address_index(const rct::key &cipher_key, const address_tag_t &addr_tag, address_index_t &j_out)
{
    // prepare to decrypt the tag
    const jamtis_address_tag_cipher_context cipher_context{cipher_key};

    // decrypt it
    return try_decipher_address_index(cipher_context, addr_tag, j_out);
}
//-------------------------------------------------------------------------------------------------------------------
encrypted_address_tag_t encrypt_address_tag(const rct::key &sender_receiver_secret,
    const rct::key &onetime_address,
    const address_tag_t &addr_tag)
{
    static_assert(sizeof(address_tag_t), "");

    // addr_tag_enc = addr_tag XOR encryption_secret
    return addr_tag ^ get_encrypted_address_tag_secret(sender_receiver_secret, onetime_address);
}
//-------------------------------------------------------------------------------------------------------------------
address_tag_t decrypt_address_tag(const rct::key &sender_receiver_secret,
    const rct::key &onetime_address,
    const encrypted_address_tag_t &addr_tag_enc)
{
    // addr_tag = addr_tag_enc XOR encryption_secret
    return addr_tag_enc ^ get_encrypted_address_tag_secret(sender_receiver_secret, onetime_address);
}
//-------------------------------------------------------------------------------------------------------------------
void gen_address_tag(address_tag_t &addr_tag_inout)
{
    crypto::rand(sizeof(address_tag_t), reinterpret_cast<unsigned char*>(&addr_tag_inout));
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace jamtis
} //namespace sp

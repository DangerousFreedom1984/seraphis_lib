// Copyright (c) 2014-2024, The Monero Project
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

#include <boost/filesystem/path.hpp>
#include <cstdint>
#include <gtest/gtest.h>

#include "crypto/chacha.h"
#include "seraphis_wallet/key_container.h"
#include "unit_tests_utils.h"

using namespace seraphis_wallet;

TEST(seraphis_wallet, key_container) {
    KeyContainer container;
    crypto::chacha_key key;
}

TEST(seraphis_wallet, store_and_load_key_container)
{
    // 1. create variables, set password and path
    KeyContainer kc_all{},kc_all_recovered{},kc_vo{},kc_vb{};
    crypto::chacha_key chacha_key;
    const uint64_t kdf_rounds = 1;
    const epee::wipeable_string password = "password";
    const boost::filesystem::path wallet_file_all = unit_test::data_dir / "wallet3.spkeys";
    const boost::filesystem::path wallet_file_vo = unit_test::data_dir / "wallet3_vo.spkeys";
    
    // 2. generate chacha_key and keys of container
    crypto::generate_chacha_key(password.data(),password.length(),chacha_key,kdf_rounds);
    kc_all.generate_keys();

    // 3. save keys to file
    ASSERT_TRUE(kc_all.write_master(wallet_file_all.string(), chacha_key));
    ASSERT_TRUE(kc_all.write_view_all(wallet_file_vo.string(), chacha_key));
    
    // 4. load keys from file
    ASSERT_TRUE(kc_all_recovered.load_from_keys_file(wallet_file_all.string(), chacha_key, false));
    ASSERT_TRUE(kc_vo.load_from_keys_file(wallet_file_vo.string(), chacha_key, false));

    // 5. verify if stored and loaded keys are the same
    ASSERT_TRUE(kc_all.compare_keys(kc_all_recovered, chacha_key));
    ASSERT_FALSE(kc_all.compare_keys(kc_vo, chacha_key));
}

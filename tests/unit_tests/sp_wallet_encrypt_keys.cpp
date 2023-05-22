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


#include <gtest/gtest.h>

#include "jamtis_mock_keys.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis_wallet/encrypt_file.h"
#include "string_tools.h"



TEST(encrypt_wallet, read_write) {
  std::string secret{"secret"};
  std::string data1{"data1"};
  std::string data2;

  bool r1 = write_encrypted_file("test.wallet", secret, data1);
  bool r2 = read_encrypted_file("test.wallet", secret, data2);

  ASSERT_TRUE(r1 && r2);

}

TEST(encrypt_wallet, read_write_master_wallet) {

  std::string passwordA = "passwordA";
  std::string passwordB = "passwordB";

  bool r1 = generate_master_wallet("masterA.wallet",passwordA);
  bool r2 = generate_master_wallet("masterB.wallet", passwordB);
  jamtis_mock_keys master_keys;
  bool r3 = read_master_wallet("masterA.wallet", passwordA,master_keys);

  ASSERT_TRUE(r1 && r2 && r3);
}
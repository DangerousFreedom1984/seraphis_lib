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

#pragma once

#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "seraphis/sp_crypto_utils.h"


namespace cryptonote
{

enum class account_generator_era : unsigned char
{
  unknown = 0,
  cryptonote = 1,  //and ringct
  seraphis = 2
};

struct account_generators
{
  rct::key primary;    //e.g. for spend key
  rct::key secondary;  //e.g. for view key
};

inline const rct::key& get_primary_generator(const account_generator_era era)
{
  if (era == account_generator_era::cryptonote)
    return rct::G;
  else if (era == account_generator_era::seraphis)
    return sp::get_U_gen();
  else
    return rct::Z;  //error
}

inline const rct::key& get_secondary_generator(const account_generator_era era)
{
  if (era == account_generator_era::cryptonote)
    return rct::G;
  else if (era == account_generator_era::seraphis)
    return sp::get_X_gen();
  else
    return rct::Z;  //error
}

inline account_generators get_account_generators(const account_generator_era era)
{
  return account_generators{get_primary_generator(era), get_secondary_generator(era)};
}

} //namespace cryptonote

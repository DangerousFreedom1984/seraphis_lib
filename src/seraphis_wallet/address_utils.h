// Copyright (c) 2024, The Monero Project
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

// local headers
#include "seraphis_core/jamtis_destination.h"

// third party headers
#include <string>

// standard headers

// forward declarations

using namespace sp::jamtis;
using namespace sp;

enum class JamtisAddressNetwork : char
{
    MAINNET   = 'm',
    TESTNET   = 't',
    STAGENET  = 's',
    FAKECHAIN = 'f',
};

enum class JamtisAddressVersion : char
{
    V1 = '1',
};

// Given the JamtisDestination, JamtisAddressVersion and JamtisAddressNetwork
// get the human-readable address format 'xmra...'
void get_str_from_destination(const JamtisDestinationV1 &dest,
    const JamtisAddressVersion address_version,
    const JamtisAddressNetwork address_network,
    std::string &address_out);

// Given the human-readable address format 'xmra...'
// get the JamtisDestination
void get_destination_from_str(const std::string &address, JamtisDestinationV1 &dest_out);

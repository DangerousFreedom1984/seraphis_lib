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

// Core hash functions for Seraphis (note: this implementation satisfies the Jamtis specification).


#pragma once

//local headers

//third party headers

//standard headers

//forward declarations
namespace sp { class SpTranscript; }

namespace sp
{

/// H_1(x): 1-byte output
void sp_hash_to_1(const SpTranscript &transcript, unsigned char *hash_out);
/// H_8(x): 8-byte output
void sp_hash_to_8(const SpTranscript &transcript, unsigned char *hash_out);
/// H_16(x): 16-byte output
void sp_hash_to_16(const SpTranscript &transcript, unsigned char *hash_out);
/// H_32(x): 32-byte output
void sp_hash_to_32(const SpTranscript &transcript, unsigned char *hash_out);
/// H_n(x): Ed25519 group scalar output (32 bytes)
void sp_hash_to_scalar(const SpTranscript &transcript, unsigned char *hash_out);
/// H_n[k](x): Ed25519 group scalar output (32 bytes); 32-byte key
void sp_derive_key(const unsigned char *derivation_key, const SpTranscript &transcript, unsigned char *hash_out);
/// H_32[k](x): 32-byte output; 32-byte key
void sp_derive_secret(const unsigned char *derivation_key, const SpTranscript &transcript, unsigned char *hash_out);

} //namespace sp

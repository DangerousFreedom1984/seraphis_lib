#Copyright(c) 2014 - 2022, The Monero Project
#
#All rights reserved.
#
#Redistribution and use in source and binary forms, with or without modification, are
#permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#of conditions and the following disclaimer in the documentation and / or other
#materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#used to endorse or promote products derived from this software without specific
#prior written permission.
#
#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
#EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
#MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.IN NO EVENT SHALL
#THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES(INCLUDING, BUT NOT LIMITED TO,
#PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#STRICT LIABILITY, OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
#THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(seraphis_wallet_sources
    address_utils.cpp
    jamtis_keys.cpp
    key_container.cpp
    send_receive.cpp
    serialization_types.cpp
    show_enotes.cpp
    sp_knowledge_proofs.cpp
    transaction_history.cpp
    wallet3.cpp)

set(wallet3_sources
    wallet3.cpp)

monero_find_all_headers(wallet_private_headers "${CMAKE_CURRENT_SOURCE_DIR}")

monero_private_headers(seraphis_wallet
  ${wallet_private_headers})

monero_private_headers(wallet3
  ${wallet_private_headers})

monero_add_library(seraphis_wallet
  ${seraphis_wallet_sources}
  ${seraphis_wallet_private_headers})

monero_add_executable(wallet3
  ${seraphis_wallet_sources}
  ${seraphis_wallet_headers}
  ${seraphis_wallet_private_headers})

target_link_libraries(seraphis_wallet
  PUBLIC
    cncrypto
    common
    cryptonote_basic
    device
    epee
    ringct
    seraphis_core
    seraphis_crypto
    seraphis_impl
    seraphis_mocks
    rpc_base
    multisig
    net
    wallet2_basic
    ${LMDB_LIBRARY}
    ${Boost_CHRONO_LIBRARY}
    ${Boost_SERIALIZATION_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_THREAD_LIBRARY}
    ${Boost_REGEX_LIBRARY}
  PRIVATE
    ${EXTRA_LIBRARIES})

target_link_libraries(wallet3
  PUBLIC
    cncrypto
    common
    cryptonote_basic
    device
    epee
    ringct
    seraphis_core
    seraphis_crypto
    seraphis_impl
    seraphis_mocks
    rpc_base
    multisig
    net
    wallet2_basic
    ${LMDB_LIBRARY}
    ${Boost_CHRONO_LIBRARY}
    ${Boost_SERIALIZATION_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_THREAD_LIBRARY}
    ${Boost_REGEX_LIBRARY}
  PRIVATE
    ${EXTRA_LIBRARIES}
    ${EPEE_READLINE}
    qrcodegen
    version
    ${Boost_CHRONO_LIBRARY}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_LOCALE_LIBRARY}
    ${ICU_LIBRARIES}
    ${Boost_THREAD_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${GNU_READLINE_LIBRARY}
    ${EXTRA_LIBRARIES})
set_property(TARGET wallet3
  PROPERTY
    OUTPUT_NAME "monero-wallet3")
install(TARGETS wallet3 DESTINATION bin)
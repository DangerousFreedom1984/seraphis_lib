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
#include "tx_discretized_fees.h"

//local headers
#include "seraphis_config_temp.h"

//third party headers

//standard headers
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <mutex>
#include <utility>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{

/// fee context: set of <level, value> pairs
static std::vector<std::pair<discretized_fee_level_t, std::uint64_t>> s_discretized_fee_map;

static std::once_flag init_fee_context_once_flag;

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static long double round_to_sig_figs(long double value, const std::size_t num_sig_figs)
{
    std::size_t decimal_scale{0};

    // put value into scientific notation (with each desired significant digit left above the decimal point)
    while (value >= std::pow(10.0, num_sig_figs))
    {
        value /= 10.0;
        ++decimal_scale;
    }

    // round
    value = std::round(value);

    // put value back into normal notation
    while (decimal_scale)
    {
        value *= 10.0;
        --decimal_scale;
    }

    return value;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void generate_discretized_fee_context()
{
    std::call_once(init_fee_context_once_flag,
        [&](){

        const long double fee_level_factor{config::DISC_FEE_LEVEL_NUMERATOR_X100 / 100.0};
        std::size_t current_level{0};
        std::uint64_t last_fee_value{static_cast<std::uint64_t>(-1)};
        std::uint64_t fee_value;

        do
        {
            // value = round_1_sig_fig(factor ^ level)
            fee_value = static_cast<std::uint64_t>(round_to_sig_figs(std::pow(fee_level_factor, current_level), 1));

            // skip if we already have this value
            if (fee_value == last_fee_value)
                continue;

            // save fee level and value
            s_discretized_fee_map.emplace_back(static_cast<discretized_fee_level_t>(current_level), fee_value);

            last_fee_value = fee_value;
        } while (round_to_sig_figs(std::pow(fee_level_factor, ++current_level), 1) < std::numeric_limits<std::uint64_t>::max());

        s_discretized_fee_map.emplace_back(static_cast<discretized_fee_level_t>(current_level), 0);

        // sanity check
        if (current_level > std::numeric_limits<discretized_fee_level_t>::max())
            throw std::runtime_error("Seraphis discretized fees: could not fit all fee levels in the fee level type.");

    });
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
bool try_discretize_fee_value(const std::uint64_t raw_fee_value, DiscretizedFee &discretized_fee_out)
{
    // try to find the closest discretized fee that is >= the specified fee value
    generate_discretized_fee_context();

    DiscretizedFee temp_discretized_fee;
    std::uint64_t closest_discretized_fee_value{static_cast<std::uint64_t>(-1)};
    bool result_found{false};

    for (const auto &discretized_fee_setting : s_discretized_fee_map)
    {
        if (discretized_fee_setting.second < raw_fee_value)
            continue;

        if (discretized_fee_setting.second <= closest_discretized_fee_value)
        {
            temp_discretized_fee.m_fee_level = discretized_fee_setting.first;
            closest_discretized_fee_value = discretized_fee_setting.second;
            result_found = true;
        }
    }

    // check if a valid fee was found (if the fee value was > the highest discretized fee value, this will fail)
    if (!result_found)
        return false;

    discretized_fee_out = temp_discretized_fee;
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool try_get_fee_value(const DiscretizedFee discretized_fee, std::uint64_t &fee_value_out)
{
    // try to find this discretized fee in the map and return its fee value
    generate_discretized_fee_context();

    const auto found_fee = std::find_if(s_discretized_fee_map.begin(), s_discretized_fee_map.end(),
            [&discretized_fee](const auto &discretized_fee_setting) -> bool
            {
                return discretized_fee_setting.first == discretized_fee;
            }
        );

    if (found_fee == s_discretized_fee_map.end())
        return false;

    fee_value_out = found_fee->second;
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp

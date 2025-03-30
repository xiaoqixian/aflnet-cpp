// Date:   Fri Mar 28 11:27:36 AM 2025
// Mail:   lunar_ubuntu@qq.com
// Author: https://github.com/xiaoqixian

#pragma once

#include <cstddef>
#include <cstdint>

constexpr size_t MAP_SIZE_POW2 = 16;
constexpr size_t MAP_SIZE = 1 << MAP_SIZE_POW2;

constexpr size_t MAX_FILE = 1 * 1024 * 1024;
constexpr size_t SKIP_TO_NEW_PROB = 99;
constexpr size_t SKIP_NFAV_NEW_PROB = 75;
constexpr size_t SKIP_NFAV_OLD_PROB = 95;

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;


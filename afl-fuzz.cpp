// Date:   Fri Mar 28 11:14:07 AM 2025
// Mail:   lunar_ubuntu@qq.com
// Author: https://github.com/xiaoqixian

#include <cassert>
#include <cstdio>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <random>
#include <vector>
#include "aflnet.h"
#include "config.h"
#include "hash.h"

#define TODO() assert(false)

using StateSeq = std::vector<u32>;
using Buf = std::vector<u8>;

static std::unordered_set<u32> ipsm_paths;
static std::function<StateSeq(Buf const&)> extract_response_codes;
static std::unordered_map<u32, state_info_t> state_map;

static Buf response_buf;

static size_t message_sent = 0;

/* Though its called a queue, I feel like it acts like a all push 
 * from back container.*/
static std::vector<queue_entry> queue;
static size_t queued_paths = 0;

template <typename T = size_t>
static T gen_random(T max, T min = 0) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<T> dis(min, max);
    return dis(gen);
}

static size_t get_unique_state_count(StateSeq const& state_seq) {
  return std::unordered_set(
    state_seq.cbegin(), state_seq.cend()
  ).size();
}

static bool is_state_sequnce_interesting(StateSeq const& state_seq) {
  StateSeq trimmed_state_seq;
  for (size_t i = 0; i < state_seq.size(); i++) {
    if (i >= 2 && state_seq[i] == state_seq[i-1] && state_seq[i] == state_seq[i-2]) {
      continue;
    }
    trimmed_state_seq.emplace_back(state_seq[i]);
  }

  u32 hash_key = hash32(trimmed_state_seq.data(), trimmed_state_seq.size(), 0);
  
  if (ipsm_paths.contains(hash_key)) {
    return false;
  } else {
    ipsm_paths.emplace(hash_key);
    return true;
  }
}

/**
 * Update the annotaions of regions, with the state sequence received
 * from the server.
 */
static void update_region_annotations(queue_entry& q) {
  for (size_t i = 0; i < message_sent; i++) {
    if (
      response_buf[i] == 0 || 
      (i > 0 && response_buf[i] == response_buf[i-1])
    ) {
      q.regions[i].state_seq.clear();
    } else {
      q.regions[i].state_seq = extract_response_codes(response_buf);
    }
  }
}

/**
 * Choose a region data for region-level mutations
 */
static Buf choose_source_region() {
  auto const index = gen_random(queued_paths);
  auto& q = queue[index];
  Buf out;

  if (!q.regions.empty()) {
    auto const reg_idx = gen_random(q.regions.size());
    auto const& reg = q.regions[reg_idx];
    
    const size_t len = reg.end_byte - reg.start_byte + 1;
    if (len <= MAX_FILE) {
      out.reserve(len);
      
      FILE* fp = std::fopen(q.fname.c_str(), "rb");
      std::fseek(fp, reg.start_byte, SEEK_CUR);
      std::fread(out.data(), 1, len, fp);
      std::fclose(fp);
    }
  }
  return out;
}

/**
 * Update state.fuzzs when visiting specific state
 */
static void update_fuzzs() {
  auto const state_seq = extract_response_codes(response_buf);
  std::unordered_set<u32> state_id_set;
  
  for (auto const state_id: state_seq) {
    if (state_id_set.contains(state_id)) continue;
    state_id_set.emplace(state_id);
    auto const it = state_map.find(state_id);
    if (it != state_map.end()) {
      it->second.fuzzs++;
    }
  }
}

static u32 update_scores_and_select_next_state(u8 const mode) {
}

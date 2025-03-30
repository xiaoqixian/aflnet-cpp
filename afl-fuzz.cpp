// Date:   Fri Mar 28 11:14:07 AM 2025
// Mail:   lunar_ubuntu@qq.com
// Author: https://github.com/xiaoqixian

#include <array>
#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <functional>
#include <list>
#include <memory>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <random>
#include <vector>
#include <graphviz/gvc.h>
#include <graphviz/cgraph.h>
#include <fcntl.h>

#include "aflnet.h"
#include "config.h"
#include "hash.h"
#include "debug.h"

#define TODO() assert(false)

using StateSeq = std::vector<u32>;
using Buf = std::vector<u8>;

enum class SelectMode: u8 {
  Random,
  RoundRobin,
  Favor
};

static constexpr size_t STATE_STR_LEN = 12;

static std::unordered_set<u32> ipsm_paths;
static std::function<StateSeq(Buf const&)> extract_response_codes;
static std::unordered_map<u32, state_info_t> state_map;
static std::vector<u32> state_ids;
static std::vector<std::vector<FuzzedState>> was_fuzzed_map;
static std::list<std::vector<u8>> messages;

static Agraph_t* ipsm = nullptr;

static size_t selected_state_idx = 0;
static size_t state_cycles = 0;
static size_t queue_cycles = 0;
static size_t pending_favored = 0;
static u32 target_state_id;

static char const* out_dir = nullptr;
static std::string ipsm_dot_fname;

static Buf response_buf;

static size_t message_sent = 0;

/* Though its called a queue, I feel like it acts like a all push 
 * from back container.*/
static std::vector<std::shared_ptr<queue_entry>> queue;
static size_t queued_paths = 0;

template <typename T = size_t>
static T gen_random(T max, T min = 0) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<T> dis(min, max);
    return dis(gen);
}

static void setup_fnames() {
  std::stringstream ss;
  ss << out_dir << "/ipsm.dot";
  ipsm_dot_fname = ss.str();
  ss.clear();
}

static size_t get_unique_state_count(StateSeq const& state_seq) {
  return std::unordered_set(
    state_seq.cbegin(), state_seq.cend()
  ).size();
}

static size_t get_state_index(u32 state_id) {
  for (size_t i = 0; i < state_ids.size(); i++) {
    if (state_ids[i] == state_id) return i;
  }
  assert(false);
}

/**
 * Expand the size of the map when a new seed or a new state has beed discovered.
 */
void expand_was_fuzzed_map(u32 new_states, u32 new_qentries) {
  auto const fuzzed_map_size = was_fuzzed_map.empty() ? 0 : was_fuzzed_map.front().size();

  for (auto& fuzz_map: was_fuzzed_map) {
    fuzz_map.resize(fuzzed_map_size + new_qentries, FuzzedState::Unreachable);
  }

  was_fuzzed_map.reserve(was_fuzzed_map.size() + new_states);
  for (size_t i = 0; i < new_states; i++) {
    was_fuzzed_map.emplace_back(fuzzed_map_size + new_qentries, FuzzedState::Unreachable);
  }
}

static bool is_state_sequence_interesting(StateSeq const& state_seq) {
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

  if (!q->regions.empty()) {
    auto const reg_idx = gen_random(q->regions.size());
    auto const& reg = q->regions[reg_idx];
    
    const size_t len = reg.end_byte - reg.start_byte + 1;
    if (len <= MAX_FILE) {
      out.reserve(len);
      
      FILE* fp = std::fopen(q->fname.c_str(), "rb");
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

/**
 * Calculate state scores and select the next state
 */
static u32 update_scores_and_select_next_state(SelectMode const mode) {
  if (state_ids.empty()) return 0;

  std::vector<u32> state_scores;
  state_scores.reserve(state_ids.size());

  for (auto const state_id: state_ids) {
    auto& state = state_map[state_id];
    switch (mode) {
      case SelectMode::Favor:
        state.score = std::ceil(1000 * std::pow(2, -std::log10(state.fuzzs + 1) * state.selected_times + 1)) * std::pow(2, std::log(state.paths_discovered + 1));
      default:
        break;
    }

    if (state_scores.empty()) {
      state_scores.emplace_back(state.score);
    } else {
      state_scores.emplace_back(state_scores.back() + state.score);
    }
  }

  u32 const rand_score = gen_random<u32>(state_scores.back());
  u32 result = 0;
  for (size_t i = 0; i < state_scores.size(); i++) {
    if (rand_score <= state_scores[i]) {
      result = i;
      break;
    }
  }
  return result;
}

static u32 choose_target_state(SelectMode const mode) {
  switch (mode) {
    case SelectMode::Random:
      return state_ids[gen_random(state_ids.size())];
    case SelectMode::RoundRobin:
      {
        auto const res = state_ids[selected_state_idx];
        if (++selected_state_idx == state_ids.size()) {
          selected_state_idx = 0;
        }
        return res;
      }
    case SelectMode::Favor:
      /* Do RoundRobin for a few cycles to get enough statistical information*/
      if (state_cycles < 5) {
        auto const res = state_ids[selected_state_idx];
        if (++selected_state_idx == state_ids.size()) {
          selected_state_idx = 0;
          state_cycles = 0;
        }
        return res;
      }
      return update_scores_and_select_next_state(SelectMode::Favor);
  }
  assert(false);
}

/**
 * Select a seed to exercise the target state, 
 * return the seed index in the queue.
 */
static std::shared_ptr<queue_entry> choose_seed(u32 const target_state_id, SelectMode const mode) {
  auto& state = state_map[target_state_id];

  switch (mode) {
    case SelectMode::Random:
      state.selected_seed_index = gen_random(state.seeds.size());
      return state.seeds[state.selected_seed_index];
      
    case SelectMode::RoundRobin:
      {
        auto res = state.seeds[state.selected_seed_index];
        if (++state.selected_seed_index == state.seeds.size()) {
          state.selected_seed_index = 0;
        }
        return res;
      }
    case SelectMode::Favor:
      if (state.seeds.size() > 10) {
        std::shared_ptr<queue_entry> res = nullptr;
        for (u32 passed_cycles = 0; passed_cycles < 5;) {
          res = state.seeds[state.selected_seed_index];
          state.selected_seed_index++;
          if (state.selected_seed_index == state.seeds.size()) {
            state.selected_seed_index = 0;
            passed_cycles++;
          }

          /*
           * Skip this seed with high probability if it is neither 
           * an initial seed nor a seed generated while current 
           * target_state_id was targeted.
           */
          if (res->generating_state_id != target_state_id 
            && !res->is_initial_seed && gen_random(100) < 90) 
            continue;

          u32 const target_state_index = get_state_index(target_state_id);
          if (pending_favored > 0) {
            // If we have any favored, non-fuzzed new arrivals in the queue.
            // possibly skip to them at the expense of already-fuzzed
            // or non-favored.
            if (
              (was_fuzzed_map[target_state_index][res->index] == FuzzedState::Fuzzed || res->favored) &&
              gen_random(100u) < SKIP_TO_NEW_PROB
            ) continue;

            // Otherwise, the seed is selected.
            break;
          } else if (!res->favored && queued_paths > 10) {
            /* Otherwise, still possibly skip non-favored cases, 
             * albeit less often. 
             * The odds of skipping stuff are higher for 
             * already-fuzzed inputs and lower for never-fuzzed 
             * entries. */
            if (queue_cycles > 1 && was_fuzzed_map[target_state_index][res->index] == FuzzedState::ReachableNotFuzzed) {
              if (gen_random(100u) < SKIP_NFAV_NEW_PROB) continue;
            } else {
              if (gen_random(100u) < SKIP_NFAV_OLD_PROB) continue;
            }

          }
        }
        assert(res != nullptr);
        return res;
      } else {
        // Do round-robin if seeds count of the selected state is small
        auto res = state.seeds[state.selected_seed_index];
        state.selected_seed_index++;
        if (state.selected_seed_index == state.seeds.size()) {
          state.selected_seed_index = 0;
        }
        return res;
      }
      break;
  }
  assert(false);
}

static void update_state_aware_variables(std::shared_ptr<queue_entry> q, bool dry_run) {
  if (response_buf.empty()) return;

  auto const state_seq = extract_response_codes(response_buf);

  q->unique_state_count = get_unique_state_count(state_seq);

  if (is_state_sequence_interesting(state_seq)) {
    std::string fname;
    {
      auto const temp_str = state_sequence_to_string(state_seq);
      std::stringstream ss;
      ss << out_dir << "/replayable-new-ipsm-paths/id:" << temp_str << ':' << 
        (dry_run ? basename(q->fname.c_str()) : "new");
      fname = ss.str();
    }

    save_messages_to_file(messages, fname, true, message_sent);

    // Update the IPSM graph
    if (state_seq.size() > 1) {
      auto prev_state_id = state_seq[0];
      
      for (size_t i = 1; i < state_seq.size(); i++) {
        auto const curr_state_id = state_seq[i];
        
        char from_state[STATE_STR_LEN], to_state[STATE_STR_LEN];
        std::snprintf(from_state, STATE_STR_LEN, "%d", prev_state_id);
        std::snprintf(to_state, STATE_STR_LEN, "%d", curr_state_id);

        std::array<std::pair<char*, u32>, 2> from_to = {
          std::pair<char*, u32> {from_state, prev_state_id}, 
          std::pair<char*, u32> {to_state, curr_state_id}
        };
        std::array<Agnode_t*, 2> graph_nodes;
        size_t emplace_idx = 0;

        for (auto const [name, state_id]: from_to) {
          Agnode_t* node = agnode(ipsm, name, false);
          graph_nodes[emplace_idx++] = node;
          if (!node) {
            node = agnode(ipsm, name, true);
            if (dry_run) agset(node, const_cast<char*>("color"), "blue");
            else agset(node, const_cast<char*>("color"), "red");

            // Insert this newly discovered state into the states hashtable
            state_info_t new_state;
            new_state.id = state_id;
            new_state.is_covered = true;
            new_state.paths = 0;
            new_state.paths_discovered = 0;
            new_state.selected_times = 0;
            new_state.fuzzs = 0;
            new_state.score = 1;
            new_state.selected_seed_index = 0;

            state_map.emplace(state_id, std::move(new_state));
            state_ids.emplace_back(state_id);

            if (state_id != 0) expand_was_fuzzed_map(1, 0);
          }
        }

        Agnode_t* from = graph_nodes[0], *to = graph_nodes[1];
        Agedge_t* edge = agedge(ipsm, from, to, NULL, false);
        if (!edge) {
          edge = agedge(ipsm, from, to, NULL, true);
          if (dry_run) agset(edge, const_cast<char*>("color"), "blue");
          else agset(edge, const_cast<char*>("color"), "red");
        }

        prev_state_id = curr_state_id;
      }
    }

    // update the dot file
    const int fd = open(ipsm_dot_fname.c_str(), O_WRONLY | O_CREAT, 0600);
    if (fd < 0) {
      PFATAL("Unable to create %s", ipsm_dot_fname.c_str());
    } else {
      FILE* ipsm_dot_file = fdopen(fd, "w");
      agwrite(ipsm, ipsm_dot_file);
      close(fd);
    }
  }

  update_region_annotations(*q);

  // Update the states hashtable to keep the list of seeds which help 
  // us to reach a specific state
  // Iterate over the regions & their annotated state sequences and 
  // update the hashtable accordingly.
  // All seeds should reach state 0 (initial state), so we add this 
  // one to the map first.
  auto const it = state_map.find(0);
  if (it == state_map.end()) {
    PFATAL("AFLNet - the states hashtable should always contain an entry of the initial state");
  } else {
    auto& state = it->second;
    state.seeds.emplace_back(q);
    was_fuzzed_map[0][q->index] = FuzzedState::ReachableNotFuzzed;
  }

  // Now update other states
  for (size_t i = 0; i < q->regions.size(); i++) {
    if (!q->regions[i].state_seq.empty()) {
      auto const reachable_state_id = q->regions[i].state_seq.back();
      auto const it = state_map.find(reachable_state_id);
      if (it != state_map.end()) {
        it->second.seeds.emplace_back(q);
      } else {
        //XXX. This branch is supposed to be not reachable
        //However, due to some undeterminism, new state could be seen during regions' annotating process
        //even though the state was not observed before
        //To completely fix this, we should fix all causes leading to potential undeterminism
        //For now, we just add the state into the hashtable
        state_info_t new_state;
        new_state.id = reachable_state_id;
        new_state.is_covered = true;
        new_state.paths = 0;
        new_state.paths_discovered = 0;
        new_state.selected_times = 0;
        new_state.fuzzs = 0;
        new_state.score = 1;
        new_state.selected_seed_index = 0;
        new_state.seeds.emplace_back(q);

        state_map.emplace(reachable_state_id, std::move(new_state));
        state_ids.emplace_back(reachable_state_id);

        if (reachable_state_id != 0) expand_was_fuzzed_map(1, 0);
      }

      was_fuzzed_map[get_state_index(reachable_state_id)][q->index] = FuzzedState::ReachableNotFuzzed;
    }
  }

  //Update the number of paths which have traversed a specific state
  //It can be used for calculating fuzzing energy
  //A hash set is used so that the #paths is not updated more than once for one specific state
  std::unordered_set<u32> state_id_set;

  for (auto const state_id: state_seq) {
    if (state_id_set.contains(state_id)) continue;

    state_id_set.emplace(state_id);
    auto const it = state_map.find(state_id);
    if (it != state_map.end()) {
      it->second.paths++;
    }
  }

  if (!dry_run) {
    auto const it = state_map.find(target_state_id);
    if (it != state_map.end()) {
      it->second.paths_discovered++;
    }
  }
}

int main() {
  setup_fnames();
}

// Date:   Fri Mar 28 11:14:07 AM 2025
// Mail:   lunar_ubuntu@qq.com
// Author: https://github.com/xiaoqixian

#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <functional>
#include <list>
#include <memory>
#include <sched.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <unordered_map>
#include <unordered_set>
#include <random>
#include <vector>
#include <graphviz/gvc.h>
#include <graphviz/cgraph.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <filesystem>

#include "aflnet.h"
#include "config.h"
#include "hash.h"
#include "debug.h"
#include "util.h"

#define TODO() assert(false)

using StateSeq = std::vector<u32>;
using MessageSeq = std::vector<std::vector<u8>>;

enum class SelectMode: u8 {
  Random,
  RoundRobin,
  Favor
};
enum class Protocol: u8 {
  TCP,
  UDP
};

static std::unordered_set<u32> ipsm_paths;
static std::function<StateSeq(u8*, size_t)> extract_response_codes;
static std::function<std::vector<region_t>(u8*, size_t)> extract_requests;
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

static size_t max_seed_region_count = 0;

static std::string in_dir;
static char const* out_dir = nullptr;
static std::string ipsm_dot_fname;

static std::vector<u8> response_buf;
static std::vector<size_t> response_bytes;

static size_t message_sent = 0;
static size_t queued_favored = 0;

static size_t server_wait_usecs = 10000;
static size_t socket_timeout_usecs = 1000;
static size_t poll_wait_msecs = 1;
static Protocol net_protocol;
static u16 net_port;
static char const* net_ip;
static u16 local_port;

static pid_t forksrv_pid;
static pid_t child_pid;

static bool child_timed_out = false;

static u32 cur_depth = 0;
static u32 max_depth = 0;

static u64 last_path_time = 0;

static size_t mem_limit = MEM_LIMIT;

static const char* doc_path = "docs";

// Options
static bool false_negative_reduction = false;
static bool terminate_child = false;
static bool dumb_mode = false;

static bool uses_asan;

using BitMap = std::array<u8, MAP_SIZE>;
static BitMap session_virgin_bits;
static BitMap virgin_bits;
static BitMap virgin_tmout;
static BitMap virgin_crash;
static bool bitmap_changed = false;
static bool score_changed = false;

std::array<std::shared_ptr<queue_entry>, MAP_SIZE> top_rated {};

static u8* trace_bits;
static u8* in_bitmap;

static u32 shm_id;
static int dev_null_fd = -1;
static int fsrv_st_fd = -1;
static int fsrv_ctl_fd = -1;

static const char* target_path = NULL;

static u32 exec_tmout = EXEC_TIMEOUT;

/* Though its called a queue, I feel like it acts like a all push 
 * from back container.*/
static std::list<std::shared_ptr<queue_entry>> queue;

static inline u8 has_new_bits(BitMap& virgin_map);

static std::vector<region_t> convert_messages_to_regions();
static void save_regions_to_file(std::string const& fname, std::list<std::vector<u8>> const& messages);

/* Describe integer. Uses 12 cyclic static buffers for return values. The value
   returned should be five characters or less for all the integers we reasonably
   expect to see. */

static char* DI(u64 val) {

  static std::array<char[16], 12> tmp;
  static char cur;

  cur = (cur + 1) % 12;

#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast) do { \
    if (val < (_divisor) * (_limit_mult)) { \
      std::sprintf(static_cast<char*>(tmp[cur]), _fmt, ((_cast)val) / (_divisor)); \
      return tmp[cur]; \
    } \
  } while (0)

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1000, 99.95, "%0.01fk", double);

  /* 100k - 999k */
  CHK_FORMAT(1000, 1000, "%lluk", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1000 * 1000, 9.995, "%0.02fM", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1000 * 1000, 99.95, "%0.01fM", double);

  /* 100M - 999M */
  CHK_FORMAT(1000 * 1000, 1000, "%lluM", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000, 9.995, "%0.02fG", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1000LL * 1000 * 1000, 99.95, "%0.01fG", double);

  /* 100G - 999G */
  CHK_FORMAT(1000LL * 1000 * 1000, 1000, "%lluG", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 9.995, "%0.02fT", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 99.95, "%0.01fT", double);

  /* 100T+ */
  strcpy(tmp[cur], "infty");
  return tmp[cur];

}


/* Describe float. Similar to the above, except with a single
   static buffer. */

static char* DF(double val) {

  static char tmp[16];

  if (val < 99.995) {
    sprintf(tmp, "%0.02f", val);
    return tmp;
  }

  if (val < 999.95) {
    sprintf(tmp, "%0.01f", val);
    return tmp;
  }

  return DI((u64)val);

}


/* Describe integer as memory size. */

static char* DMS(u64 val) {

  static std::array<char[16], 12> tmp;
  static char cur;

  cur = (cur + 1) % 12;

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu B", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1024, 99.95, "%0.01f kB", double);

  /* 100k - 999k */
  CHK_FORMAT(1024, 1000, "%llu kB", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1024 * 1024, 9.995, "%0.02f MB", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1024 * 1024, 99.95, "%0.01f MB", double);

  /* 100M - 999M */
  CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024, 9.995, "%0.02f GB", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1024LL * 1024 * 1024, 99.95, "%0.01f GB", double);

  /* 100G - 999G */
  CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 9.995, "%0.02f TB", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 99.95, "%0.01f TB", double);

#undef CHK_FORMAT

  /* 100T+ */
  strcpy(tmp[cur], "infty");
  return tmp[cur];

}


template <typename T = size_t>
static T gen_random(T max, T min = 0) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<T> dis(min, max);
    return dis(gen);
}

static int check_open(const char* fname, const int mode) {
  int fd = open(fname, mode);
  if (fd < 0) {
    PFATAL("Open %s failed", fname);
  }
  return fd;
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

  const u32 hash_key = hash32(trimmed_state_seq.data(), trimmed_state_seq.size(), 0);
  
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
      response_bytes[i] == 0 || 
      (i > 0 && response_bytes[i] == response_bytes[i-1])
    ) {
      q.regions[i].state_seq.clear();
    } else {
      q.regions[i].state_seq = extract_response_codes(response_buf.data(), response_bytes[i]);
    }
  }
}

/**
 * Choose a region data for region-level mutations
 */
[[maybe_unused]]
static std::vector<u8> choose_source_region() {
  assert(!queue.empty());
  auto index = gen_random(queue.size());
  auto it = queue.begin();
  while (index--) it++;

  auto& q = *it;
  std::vector<u8> out;

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
[[maybe_unused]]
static void update_fuzzs() {
  auto const state_seq = extract_response_codes(response_buf.data(), response_buf.size());
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

[[maybe_unused]]
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
[[maybe_unused]]
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
          } else if (!res->favored && queue.size() > 10) {
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

[[maybe_unused]]
static void update_state_aware_variables(std::shared_ptr<queue_entry> q, bool dry_run) {
  if (response_buf.empty()) return;

  auto const state_seq = extract_response_codes(response_buf.data(), response_buf.size());

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
        stack_vec<Agnode_t*, 2> graph_nodes;

        for (auto const [name, state_id]: from_to) {
          Agnode_t* node = agnode(ipsm, name, false);
          graph_nodes.emplace_back(node);

          if (!node) {
            node = agnode(ipsm, name, true);
            if (dry_run) agset(node, const_cast<char*>("color"), const_cast<char*>("blue"));
            else agset(node, const_cast<char*>("color"), const_cast<char*>("red"));

            // Insert this newly discovered state into the states hashtable
            state_info_t new_state;
            new_state.id = state_id;
            new_state.is_covered = true;
            new_state.score = 1;

            state_map.emplace(state_id, std::move(new_state));
            state_ids.emplace_back(state_id);

            if (state_id != 0) expand_was_fuzzed_map(1, 0);
          }
        }

        Agnode_t* from = graph_nodes[0], *to = graph_nodes[1];
        Agedge_t* edge = agedge(ipsm, from, to, NULL, false);
        if (!edge) {
          edge = agedge(ipsm, from, to, NULL, true);
          if (dry_run) agset(edge, const_cast<char*>("color"), const_cast<char*>("blue"));
          else agset(edge, const_cast<char*>("color"), const_cast<char*>("red"));
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
        new_state.score = 1;
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

/**
 * Send messages over network, returns a bool to represent if the 
 * communication is successful.
 */
[[maybe_unused]]
static bool send_over_network() {
  bool likely_buggy = false;
  
  usleep(server_wait_usecs);

  response_buf.clear();
  response_bytes.clear();

  //Create a TCP/UDP socket
  int sockfd = -1;
  if (net_protocol == Protocol::TCP)
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
  else if (net_protocol == Protocol::UDP)
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

  if (sockfd < 0) {
    PFATAL("Cannot create a socket");
  }

  //Set timeout for socket data sending/receiving -- otherwise it causes a big delay
  //if the server is still alive after processing all the requests
  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = socket_timeout_usecs;
  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

  struct sockaddr_in serv_addr, local_serv_addr;
  memset(&serv_addr, '0', sizeof(serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(net_port);
  serv_addr.sin_addr.s_addr = inet_addr(net_ip);

  //This piece of code is only used for targets that send responses to a specific port number
  //The Kamailio SIP server is an example. After running this code, the intialized sockfd 
  //will be bound to the given local port
  if(local_port > 0) {
    local_serv_addr.sin_family = AF_INET;
    local_serv_addr.sin_addr.s_addr = INADDR_ANY;
    local_serv_addr.sin_port = htons(local_port);

    local_serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(sockfd, (struct sockaddr*) &local_serv_addr, sizeof(struct sockaddr_in)))  {
      FATAL("Unable to bind socket on local source port");
    }
  }

  if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    //If it cannot connect to the server under test
    //try it again as the server initial startup time is varied
    size_t n;
    for (n = 0; n < 1000; n++) {
      if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) break;
      usleep(1000);
    }
    if (n == 1000) {
      close(sockfd);
      return false;
    }
  }

  if (net_recv(sockfd, timeout, poll_wait_msecs, response_buf)) {
    for (auto it = messages.cbegin(); it != messages.cend(); ++it) {
      const int n = net_send(sockfd, timeout, *it);
      message_sent++;

      // jump out if something wrong leading to incomplete message sent
      if (n != static_cast<int>(it->size())) break;
      
      auto const prev_response_buf_size = response_buf.size();
      if (!net_recv(sockfd, timeout, poll_wait_msecs, response_buf)) break;
      
      response_bytes.emplace_back(response_buf.size());

      if (response_buf.size() == prev_response_buf_size) likely_buggy = true;
      else likely_buggy = false;
    }
  }

  net_recv(sockfd, timeout, poll_wait_msecs, response_buf);
  if (message_sent > 0) {
    response_bytes.emplace_back(response_buf.size());
  }

  // wait a bit letting the server to complete its remaining tasks
  session_virgin_bits.fill(0xff);
  while (true) {
    if (has_new_bits(session_virgin_bits) != 2) break;
  }

  close(sockfd);

  if (likely_buggy && false_negative_reduction) return true;

  if (terminate_child && (child_pid > 0)) kill(child_pid, SIGTERM);

  //give the server a bit more time to gracefully terminate
  while(1) {
    int status = kill(child_pid, 0);
    if ((status != 0) && (errno == ESRCH)) break;
  }

  return true;
}

/* Get unix time in milliseconds */

static u64 get_cur_time(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}


/* Get unix time in microseconds */

[[maybe_unused]]
static u64 get_cur_time_us(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;
}

static void mark_as_redundant(queue_entry& q, bool favored) {
  if (q.favored == favored) return;

  q.fs_redundant = favored;

  TODO();
}

static void add_to_queue(std::string const& fname, size_t len, bool passed_det, u8 corpus_read_or_sync) {
  auto q = std::make_shared<queue_entry>();
  q->fname               = fname;
  q->len                 = len;
  q->depth               = cur_depth    + 1;
  q->passed_det          = passed_det;
  q->index               = queue.size() - 1;
  q->generating_state_id = target_state_id;

  max_depth = std::max(max_depth, q->depth);
  
  queue.emplace_front(q);
  
  // extract regions keeping client requests if needed
  if (corpus_read_or_sync) {
    FILE* fp = std::fopen(fname.c_str(), "rb");
    std::vector<u8> buf(len);
    const u32 bytes_read = std::fread(buf.data(), 1, len, fp);
    std::fclose(fp);
    if (bytes_read != len) PFATAL("AFLNet - Inconsistent file length '%s'", fname.c_str());
    q->regions = extract_requests(buf.data(), buf.size());

    if (corpus_read_or_sync == 1) {
      max_seed_region_count = std::max(max_seed_region_count, q->regions.size());
    }
  } else {
    q->regions = convert_messages_to_regions();
  }

  std::string region_fname;
  {
    std::stringstream ss;
    ss << out_dir << "/regions/" << basename(fname.c_str());
    region_fname = ss.str();
  }
  save_regions_to_file(region_fname, messages);

  last_path_time = get_cur_time();

  if (!was_fuzzed_map.empty()) {
    expand_was_fuzzed_map(0, 1);
  } else {
    expand_was_fuzzed_map(1, 1);
  }
}

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

static inline u8 has_new_bits(BitMap& virgin_map) {

#ifdef WORD_SIZE_64

  u64* current = (u64*)trace_bits;
  u64* virgin  = (u64*)virgin_map.data();

  u32  i = (MAP_SIZE >> 3);

#else

  u32* current = (u32*)trace_bits;
  u32* virgin  = (u32*)virgin_map.data();

  u32  i = (MAP_SIZE >> 2);

#endif /* ^WORD_SIZE_64 */

  u8   ret = 0;

  while (i--) {

    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */

    if (*current && (*current & *virgin)) [[unlikely]] {

      if (ret < 2) [[likely]] {

        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;

        /* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[]. */

#ifdef WORD_SIZE_64

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) ret = 2;
        else ret = 1;

#else

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff)) ret = 2;
        else ret = 1;

#endif /* ^WORD_SIZE_64 */

      }

      *virgin &= ~*current;

    }

    current++;
    virgin++;

  }

  if (ret && virgin_map == virgin_bits) bitmap_changed = true;

  return ret;

}

/* Count the number of bits set in the provided bitmap. Used for the status
   screen several times every second, does not have to be fast. */

[[maybe_unused]]
static u32 count_bits(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */

    if (v == 0xffffffff) {
      ret += 32;
      continue;
    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;

  }

  return ret;

}


#define FF(_b)  (0xff << ((_b) << 3))
#define UFF(_b)  (0xffu << ((_b) << 3))

/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */

[[maybe_unused]]
static u32 count_bytes(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (!v) continue;
    if (v & UFF(0)) ret++;
    if (v & UFF(1)) ret++;
    if (v & UFF(2)) ret++;
    if (v & UFF(3)) ret++;

  }

  return ret;

}


/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */

[[maybe_unused]]
static u32 count_non_255_bytes(u8* mem) {

  u32* ptr = (u32*)mem;
  u32  i   = (MAP_SIZE >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (v == 0xffffffff) continue;
    if ((v & UFF(0)) != UFF(0)) ret++;
    if ((v & UFF(1)) != UFF(1)) ret++;
    if ((v & UFF(2)) != UFF(2)) ret++;
    if ((v & UFF(3)) != UFF(3)) ret++;

  }

  return ret;

}


/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast. */

static std::array<u8, 256> simplify_lookup = [] {
    std::array<u8, 256> arr{};
    arr[0] = 1;
    std::fill(arr.begin() + 1, arr.end(), 128);
    return arr;
}();

#ifdef WORD_SIZE_64

static void simplify_trace(u64* mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u8* mem8 = (u8*)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];
      mem8[4] = simplify_lookup[mem8[4]];
      mem8[5] = simplify_lookup[mem8[5]];
      mem8[6] = simplify_lookup[mem8[6]];
      mem8[7] = simplify_lookup[mem8[7]];

    } else *mem = 0x0101010101010101ULL;

    mem++;

  }

}

#else

[[maybe_unused]]
static void simplify_trace(u32* mem) {

  u32 i = MAP_SIZE >> 2;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (*mem) [[unlikely]] {

      u8* mem8 = (u8*)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];

    } else *mem = 0x01010101;

    mem++;
  }

}

#endif /* ^WORD_SIZE_64 */


/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */
static const std::array<u8, 256> count_class_lookup8 = [] {
    std::array<u8, 256> arr{};

    arr[0] = 0;
    arr[1] = 1;
    arr[2] = 2;
    arr[3] = 4;
    
    std::fill(arr.begin() + 4, arr.begin() + 8, 8);
    std::fill(arr.begin() + 8, arr.begin() + 16, 16);
    std::fill(arr.begin() + 16, arr.begin() + 32, 32);
    std::fill(arr.begin() + 32, arr.begin() + 128, 64);
    std::fill(arr.begin() + 128, arr.end(), 128);

    return arr;
}();

static u16 count_class_lookup16[65536];


void init_count_class16(void) {

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++)
    for (b2 = 0; b2 < 256; b2++)
      count_class_lookup16[(b1 << 8) + b2] =
        (count_class_lookup8[b1] << 8) |
        count_class_lookup8[b2];

}


#ifdef WORD_SIZE_64

static inline void classify_counts(u64* mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];
      mem16[2] = count_class_lookup16[mem16[2]];
      mem16[3] = count_class_lookup16[mem16[3]];

    }

    mem++;

  }

}

#else

[[maybe_unused]]
static inline void classify_counts(u32* mem) {

  u32 i = MAP_SIZE >> 2;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (*mem) [[unlikely]] {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];

    }

    mem++;

  }

}

#endif /* ^WORD_SIZE_64 */


/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) {
  shmctl(shm_id, IPC_RMID, NULL);
}


/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */

static void minimize_bits(u8* dst, u8* src) {
  u32 i = 0;
  while (i < MAP_SIZE) {
    if (*(src++)) dst[i >> 3] |= 1 << (i & 7);
    i++;
  }
}

/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of top_rated[] entries
   for every byte in the bitmap. We win that slot if there is no previous
   contender, or if the contender has smaller unique state count or
   it has a more favorable speed x size factor. */
[[maybe_unused]]
static void update_bitmap_score(std::shared_ptr<queue_entry> q) {
  const u64 fav_factor = q->exec_us * q->len;
  
  for (size_t i = 0; i < MAP_SIZE; i++) {
    if (trace_bits[i] == 0 || top_rated[i] == nullptr) continue;
    
    queue_entry & rated_i = *(top_rated[i]);
    if (q->unique_state_count < rated_i.unique_state_count) continue;

    if (fav_factor > rated_i.exec_us * rated_i.len) continue;

    rated_i.trace_mini.clear();

    top_rated[i] = q;
    if (q->trace_mini.empty()) {
      q->trace_mini.resize(MAP_SIZE >> 3);
      minimize_bits(q->trace_mini.data(), trace_bits);
    }

    score_changed = true;
  }
}

/**
 * Iterate over queue, update top_rated array according to a bitmap.
 * Make all queue entries be favored.
 * If a queue entry is good enough, update pending_favored.
 */
[[maybe_unused]]
static void cull_queue() {
  if (dumb_mode || !score_changed) return;

  static constexpr auto MAP_MINI = MAP_SIZE >> 3;
  static std::array<u8, MAP_MINI> temp_v;

  score_changed = false;
  temp_v.fill(255);

  for (auto const& q_ref: queue) {
    queue_entry& q = *q_ref;
    if (q.is_initial_seed) {
      q.favored = false;
    }
  }

  for (size_t i = 0; i < MAP_SIZE; i++) {
    if (top_rated[i] != nullptr && (temp_v[i >> 3] & (1 << (i & 7)))) {
      queue_entry& qi = *top_rated[i];
      for (u32 j = MAP_SIZE >> 3; j > 0; j--) {

        if (qi.trace_mini[j])
          temp_v[j] &= ~qi.trace_mini[j];
      }

      qi.favored = true;
      queued_favored++;

      if ((qi.generating_state_id == target_state_id || qi.is_initial_seed) && 
        (was_fuzzed_map[get_state_index(target_state_id)][qi.index] == FuzzedState::ReachableNotFuzzed))
        pending_favored++;
    }
  }

  for (auto const& q_ref: queue) {
    mark_as_redundant(*q_ref, !q_ref->favored);
  }
}

[[maybe_unused]]
static void setup_shm(void) {
  if (!in_bitmap) virgin_bits.fill(255);

  virgin_tmout.fill(255);
  virgin_crash.fill(255);

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  if (shm_id < 0) PFATAL("shmget() failed");

  atexit(remove_shm);

  std::string shm_str;
  {
    std::stringstream ss;
    ss << shm_id;
    shm_str = ss.str();
  }

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

  if (!dumb_mode) setenv(SHM_ENV_VAR, shm_str.c_str(), 1);

  trace_bits = (u8*)shmat(shm_id, NULL, 0);

  if (!trace_bits) PFATAL("shmat() failed");

}

[[maybe_unused]]
static void setup_post() {
  TODO();
}

[[maybe_unused]]
static void read_testcases() {
  // auto-detect non-in-place resumption attempts.
  {
    std::string fn = alloc_printf("%s/queue", in_dir.c_str());
    if (!access(fn.c_str(), F_OK)) {
      in_dir = std::move(fn);
    }
  }

  namespace fs = std::filesystem;
  try {
    std::vector<std::string> files;
    for (const auto& entry : fs::directory_iterator(in_dir)) {
      if (fs::is_regular_file(entry)) {
        files.emplace_back(entry.path().filename().string());
      }
    }

    {
      std::random_device rd;
      std::mt19937 g(rd());
      std::shuffle(files.begin(), files.end(), g);
    }

    for (const auto& file : files) {
      auto fn = alloc_printf("%s/%s", in_dir, file.c_str());
      auto dfn = alloc_printf("%s/.state/deterministic_done/%s", in_dir, file.c_str());
      struct stat st;
      bool passed_det = false;

      if (lstat(fn.c_str(), &st) || access(fn.c_str(), R_OK))
        PFATAL("Unable to access '%s'", fn.c_str());

      if (!S_ISREG(st.st_mode) || !st.st_size) continue;

      if (static_cast<size_t>(st.st_size) > MAX_FILE) {
        FATAL("Test case '%s' is too big (%zd, limit is %zd)", fn.c_str(),
            st.st_size, MAX_FILE);

      }

      if (!access(dfn.c_str(), F_OK)) passed_det = true;
      
      add_to_queue(fn, st.st_size, passed_det, 1);
    }

  } catch (std::exception const& e) {
    PFATAL("Scan in_dir %s failed: %s", in_dir.c_str(), e.what());
  }

  if (queue.empty()) {
    SAYF("\n" cLRD "[-] " cRST
         "Looks like there are no valid test cases in the input directory! The fuzzer\n"
         "    needs one or more test case to start with - ideally, a small file under\n"
         "    1 kB or so. The cases must be stored as regular files directly in the\n"
         "    input directory.\n");

    FATAL("No usable test cases in '%s'", in_dir.c_str());
  }

  last_path_time = 0;
}

/*Move the current process to a new network namespace*/
[[maybe_unused]]
static void move_process_to_netns(std::string const& netns_name) {
  auto const netns_path = alloc_printf("/var/run/netns/%s", netns_name.c_str());
  if (netns_path.length() > 272) {
    PFATAL("Network namespace name \"%s\" is too long", netns_name.c_str());
  }

  const int netns_fd = open(netns_path.c_str(), O_RDONLY);
  if (netns_fd == -1) {
    PFATAL("Unable to open %s", netns_path.c_str());
  }
  
  if (setns(netns_fd, CLONE_NEWNET) == -1) {
    PFATAL("setns failed");
  }
}

/**
 * Spin up forkserver (instrumented mode only)
 */
[[maybe_unused]]
static void init_forkserver(int netns_id, char** argv) {
  int st_pipe[2], ctl_pipe[2];

  ACTF("Spinning up the fork server...");

  if (pipe(st_pipe) || pipe(ctl_pipe)) {
    PFATAL("pipe function failed");
  }

  forksrv_pid = fork();

  if (forksrv_pid < 0) PFATAL("fork() failed");

  if (!forksrv_pid) {
    
    struct rlimit r;

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... */
    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {
      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */
    }

    if (mem_limit) {
      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS
      setrlimit(RLIMIT_AS, &r); /* Ignore errors */
#else
      /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. */
      setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */
    }

    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. */
    r.rlim_max = r.rlim_cur = 0;
    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

    /* Move process to a different network namespace */
    move_process_to_netns(std::to_string(netns_id));

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */
    setsid();
    dup2(dev_null_fd, 1);
    dup2(dev_null_fd, 2);

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(dev_null_fd);

    /* This should improve performance a bit, since it stops the linker from
       doing extra work post-fork(). */

    if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);

    /* Set sane defaults for ASAN if nothing else specified. */

    setenv("ASAN_OPTIONS", "abort_on_error=1:"
                           "detect_leaks=0:"
                           "symbolize=0:"
                           "allocator_may_return_null=1", 0);

    /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
       point. So, we do this in a very hacky way. */

    setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                           "symbolize=0:"
                           "abort_on_error=1:"
                           "allocator_may_return_null=1:"
                           "msan_track_origins=0", 0);

    execv(target_path, argv);

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */

    *(u32*)trace_bits = EXEC_FAIL_SIG;
    exit(0);
  }

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv_st_fd = st_pipe[0];
  fsrv_ctl_fd = ctl_pipe[1];

  int status, rlen;
  {
    struct itimerval it;
    /* Wait for the fork server to come up, but don't wait too long. */

    it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
    it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

    setitimer(ITIMER_REAL, &it, NULL);

    rlen = read(fsrv_st_fd, &status, 4);

    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 0;

    setitimer(ITIMER_REAL, &it, NULL);
  }

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4) {
    OKF("All right - fork server is up.");
    return;
  }

  if (child_timed_out)
    FATAL("Timeout while initializing fork server (adjusting -t may help)");

  if (waitpid(forksrv_pid, &status, 0) <= 0)
    PFATAL("waitpid() failed");

  if (WIFSIGNALED(status)) {

    if (mem_limit && mem_limit < 500 && uses_asan) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! Since it seems to be built with ASAN and you have a\n"
           "    restrictive memory limit configured, this is expected; please read\n"
           "    %s/notes_for_asan.txt for help.\n", doc_path);

    } else if (!mem_limit) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
           "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
           "      break afl-fuzz performance optimizations when running platform-specific\n"
           "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

           "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
           "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

    } else {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The current memory limit (%s) is too restrictive, causing the\n"
           "      target to hit an OOM condition in the dynamic linker. Try bumping up\n"
           "      the limit with the -m setting in the command line. A simple way confirm\n"
           "      this diagnosis would be:\n\n"

#ifdef RLIMIT_AS
           "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
           "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

           "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
           "      estimate the required amount of virtual memory for the binary.\n\n"

           "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
           "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
           "      break afl-fuzz performance optimizations when running platform-specific\n"
           "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

           "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
           "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
           DMS(mem_limit << 20), mem_limit - 1);

    }

    FATAL("Fork server crashed with signal %d", WTERMSIG(status));

  }

  if (*(u32*)trace_bits == EXEC_FAIL_SIG)
    FATAL("Unable to execute target application ('%s')", argv[0]);

  if (mem_limit && mem_limit < 500 && uses_asan) {

    SAYF("\n" cLRD "[-] " cRST
           "Hmm, looks like the target binary terminated before we could complete a\n"
           "    handshake with the injected code. Since it seems to be built with ASAN and\n"
           "    you have a restrictive memory limit configured, this is expected; please\n"
           "    read %s/notes_for_asan.txt for help.\n", doc_path);

  } else if (!mem_limit) {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. Perhaps there is a horrible bug in the\n"
         "    fuzzer. Poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

  } else {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. There are %s probable explanations:\n\n"

         "%s"
         "    - The current memory limit (%s) is too restrictive, causing an OOM\n"
         "      fault in the dynamic linker. This can be fixed with the -m option. A\n"
         "      simple way to confirm the diagnosis may be:\n\n"

#ifdef RLIMIT_AS
         "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
         "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

         "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
         "      estimate the required amount of virtual memory for the binary.\n\n"

         "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
         "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
         getenv(DEFER_ENV_VAR) ? "three" : "two",
         getenv(DEFER_ENV_VAR) ?
         "    - You are using deferred forkserver, but __AFL_INIT() is never\n"
         "      reached before the program terminates.\n\n" : "",
         DMS(mem_limit << 20), mem_limit - 1);

  }

  FATAL("Fork server handshake failed");
}

int main() {
  setup_fnames();
  dev_null_fd = check_open("/dev/null", O_RDWR);
}

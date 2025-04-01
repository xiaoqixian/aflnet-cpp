// Date:   Fri Mar 28 11:23:32 AM 2025
// Mail:   lunar_ubuntu@qq.com
// Author: https://github.com/xiaoqixian

#pragma once

#include <bits/types/struct_timeval.h>
#include <list>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include "config.h"

struct region_t {
  int start_byte;                 /* The start byte, negative if unknown. */
  int end_byte;                   /* The last byte, negative if unknown. */
  char modifiable;                /* The modifiable flag. */
  std::vector<u32> state_seq;   /* The annotation keeping the state feedback. */
};

struct queue_entry {
  std::string fname; // File name for the test case

  bool cal_failed = false;   // Calibration failed?
  bool trim_done = false;    // Trimmed?
  bool was_fuzzed = false;   // Had any fuzzing done yet?
  bool passed_det = false;   // Deterministic stages passed?
  bool has_new_cov = false;  // Triggers new coverage?
  bool var_behavior = false; // Variable behavior?
  bool favored = false;      // Currently favored?
  bool fs_redundant = false; // Marked as redundant in the fs?

  u32 bitmap_size = 0; // Number of bits set in bitmap
  u32 exec_cksum = 0;  // Checksum of the execution trace
  u32 depth = 0;      // Path depth
  u32 len = 0;        // Input length

  u64 exec_us = 0;    // Execution time (us)
  u64 handicap = 0;   // Number of queue cycles behind

  std::vector<u8> trace_mini; // Trace bytes, if kept

  std::vector<region_t> regions; // Regions keeping information of message(s) sent to the server under test
  u32 index = 0;                 // Index of this queue entry in the whole queue
  u32 generating_state_id = 0;    // ID of the start at which the new seed was generated
  bool is_initial_seed = false;   // Is this an initial seed
  u32 unique_state_count = 0;     // Unique number of states traversed by this queue entry
};

struct state_info_t {
  u32 id;                     /* state id */
  bool is_covered;              /* has this state been covered */
  u32 paths;                  /* total number of paths exercising this state */
  u32 paths_discovered;       /* total number of new paths that have been discovered when this state is targeted/selected */
  u32 selected_times;         /* total number of times this state has been targeted/selected */
  u32 fuzzs;                  /* Total number of fuzzs (i.e., inputs generated) */
  u32 score;                  /* current score of the state */
  u32 selected_seed_index;    /* the recently selected seed index */
  std::vector<std::shared_ptr<queue_entry>> seeds;

  state_info_t():
    id(0), is_covered(false), paths(0), paths_discovered(0),
    selected_times(0), fuzzs(0), score(0), selected_seed_index(0)
  {}
};

enum class FuzzedState: u8 {
  Unreachable = 0,
  ReachableNotFuzzed,
  Fuzzed
};

std::string state_sequence_to_string(std::vector<u32> const& state_seq);

u32 save_messages_to_file(
  std::list<std::vector<u8>> const& messages,
  std::string const& fname,
  bool replay_enabled,
  u32 max_count
);

/**
 * return false for poll timeout or all data pending after poll has been
 * received successfully.
 */
bool net_recv(int sockfd, struct timeval timeout, int poll_w, std::vector<u8>& buf);
int net_send(int sockfd, struct timeval timeout, std::vector<u8> const& buf);

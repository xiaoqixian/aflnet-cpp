// Date:   Fri Mar 28 11:23:32 AM 2025
// Mail:   lunar_ubuntu@qq.com
// Author: https://github.com/xiaoqixian

#pragma once

#include <list>
#include <memory>
#include <string>
#include <vector>
#include "config.h"

struct region_t {
  int start_byte;                 /* The start byte, negative if unknown. */
  int end_byte;                   /* The last byte, negative if unknown. */
  char modifiable;                /* The modifiable flag. */
  std::vector<u32> state_seq;   /* The annotation keeping the state feedback. */
};

struct queue_entry {
  std::string fname;                  /* File name for the test case      */

  u8  cal_failed,                     /* Calibration failed?              */
      trim_done,                      /* Trimmed?                         */
      was_fuzzed,                     /* Had any fuzzing done yet?        */
      passed_det,                     /* Deterministic stages passed?     */
      has_new_cov,                    /* Triggers new coverage?           */
      var_behavior,                   /* Variable behavior?               */
      favored,                        /* Currently favored?               */
      fs_redundant;                   /* Marked as redundant in the fs?   */

  u32 bitmap_size,                    /* Number of bits set in bitmap     */
      exec_cksum;                     /* Checksum of the execution trace  */

  u64 exec_us,                        /* Execution time (us)              */
      handicap,                       /* Number of queue cycles behind    */
      depth;                          /* Path depth                       */

  std::vector<u8> trace_mini;         /* Trace bytes, if kept             */
  u32 tc_ref;                         /* Trace bytes ref count            */

  std::vector<region_t> regions;      /* Regions keeping information of message(s) sent to the server under test */
  u32 index;                          /* Index of this queue entry in the whole queue */
  u32 generating_state_id;            /* ID of the start at which the new seed was generated */
  bool is_initial_seed;                 /* Is this an initial seed */
  u32 unique_state_count;             /* Unique number of states traversed by this queue entry */
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

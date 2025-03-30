// Date:   Sat Mar 29 17:43:47 2025
// Mail:   lunar_ubuntu@qq.com
// Author: https://github.com/xiaoqixian

#include "aflnet.h"
#include <sstream>

std::string state_sequence_to_string(std::vector<u32> const& state_seq) {
  std::stringstream ss;

  for (size_t i = 0; i < state_seq.size(); i++) {
    if (i >= 2 && state_seq[i] == state_seq[i-1] && state_seq[i] == state_seq[i-1]) continue;
    
    auto const state_id = state_seq[i];
    ss << state_id;
    if (i != state_seq.size() - 1) {
      ss << '-';
    }

    if (ss.tellp() > 150 && i + 1 < state_seq.size()) {
      ss << "end-at-" << state_seq.back();
      break;
    }
  }
  return ss.str();
}

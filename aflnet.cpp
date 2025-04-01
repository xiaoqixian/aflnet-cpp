// Date:   Sat Mar 29 17:43:47 2025
// Mail:   lunar_ubuntu@qq.com
// Author: https://github.com/xiaoqixian

#include <cerrno>
#include <sstream>
#include <sys/poll.h>
#include <sys/socket.h>

#include "aflnet.h"

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

bool net_recv(int sockfd, struct timeval timeout, int poll_w, std::vector<u8>& buf) {
  struct pollfd pfd[1];
  pfd[0].fd = sockfd;
  pfd[0].events = POLLIN;
  const int res = poll(pfd, 1, poll_w);

  constexpr size_t BUF_SIZE = 1024;

  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

  if (res > 0) {
    if (pfd[0].revents & POLLIN) {
      int bytes_read = 0;
      do {
        const size_t orig_size = buf.size();
        buf.resize(orig_size + BUF_SIZE);
        u8* const write_pos = buf.data() + orig_size;
        bytes_read = recv(sockfd, write_pos, BUF_SIZE, 0);
        if (bytes_read < 0 && errno != EAGAIN) {
          buf.resize(orig_size);
          return false;
        }
        
        buf.resize(orig_size + bytes_read);
      } while (bytes_read > 0);
    }
  }
  else if (res < 0) return false;
  return true;
}

int net_send(int sockfd, struct timeval timeout, std::vector<u8> const& buf) {
  struct pollfd pfd[1];
  pfd[0].fd = sockfd;
  pfd[0].events = POLLOUT;
  const int res = poll(pfd, 1, 1);
  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

  size_t bytes_write = 0;
  if (res > 0) {
    if (pfd[0].revents & POLLOUT) {
      while (bytes_write < buf.size()) {
        int n = send(sockfd, buf.data() + bytes_write, buf.size() - bytes_write, MSG_NOSIGNAL);
        if (n == 0) return bytes_write;
        if (n == -1) return -1;
        bytes_write += n;
      }
    }
  }
  return bytes_write;
}

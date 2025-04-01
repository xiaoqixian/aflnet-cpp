// Date:   Mon Mar 31 09:21:53 AM 2025
// Mail:   lunar_ubuntu@qq.com
// Author: https://github.com/xiaoqixian

#include <array>
#include <cassert>
#include <cstddef>
#include <utility>

template <typename T, size_t N>
class stack_vec {
  std::array<T, N> arr_;
  size_t size_ { 0 };
public:
  template <typename U>
  constexpr void emplace_back(U&& elem) {
    assert(size_ < N);
    arr_[size_++] = std::forward<U>(elem);
  }
  
  constexpr T& operator[](size_t index) {
    assert(index < size_);
    return arr_[index];
  }
  
  constexpr T const& operator[](size_t index) const {
    assert(index < size_);
    return arr_[index];
  }

  constexpr size_t size() const {
    return size_;
  }
};

#define likely(_x)   __builtin_expect(!!(_x), 1)
#define unlikely(_x)  __builtin_expect(!!(_x), 0)

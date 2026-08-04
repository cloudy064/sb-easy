#pragma once

#include <functional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace sbeasy::test {

using Test = std::pair<std::string, std::function<void()>>;

std::vector<Test>& registry();

class Registration final {
  public:
    Registration(std::string name, std::function<void()> function);
};

inline void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

template <typename Exception, typename Function>
void require_throws(Function&& function, const char* message) {
    try {
        std::forward<Function>(function)();
    } catch (const Exception&) {
        return;
    }
    throw std::runtime_error(message);
}

} // namespace sbeasy::test

#define SB_EASY_TEST_CONCAT_INNER(left, right) left##right
#define SB_EASY_TEST_CONCAT(left, right) SB_EASY_TEST_CONCAT_INNER(left, right)
#define SB_EASY_TEST(name)                                                             \
    static void SB_EASY_TEST_CONCAT(test_, __LINE__)();                                \
    static const ::sbeasy::test::Registration SB_EASY_TEST_CONCAT(                     \
        registration_, __LINE__){name, SB_EASY_TEST_CONCAT(test_, __LINE__)};          \
    static void SB_EASY_TEST_CONCAT(test_, __LINE__)()

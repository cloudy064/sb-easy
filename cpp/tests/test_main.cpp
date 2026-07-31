#include "test_support.hpp"

#include <exception>
#include <iostream>

namespace sbeasy::test {

std::vector<Test>& registry() {
    static std::vector<Test> tests;
    return tests;
}

Registration::Registration(std::string name, std::function<void()> function) {
    registry().emplace_back(std::move(name), std::move(function));
}

} // namespace sbeasy::test

int main() {
    int failures = 0;
    for (const auto& [name, test] : sbeasy::test::registry()) {
        try {
            test();
            std::cout << "[pass] " << name << '\n';
        } catch (const std::exception& error) {
            ++failures;
            std::cerr << "[fail] " << name << ": " << error.what() << '\n';
        }
    }
    return failures == 0 ? 0 : 1;
}

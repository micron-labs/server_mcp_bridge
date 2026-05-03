// Minimal in-process test framework. We don't pull in Catch2/gtest so the
// test build has no extra deps beyond what mcp_bridge_core already needs.
#pragma once
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace mcp_test {

struct Case {
    const char* name;
    void (*fn)();
};

inline std::vector<Case>& cases() { static std::vector<Case> v; return v; }

struct Registrar {
    Registrar(const char* n, void (*f)()) { cases().push_back({n, f}); }
};

struct AssertionFailure : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

template <typename A, typename B>
inline std::string fmt_eq(const char* file, int line,
                          const char* a_expr, const char* b_expr,
                          const A& a, const B& b) {
    std::ostringstream o;
    o << file << ":" << line << "\n      expected: " << a_expr << " == " << b_expr
      << "\n           lhs: " << a
      << "\n           rhs: " << b;
    return o.str();
}

}

#define TEST(name)                                                                \
    static void test_##name();                                                    \
    static ::mcp_test::Registrar reg_##name(#name, test_##name);                  \
    static void test_##name()

#define ASSERT(cond)                                                              \
    do {                                                                          \
        if (!(cond)) {                                                            \
            throw ::mcp_test::AssertionFailure(                                   \
                std::string(__FILE__) + ":" + std::to_string(__LINE__) +          \
                "\n      assert(" #cond ") failed");                              \
        }                                                                         \
    } while (0)

#define ASSERT_EQ(a, b)                                                           \
    do {                                                                          \
        auto&& _av = (a); auto&& _bv = (b);                                       \
        if (!(_av == _bv)) {                                                      \
            throw ::mcp_test::AssertionFailure(                                   \
                ::mcp_test::fmt_eq(__FILE__, __LINE__, #a, #b, _av, _bv));        \
        }                                                                         \
    } while (0)

#define ASSERT_THROWS(expr)                                                       \
    do {                                                                          \
        bool _threw = false;                                                      \
        try { (void)(expr); } catch (...) { _threw = true; }                      \
        if (!_threw) {                                                            \
            throw ::mcp_test::AssertionFailure(                                   \
                std::string(__FILE__) + ":" + std::to_string(__LINE__) +          \
                "\n      expected " #expr " to throw");                           \
        }                                                                         \
    } while (0)

inline int main_run_all() {
    int failed = 0;
    auto& cs = ::mcp_test::cases();
    for (auto& c : cs) {
        std::cerr << "[ RUN  ] " << c.name << "\n";
        try {
            c.fn();
            std::cerr << "[  OK  ] " << c.name << "\n";
        } catch (const std::exception& e) {
            std::cerr << "[ FAIL ] " << c.name << "\n      " << e.what() << "\n";
            ++failed;
        }
    }
    std::cerr << "\n" << (cs.size() - static_cast<std::size_t>(failed))
              << " passed, " << failed << " failed of " << cs.size() << "\n";
    return failed == 0 ? 0 : 1;
}

#define TEST_MAIN int main() { return main_run_all(); }

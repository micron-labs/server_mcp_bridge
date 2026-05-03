#pragma once
#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

class RateLimiter {
public:
    explicit RateLimiter(int max_requests_per_minute = 60);
    bool allow(const std::string& key);

private:
    int max_rpm_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> requests_;
    std::chrono::steady_clock::time_point last_gc_;
};

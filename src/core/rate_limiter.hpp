#pragma once
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <chrono>

class RateLimiter {
public:
    explicit RateLimiter(int max_requests_per_minute = 60);
    bool allow(const std::string& ip);

private:
    int max_rpm_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> requests_;
};

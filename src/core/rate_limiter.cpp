#include "core/rate_limiter.hpp"
#include <algorithm>

RateLimiter::RateLimiter(int max_requests_per_minute)
    : max_rpm_(max_requests_per_minute) {}

bool RateLimiter::allow(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    auto window = now - std::chrono::minutes(1);

    auto& timestamps = requests_[ip];
    // Remove entries older than 1 minute
    timestamps.erase(
        std::remove_if(timestamps.begin(), timestamps.end(),
            [&window](const auto& t) { return t < window; }),
        timestamps.end()
    );

    if (static_cast<int>(timestamps.size()) >= max_rpm_) {
        return false;
    }
    timestamps.push_back(now);
    return true;
}

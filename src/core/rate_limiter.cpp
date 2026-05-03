#include "core/rate_limiter.hpp"
#include <algorithm>

RateLimiter::RateLimiter(int max_requests_per_minute)
    : max_rpm_(max_requests_per_minute), last_gc_(std::chrono::steady_clock::now()) {}

bool RateLimiter::allow(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    auto window = now - std::chrono::minutes(1);

    auto& timestamps = requests_[key];
    timestamps.erase(
        std::remove_if(timestamps.begin(), timestamps.end(),
            [&window](const auto& t) { return t < window; }),
        timestamps.end());

    bool ok = static_cast<int>(timestamps.size()) < max_rpm_;
    if (ok) timestamps.push_back(now);

    // Periodic GC: drop buckets idle for more than 5 minutes so the map
    // doesn't grow unboundedly when many keys are seen once.
    if (now - last_gc_ > std::chrono::minutes(5)) {
        auto stale = now - std::chrono::minutes(5);
        for (auto it = requests_.begin(); it != requests_.end();) {
            if (it->second.empty() || it->second.back() < stale) {
                it = requests_.erase(it);
            } else {
                ++it;
            }
        }
        last_gc_ = now;
    }

    return ok;
}

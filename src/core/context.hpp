#pragma once
#include <json.hpp>
#include <string>
#include <mutex>

using json = nlohmann::json;

class Context {
public:
    explicit Context(const std::string& path = "context.json");
    json get() const;
    void set(const std::string& key, const json& value);
    void save();

private:
    void load();
    std::string path_;
    json data_;
    mutable std::mutex mutex_;
};

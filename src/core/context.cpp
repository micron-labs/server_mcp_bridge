#include "core/context.hpp"
#include <fstream>
#include <spdlog/spdlog.h>

Context::Context(const std::string& path) : path_(path) {
    load();
}

void Context::load() {
    std::ifstream file(path_);
    if (file.is_open()) {
        try {
            file >> data_;
        } catch (...) {
            data_ = json::object();
        }
    } else {
        data_ = json::object();
    }
}

json Context::get() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return data_;
}

void Context::set(const std::string& key, const json& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    data_[key] = value;
    save();
}

void Context::save() {
    std::ofstream file(path_);
    if (file.is_open()) {
        file << data_.dump(2);
    } else {
        spdlog::warn("Could not save context to {}", path_);
    }
}

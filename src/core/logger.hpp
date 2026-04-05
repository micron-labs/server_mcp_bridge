#pragma once
#include <string>
#include <spdlog/spdlog.h>

void init_logger(const std::string& log_file, const std::string& log_level);

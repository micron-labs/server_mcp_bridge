#include "core/logger.hpp"
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <filesystem>
#include <iostream>

void init_logger(const std::string& log_file, const std::string& log_level) {
    try {
        // Ensure log directory exists
        auto log_dir = std::filesystem::path(log_file).parent_path();
        if (!log_dir.empty()) {
            std::filesystem::create_directories(log_dir);
        }

        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            log_file, 5 * 1024 * 1024, 3);

        auto logger = std::make_shared<spdlog::logger>("mcp",
            spdlog::sinks_init_list{console_sink, file_sink});

        logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");

        if (log_level == "debug") logger->set_level(spdlog::level::debug);
        else if (log_level == "warn") logger->set_level(spdlog::level::warn);
        else if (log_level == "error") logger->set_level(spdlog::level::err);
        else logger->set_level(spdlog::level::info);

        spdlog::set_default_logger(logger);
        spdlog::info("Logger initialized (level: {})", log_level);
    } catch (const std::exception& e) {
        std::cerr << "[logger] Failed to initialize: " << e.what() << "\n";
        // Fall back to console-only
        auto console = spdlog::stdout_color_mt("mcp");
        spdlog::set_default_logger(console);
    }
}

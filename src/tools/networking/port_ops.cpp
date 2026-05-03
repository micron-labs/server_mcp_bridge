#include "tools/networking/port_ops.hpp"
#include "registry/tool_registry.hpp"
#include "platform/platform.hpp"
#include <json.hpp>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <atomic>
#include <spdlog/spdlog.h>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#endif

using json = nlohmann::json;

struct ManagedListener {
    int port;
    std::string protocol;
    std::string response;
    std::atomic<bool> running{true};
    std::thread thread;
    int socket_fd = -1;
};

static std::mutex listeners_mutex;
static std::unordered_map<int, std::unique_ptr<ManagedListener>> listeners;

static void tcp_listener_thread(ManagedListener* l) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return;
    l->socket_fd = server_fd;

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(static_cast<uint16_t>(l->port));

    if (bind(server_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(server_fd);
        return;
    }
    listen(server_fd, 5);

    while (l->running) {
        // Use select with timeout so we can check running flag
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(server_fd, &fds);
        struct timeval tv{1, 0};
        if (select(server_fd + 1, &fds, nullptr, nullptr, &tv) > 0) {
            int client = accept(server_fd, nullptr, nullptr);
            if (client >= 0) {
                if (!l->response.empty()) {
                    send(client, l->response.c_str(), l->response.size(), 0);
                }
                close(client);
            }
        }
    }
    close(server_fd);
}

void register_port_tools() {
    auto& reg = ToolRegistry::instance();

    reg.register_tool("list_listening_ports", {
        "", "Show all listening ports on the system",
        {}, {},
        [](const RequestContext&, const json&) -> json {
            return {{"output", list_listening_ports_raw()}};
        }
    });

    reg.register_tool("check_port", {
        "", "Check if a specific port is open/in-use",
        {"port"}, {"host"},
        [](const RequestContext&, const json& args) -> json {
            int port = args["port"];
            std::string host = args.value("host", "localhost");
            bool open = check_port(port, host);
            return {{"port", port}, {"host", host}, {"open", open}};
        }
    });

    reg.register_tool("start_listener", {
        "", "Start a simple TCP listening service on a port",
        {"port"}, {"protocol", "response"},
        [](const RequestContext&, const json& args) -> json {
            int port = args["port"];
            std::string proto = args.value("protocol", "tcp");
            std::string response = args.value("response", "OK\n");

            std::lock_guard<std::mutex> lock(listeners_mutex);
            if (listeners.count(port)) {
                throw std::runtime_error("Port " + std::to_string(port) + " already has a listener");
            }

            auto l = std::make_unique<ManagedListener>();
            l->port = port;
            l->protocol = proto;
            l->response = response;
            auto* ptr = l.get();
            l->thread = std::thread(tcp_listener_thread, ptr);
            l->thread.detach();
            listeners[port] = std::move(l);

            spdlog::info("Started listener on port {}", port);
            return {{"port", port}, {"protocol", proto}, {"started", true}};
        }
    });

    reg.register_tool("stop_listener", {
        "", "Stop a managed listener",
        {"port"}, {},
        [](const RequestContext&, const json& args) -> json {
            int port = args["port"];
            std::lock_guard<std::mutex> lock(listeners_mutex);
            auto it = listeners.find(port);
            if (it == listeners.end()) {
                throw std::runtime_error("No listener on port " + std::to_string(port));
            }
            it->second->running = false;
            if (it->second->socket_fd >= 0) {
                close(it->second->socket_fd);
            }
            listeners.erase(it);
            spdlog::info("Stopped listener on port {}", port);
            return {{"port", port}, {"stopped", true}};
        }
    });

    reg.register_tool("list_listeners", {
        "", "List all active managed listeners",
        {}, {},
        [](const RequestContext&, const json&) -> json {
            std::lock_guard<std::mutex> lock(listeners_mutex);
            json result = json::array();
            for (const auto& [port, l] : listeners) {
                result.push_back({
                    {"port", port},
                    {"protocol", l->protocol},
                    {"running", l->running.load()}
                });
            }
            return result;
        }
    });
}

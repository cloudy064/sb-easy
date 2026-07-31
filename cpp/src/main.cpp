#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

#include "sbeasy/config_renderer.hpp"
#include "sbeasy/store.hpp"

namespace {

[[nodiscard]] sbeasy::RenderRequest parse_request(const nlohmann::json& value) {
    sbeasy::RenderRequest request;
    request.mode = value.value("mode", "managed") == "full"
                       ? sbeasy::ProfileMode::full
                       : sbeasy::ProfileMode::managed;
    request.profile = value.at("profile");
    request.nodes = value.value("nodes", std::vector<sbeasy::ProxyNode>{});
    request.host_context = value.value("host", nlohmann::json::object());
    request.external_route_tags =
        value.value("external_route_tags", std::vector<std::string>{});
    if (value.contains("rule_script") && value["rule_script"].is_string()) {
        request.rule_script = value["rule_script"].get<std::string>();
    }
    if (value.contains("clash") && value["clash"].is_object()) {
        request.clash_controller = value["clash"].value("controller", "");
        request.clash_secret = value["clash"].value("secret", "");
    }
    return request;
}

void usage(const char* executable) {
    std::cerr << "Usage:\n  " << executable << " render <request.json>\n  "
              << executable << " migrate <database.db> <migration-directory>\n  "
              << executable
              << " render-host <database.db> <host-id> <migration-directory>\n  "
              << executable << " --version\n";
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string{argv[1]} == "--version") {
            std::cout << "sb-easy-cpp 0.1.0\n";
            return 0;
        }

        if (argc == 3 && std::string{argv[1]} == "render") {
            std::ifstream input{argv[2]};
            if (!input) {
                throw std::runtime_error(std::string{"cannot open request file: "} +
                                         argv[2]);
            }

            nlohmann::json value;
            input >> value;
            const sbeasy::ConfigRenderer renderer;
            std::cout << renderer.render(parse_request(value)).dump(2) << '\n';
            return 0;
        }

        if (argc == 4 && std::string{argv[1]} == "migrate") {
            sbeasy::Database database{argv[2]};
            database.migrate(argv[3]);
            std::cout << "applied migrations: " << database.applied_migration_count()
                      << '\n';
            return 0;
        }

        if (argc == 5 && std::string{argv[1]} == "render-host") {
            const sbeasy::Store store{argv[2], argv[4]};
            const sbeasy::ConfigRenderer renderer;
            std::cout << renderer.render(store.render_request_for_host(argv[3])).dump(2)
                      << '\n';
            return 0;
        }

        usage(argv[0]);
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}

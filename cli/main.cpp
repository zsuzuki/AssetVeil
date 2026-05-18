#include "assetveil/assetveil.hpp"

#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace {

void print_usage()
{
    std::cerr
        << "Usage:\n"
        << "  assetveil encode <input> <output> --key <key>\n"
        << "  assetveil decode <input.av> <output> --key <key>\n"
        << "  assetveil pack <input_dir> <output.avp> --key <key>\n"
        << "  assetveil unpack <input.avp> <output_dir> --key <key>\n"
        << "  assetveil list <input.avp> [--key <key>]\n";
}

std::string read_key(int argc, char** argv)
{
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == "--key") {
            return argv[i + 1];
        }
    }
    return {};
}

bool has_key_flag(int argc, char** argv)
{
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--key") {
            return true;
        }
    }
    return false;
}

int finish(const assetveil::Result& result)
{
    if (result.ok()) {
        return 0;
    }
    std::cerr << "assetveil: " << result.error() << '\n';
    return 1;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc < 2) {
        print_usage();
        return 1;
    }

    const std::string command = argv[1];
    const std::string key = read_key(argc, argv);

    if (command == "encode") {
        if (argc < 6 || !has_key_flag(argc, argv) || key.empty()) {
            print_usage();
            return 1;
        }
        return finish(assetveil::encode_file(argv[2], argv[3], key));
    }

    if (command == "decode") {
        if (argc < 6 || !has_key_flag(argc, argv) || key.empty()) {
            print_usage();
            return 1;
        }
        return finish(assetveil::decode_file(argv[2], argv[3], key));
    }

    if (command == "pack") {
        if (argc < 6 || !has_key_flag(argc, argv) || key.empty()) {
            print_usage();
            return 1;
        }
        return finish(assetveil::pack_directory(argv[2], argv[3], key));
    }

    if (command == "unpack") {
        if (argc < 6 || !has_key_flag(argc, argv) || key.empty()) {
            print_usage();
            return 1;
        }
        return finish(assetveil::unpack_file(argv[2], argv[3], key));
    }

    if (command == "list") {
        if (argc < 3) {
            print_usage();
            return 1;
        }
        assetveil::PackReader reader(argv[2], key);
        if (!reader.ok()) {
            std::cerr << "assetveil: " << reader.error() << '\n';
            return 1;
        }
        for (const auto& entry : reader.entries()) {
            std::cout << entry.path << '\t' << entry.original_size << " bytes\n";
        }
        return 0;
    }

    print_usage();
    return 1;
}

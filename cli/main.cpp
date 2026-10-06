#include "assetveil/assetveil.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

namespace {

void print_usage()
{
    std::cerr
        << "Usage:\n"
        << "  assetveil encode <input> <output> --key-file <file>\n"
        << "  assetveil decode <input.av> <output> --key-file <file>\n"
        << "  assetveil pack <input_dir> <output.avp> --key-file <file>\n"
        << "  assetveil unpack <input.avp> <output_dir> --key-file <file>\n"
        << "  assetveil list <input.avp> --key-file <file>\n"
        << "  --key <key> is also supported; prefer --key-file to avoid exposing secrets in arguments.\n";
}

struct Secret {
    std::string value;
    ~Secret() { assetveil::secure_clear(value); }
};

bool read_key(const std::string& flag, const char* argument, Secret& key)
{
    if (flag == "--key") {
        key.value = argument;
    } else if (flag == "--key-file") {
        std::ifstream file(argument, std::ios::binary);
        if (!file) {
            std::cerr << "assetveil: failed to open key file\n";
            return false;
        }
        // Exact bytes, including any newline; matches the string_view library API.
        key.value.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
        if (file.bad()) {
            std::cerr << "assetveil: failed to read key file\n";
            return false;
        }
    } else {
        print_usage();
        return false;
    }
    if (key.value.empty()) {
        std::cerr << "assetveil: key must not be empty\n";
        return false;
    }
    return true;
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
    const bool list = command == "list";
    if ((!list && command != "encode" && command != "decode" && command != "pack" && command != "unpack") ||
        argc != (list ? 5 : 6)) {
        print_usage();
        return 1;
    }
    Secret key;
    const int flag_index = list ? 3 : 4;
    if (!read_key(argv[flag_index], argv[flag_index + 1], key)) {
        return 1;
    }
    if (command == "encode") {
        return finish(assetveil::encode_file(argv[2], argv[3], key.value));
    }
    if (command == "decode") {
        return finish(assetveil::decode_file(argv[2], argv[3], key.value));
    }
    if (command == "pack") {
        return finish(assetveil::pack_directory(argv[2], argv[3], key.value));
    }
    if (command == "unpack") {
        return finish(assetveil::unpack_file(argv[2], argv[3], key.value));
    }
    assetveil::PackReader reader(argv[2], key.value);
    if (!reader.ok()) {
        std::cerr << "assetveil: " << reader.error() << '\n';
        return 1;
    }
    for (const auto& entry : reader.entries()) {
        std::cout << entry.path << '\t' << entry.original_size << " bytes\n";
    }
    return 0;
}

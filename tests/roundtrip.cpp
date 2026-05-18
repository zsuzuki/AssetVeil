#include "assetveil/assetveil.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>

namespace {

bool write_text(const std::filesystem::path& path, const std::string& text)
{
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    out << text;
    return static_cast<bool>(out);
}

std::string read_text(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

bool require(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << message << '\n';
    }
    return condition;
}

} // namespace

int main()
{
    const auto root = std::filesystem::temp_directory_path() / "assetveil_roundtrip";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    const auto plain = root / "plain.txt";
    const auto encoded = root / "plain.txt.av";
    const auto decoded = root / "decoded.txt";
    constexpr auto key = "test-key";

    if (!require(write_text(plain, "hello asset veil\n"), "failed to write fixture")) {
        return 1;
    }

    auto result = assetveil::encode_file(plain, encoded, key);
    if (!require(result.ok(), result.error().c_str())) {
        return 1;
    }

    result = assetveil::decode_file(encoded, decoded, key);
    if (!require(result.ok(), result.error().c_str())) {
        return 1;
    }

    if (!require(read_text(decoded) == "hello asset veil\n", "decoded file did not match")) {
        return 1;
    }

    const auto assets = root / "assets";
    if (!require(write_text(assets / "textures" / "player.txt", "player texture bytes"), "failed to write asset 1") ||
        !require(write_text(assets / "audio" / "click.txt", "click audio bytes"), "failed to write asset 2")) {
        return 1;
    }

    const auto pack = root / "assets.avp";
    const auto unpacked = root / "unpacked";
    result = assetveil::pack_directory(assets, pack, key);
    if (!require(result.ok(), result.error().c_str())) {
        return 1;
    }

    assetveil::PackReader reader(pack, key);
    if (!require(reader.ok(), reader.error().c_str())) {
        return 1;
    }
    if (!require(reader.entries().size() == 2, "pack entry count did not match")) {
        return 1;
    }

    auto entry = reader.read("textures/player.txt");
    if (!require(entry.ok(), entry.error().c_str())) {
        return 1;
    }
    if (!require(std::string(entry.data().begin(), entry.data().end()) == "player texture bytes", "pack read did not match")) {
        return 1;
    }

    result = assetveil::unpack_file(pack, unpacked, key);
    if (!require(result.ok(), result.error().c_str())) {
        return 1;
    }
    if (!require(read_text(unpacked / "audio" / "click.txt") == "click audio bytes", "unpacked file did not match")) {
        return 1;
    }

    return 0;
}

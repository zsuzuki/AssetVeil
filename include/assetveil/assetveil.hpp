#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace assetveil {

using ByteVector = std::vector<std::uint8_t>;

struct Error {
    std::string message;
};

class Result {
public:
    Result() = default;
    explicit Result(Error error);

    [[nodiscard]] bool ok() const;
    [[nodiscard]] const std::string& error() const;

private:
    std::string error_;
};

class DataResult {
public:
    explicit DataResult(ByteVector data);
    explicit DataResult(Error error);

    [[nodiscard]] bool ok() const;
    [[nodiscard]] const std::string& error() const;
    [[nodiscard]] const ByteVector& data() const;
    [[nodiscard]] ByteVector&& take_data();

private:
    ByteVector data_;
    std::string error_;
};

struct PackEntry {
    std::string path;
    std::uint64_t original_size = 0;
    std::uint64_t stored_size = 0;
    std::uint64_t checksum = 0;
};

class PackReader {
public:
    PackReader(const std::filesystem::path& pack_path, std::string key);

    [[nodiscard]] bool ok() const;
    [[nodiscard]] const std::string& error() const;
    [[nodiscard]] const std::vector<PackEntry>& entries() const;
    [[nodiscard]] DataResult read(std::string_view virtual_path) const;
    [[nodiscard]] Result extract_all(const std::filesystem::path& output_dir) const;

private:
    std::filesystem::path pack_path_;
    std::string key_;
    std::vector<PackEntry> entries_;
    std::vector<std::uint64_t> data_offsets_;
    std::string error_;
};

[[nodiscard]] ByteVector obfuscate_bytes(const ByteVector& input, std::string_view key, std::uint64_t nonce);
[[nodiscard]] ByteVector deobfuscate_bytes(const ByteVector& input, std::string_view key, std::uint64_t nonce);

[[nodiscard]] Result encode_file(const std::filesystem::path& input_path,
                                 const std::filesystem::path& output_path,
                                 std::string_view key);

[[nodiscard]] Result decode_file(const std::filesystem::path& input_path,
                                 const std::filesystem::path& output_path,
                                 std::string_view key);

[[nodiscard]] Result pack_directory(const std::filesystem::path& input_dir,
                                    const std::filesystem::path& output_pack,
                                    std::string_view key);

[[nodiscard]] Result unpack_file(const std::filesystem::path& input_pack,
                                  const std::filesystem::path& output_dir,
                                  std::string_view key);

[[nodiscard]] DataResult read_encoded_file(const std::filesystem::path& input_path, std::string_view key);

} // namespace assetveil

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace assetveil {

using ByteVector = std::vector<std::uint8_t>;

namespace detail {

constexpr std::uint8_t key_mask(std::size_t index, std::uint64_t seed)
{
    auto value = seed + (index + 1u) * 0x9e3779b97f4a7c15ull;
    value ^= value >> 30;
    value *= 0xbf58476d1ce4e5b9ull;
    value ^= value >> 27;
    value *= 0x94d049bb133111ebull;
    value ^= value >> 31;
    return static_cast<std::uint8_t>(value & 0xffu);
}

} // namespace detail

void secure_clear(std::string& value);

class Key {
public:
    explicit Key(std::string_view plain);

    [[nodiscard]] std::string reveal() const;
    [[nodiscard]] std::size_t size() const;

private:
    std::vector<std::uint8_t> bytes_;
    std::uint64_t seed_ = 0;
};

template <std::size_t N>
class KeyGen {
public:
    constexpr explicit KeyGen(const char (&plain)[N])
        : seed_(0xa9f4d38c72b51e6dull ^ (N * 0x517cc1b727220a95ull))
    {
        for (std::size_t i = 0; i < N; ++i) {
            bytes_[i] = static_cast<std::uint8_t>(plain[i]) ^ detail::key_mask(i, seed_);
        }
    }

    [[nodiscard]] std::string reveal() const
    {
        std::string plain;
        plain.resize(size());
        for (std::size_t i = 0; i < size(); ++i) {
            plain[i] = static_cast<char>(bytes_[i] ^ detail::key_mask(i, seed_));
        }
        return plain;
    }

    [[nodiscard]] Key runtime_key() const
    {
        auto plain = reveal();
        Key key(plain);
        secure_clear(plain);
        return key;
    }

    [[nodiscard]] constexpr std::size_t size() const
    {
        return N == 0 ? 0 : N - 1;
    }

private:
    std::array<std::uint8_t, N> bytes_{};
    std::uint64_t seed_;
};

template <std::size_t N>
KeyGen(const char (&)[N]) -> KeyGen<N>;

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
    PackReader(const std::filesystem::path& pack_path, Key key);

    template <std::size_t N>
    PackReader(const std::filesystem::path& pack_path, const KeyGen<N>& key)
        : PackReader(pack_path, key.runtime_key())
    {
    }

    [[nodiscard]] bool ok() const;
    [[nodiscard]] const std::string& error() const;
    [[nodiscard]] const std::vector<PackEntry>& entries() const;
    [[nodiscard]] DataResult read(std::string_view virtual_path) const;
    [[nodiscard]] Result extract_all(const std::filesystem::path& output_dir) const;

private:
    std::filesystem::path pack_path_;
    Key key_;
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

[[nodiscard]] Result encode_file(const std::filesystem::path& input_path,
                                 const std::filesystem::path& output_path,
                                 const Key& key);

[[nodiscard]] Result decode_file(const std::filesystem::path& input_path,
                                 const std::filesystem::path& output_path,
                                 const Key& key);

[[nodiscard]] Result pack_directory(const std::filesystem::path& input_dir,
                                    const std::filesystem::path& output_pack,
                                    const Key& key);

[[nodiscard]] Result unpack_file(const std::filesystem::path& input_pack,
                                  const std::filesystem::path& output_dir,
                                  const Key& key);

[[nodiscard]] DataResult read_encoded_file(const std::filesystem::path& input_path, const Key& key);

template <std::size_t N>
[[nodiscard]] Result encode_file(const std::filesystem::path& input_path,
                                 const std::filesystem::path& output_path,
                                 const KeyGen<N>& key)
{
    return encode_file(input_path, output_path, key.runtime_key());
}

template <std::size_t N>
[[nodiscard]] Result decode_file(const std::filesystem::path& input_path,
                                 const std::filesystem::path& output_path,
                                 const KeyGen<N>& key)
{
    return decode_file(input_path, output_path, key.runtime_key());
}

template <std::size_t N>
[[nodiscard]] Result pack_directory(const std::filesystem::path& input_dir,
                                    const std::filesystem::path& output_pack,
                                    const KeyGen<N>& key)
{
    return pack_directory(input_dir, output_pack, key.runtime_key());
}

template <std::size_t N>
[[nodiscard]] Result unpack_file(const std::filesystem::path& input_pack,
                                  const std::filesystem::path& output_dir,
                                  const KeyGen<N>& key)
{
    return unpack_file(input_pack, output_dir, key.runtime_key());
}

template <std::size_t N>
[[nodiscard]] DataResult read_encoded_file(const std::filesystem::path& input_path, const KeyGen<N>& key)
{
    return read_encoded_file(input_path, key.runtime_key());
}

} // namespace assetveil

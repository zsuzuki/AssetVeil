#include "assetveil/assetveil.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <iterator>
#include <limits>
#include <type_traits>
#include <unordered_map>

namespace assetveil {
namespace {

constexpr std::array<std::uint8_t, 8> kFileMagic = {'A', 'V', 'E', 'I', 'L', '0', '1', '\0'};
constexpr std::array<std::uint8_t, 8> kPackMagic = {'A', 'V', 'P', 'A', 'C', 'K', '1', '\0'};
constexpr std::uint32_t kFormatVersion = 1;

struct EncodedHeader {
    std::uint64_t nonce = 0;
    std::uint64_t original_size = 0;
    std::uint64_t checksum = 0;
};

struct InternalPackEntry {
    PackEntry public_entry;
    std::uint64_t nonce = 0;
    std::uint64_t offset = 0;
};

std::uint64_t fnv1a64(const std::uint8_t* data, std::size_t size, std::uint64_t seed = 14695981039346656037ull)
{
    std::uint64_t hash = seed;
    for (std::size_t i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

std::uint64_t hash_string(std::string_view value, std::uint64_t seed)
{
    return fnv1a64(reinterpret_cast<const std::uint8_t*>(value.data()), value.size(), seed);
}

std::uint64_t splitmix64(std::uint64_t& state)
{
    std::uint64_t z = (state += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

std::uint64_t make_nonce(std::string_view key, std::string_view salt, std::uint64_t size)
{
    std::uint64_t seed = hash_string(key, 14695981039346656037ull);
    seed = hash_string(salt, seed);
    seed ^= size + 0x517cc1b727220a95ull;
    return splitmix64(seed);
}

ByteVector transform_bytes(const ByteVector& input, std::string_view key, std::uint64_t nonce)
{
    ByteVector output = input;
    std::uint64_t state = hash_string(key, nonce ^ 0xd6e8feb86659fd93ull);
    state ^= nonce + 0x9e3779b97f4a7c15ull;

    std::uint64_t block = 0;
    int remaining = 0;

    for (std::size_t i = 0; i < output.size(); ++i) {
        if (remaining == 0) {
            block = splitmix64(state);
            remaining = 8;
        }
        const auto mask = static_cast<std::uint8_t>(block & 0xffu);
        block >>= 8;
        --remaining;
        output[i] ^= static_cast<std::uint8_t>(mask + static_cast<std::uint8_t>(i * 131u));
    }

    return output;
}

Result make_error(std::string message)
{
    return Result(Error{std::move(message)});
}

DataResult make_data_error(std::string message)
{
    return DataResult(Error{std::move(message)});
}

ByteVector read_all(const std::filesystem::path& path, std::string& error)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        error = "failed to open input: " + path.string();
        return {};
    }
    return ByteVector(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
}

Result write_all(const std::filesystem::path& path, const ByteVector& data)
{
    if (path.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec) {
            return make_error("failed to create output directory: " + ec.message());
        }
    }

    std::ofstream file(path, std::ios::binary);
    if (!file) {
        return make_error("failed to open output: " + path.string());
    }
    file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!file) {
        return make_error("failed to write output: " + path.string());
    }
    return Result();
}

template <typename T>
void append_le(ByteVector& out, T value)
{
    static_assert(std::is_unsigned<T>::value, "append_le requires unsigned integer types");
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        out.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xffu));
    }
}

template <typename T>
bool read_le(const ByteVector& data, std::size_t& offset, T& value)
{
    static_assert(std::is_unsigned<T>::value, "read_le requires unsigned integer types");
    if (offset + sizeof(T) > data.size()) {
        return false;
    }
    value = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        value |= static_cast<T>(data[offset + i]) << (i * 8);
    }
    offset += sizeof(T);
    return true;
}

void append_bytes(ByteVector& out, const void* data, std::size_t size)
{
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    out.insert(out.end(), bytes, bytes + size);
}

bool read_bytes(const ByteVector& data, std::size_t& offset, void* out, std::size_t size)
{
    if (offset + size > data.size()) {
        return false;
    }
    std::copy(data.begin() + static_cast<std::ptrdiff_t>(offset),
              data.begin() + static_cast<std::ptrdiff_t>(offset + size),
              static_cast<std::uint8_t*>(out));
    offset += size;
    return true;
}

ByteVector encode_blob(const ByteVector& plain, std::string_view key, std::uint64_t nonce)
{
    ByteVector output;
    output.reserve(kFileMagic.size() + 4 + 8 + 8 + 8 + plain.size());
    append_bytes(output, kFileMagic.data(), kFileMagic.size());
    append_le<std::uint32_t>(output, kFormatVersion);
    append_le<std::uint64_t>(output, nonce);
    append_le<std::uint64_t>(output, static_cast<std::uint64_t>(plain.size()));
    append_le<std::uint64_t>(output, fnv1a64(plain.data(), plain.size()));
    auto obfuscated = transform_bytes(plain, key, nonce);
    output.insert(output.end(), obfuscated.begin(), obfuscated.end());
    return output;
}

DataResult decode_blob(const ByteVector& encoded, std::string_view key)
{
    std::size_t offset = 0;
    std::array<std::uint8_t, 8> magic{};
    if (!read_bytes(encoded, offset, magic.data(), magic.size()) || magic != kFileMagic) {
        return make_data_error("invalid AssetVeil file magic");
    }

    std::uint32_t version = 0;
    EncodedHeader header;
    if (!read_le(encoded, offset, version) ||
        !read_le(encoded, offset, header.nonce) ||
        !read_le(encoded, offset, header.original_size) ||
        !read_le(encoded, offset, header.checksum)) {
        return make_data_error("truncated AssetVeil header");
    }

    if (version != kFormatVersion) {
        return make_data_error("unsupported AssetVeil format version");
    }

    const std::uint64_t remaining = static_cast<std::uint64_t>(encoded.size() - offset);
    if (remaining != header.original_size) {
        return make_data_error("encoded payload size does not match header");
    }

    ByteVector payload(encoded.begin() + static_cast<std::ptrdiff_t>(offset), encoded.end());
    auto plain = transform_bytes(payload, key, header.nonce);
    if (fnv1a64(plain.data(), plain.size()) != header.checksum) {
        return make_data_error("checksum mismatch; wrong key or corrupted data");
    }
    return DataResult(std::move(plain));
}

std::string normalize_pack_path(const std::filesystem::path& root, const std::filesystem::path& path)
{
    auto relative = std::filesystem::relative(path, root).generic_string();
    while (!relative.empty() && relative.front() == '/') {
        relative.erase(relative.begin());
    }
    return relative;
}

bool is_safe_pack_path(const std::string& path)
{
    if (path.empty() || path.front() == '/') {
        return false;
    }

    const std::filesystem::path fs_path(path);
    for (const auto& part : fs_path) {
        if (part == "..") {
            return false;
        }
    }
    return true;
}

std::vector<std::filesystem::path> list_regular_files(const std::filesystem::path& root, std::string& error)
{
    std::vector<std::filesystem::path> files;
    std::error_code ec;
    if (!std::filesystem::is_directory(root, ec)) {
        error = "input is not a directory: " + root.string();
        return files;
    }

    for (const auto& entry : std::filesystem::recursive_directory_iterator(root, ec)) {
        if (ec) {
            error = "failed to scan directory: " + ec.message();
            return {};
        }
        if (entry.is_regular_file()) {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());
    return files;
}

DataResult read_pack_bytes(const std::filesystem::path& pack_path)
{
    std::string error;
    auto data = read_all(pack_path, error);
    if (!error.empty()) {
        return make_data_error(error);
    }
    return DataResult(std::move(data));
}

std::vector<InternalPackEntry> parse_pack_entries(const ByteVector& pack_data, std::string& error)
{
    std::size_t offset = 0;
    std::array<std::uint8_t, 8> magic{};
    if (!read_bytes(pack_data, offset, magic.data(), magic.size()) || magic != kPackMagic) {
        error = "invalid AssetVeil pack magic";
        return {};
    }

    std::uint32_t version = 0;
    std::uint32_t count = 0;
    if (!read_le(pack_data, offset, version) || !read_le(pack_data, offset, count)) {
        error = "truncated AssetVeil pack header";
        return {};
    }
    if (version != kFormatVersion) {
        error = "unsupported AssetVeil pack version";
        return {};
    }

    std::vector<InternalPackEntry> entries;
    entries.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint32_t path_size = 0;
        InternalPackEntry entry;
        if (!read_le(pack_data, offset, path_size) ||
            !read_le(pack_data, offset, entry.public_entry.original_size) ||
            !read_le(pack_data, offset, entry.public_entry.stored_size) ||
            !read_le(pack_data, offset, entry.public_entry.checksum) ||
            !read_le(pack_data, offset, entry.nonce)) {
            error = "truncated AssetVeil pack entry table";
            return {};
        }
        if (offset + path_size > pack_data.size()) {
            error = "truncated AssetVeil pack entry path";
            return {};
        }
        entry.public_entry.path.assign(reinterpret_cast<const char*>(pack_data.data() + offset), path_size);
        offset += path_size;
        if (!is_safe_pack_path(entry.public_entry.path)) {
            error = "unsafe AssetVeil pack entry path: " + entry.public_entry.path;
            return {};
        }
        entries.push_back(std::move(entry));
    }

    for (auto& entry : entries) {
        entry.offset = static_cast<std::uint64_t>(offset);
        if (entry.public_entry.stored_size > pack_data.size() - offset) {
            error = "truncated AssetVeil pack payload";
            return {};
        }
        offset += static_cast<std::size_t>(entry.public_entry.stored_size);
    }

    return entries;
}

} // namespace

Result::Result(Error error) : error_(std::move(error.message)) {}

bool Result::ok() const { return error_.empty(); }

const std::string& Result::error() const { return error_; }

DataResult::DataResult(ByteVector data) : data_(std::move(data)) {}

DataResult::DataResult(Error error) : error_(std::move(error.message)) {}

bool DataResult::ok() const { return error_.empty(); }

const std::string& DataResult::error() const { return error_; }

const ByteVector& DataResult::data() const { return data_; }

ByteVector&& DataResult::take_data() { return std::move(data_); }

PackReader::PackReader(const std::filesystem::path& pack_path, std::string key)
    : pack_path_(pack_path), key_(std::move(key))
{
    const auto data_result = read_pack_bytes(pack_path_);
    if (!data_result.ok()) {
        error_ = data_result.error();
        return;
    }

    std::string parse_error;
    auto internal_entries = parse_pack_entries(data_result.data(), parse_error);
    if (!parse_error.empty()) {
        error_ = parse_error;
        return;
    }

    entries_.reserve(internal_entries.size());
    data_offsets_.reserve(internal_entries.size());
    for (const auto& entry : internal_entries) {
        entries_.push_back(entry.public_entry);
        data_offsets_.push_back(entry.offset);
    }
}

bool PackReader::ok() const { return error_.empty(); }

const std::string& PackReader::error() const { return error_; }

const std::vector<PackEntry>& PackReader::entries() const { return entries_; }

DataResult PackReader::read(std::string_view virtual_path) const
{
    if (!ok()) {
        return make_data_error(error_);
    }

    const auto data_result = read_pack_bytes(pack_path_);
    if (!data_result.ok()) {
        return data_result;
    }
    const auto& pack_data = data_result.data();

    std::string parse_error;
    const auto internal_entries = parse_pack_entries(pack_data, parse_error);
    if (!parse_error.empty()) {
        return make_data_error(parse_error);
    }

    const auto it = std::find_if(internal_entries.begin(), internal_entries.end(), [&](const InternalPackEntry& entry) {
        return entry.public_entry.path == virtual_path;
    });
    if (it == internal_entries.end()) {
        return make_data_error("entry not found: " + std::string(virtual_path));
    }

    const auto begin = pack_data.begin() + static_cast<std::ptrdiff_t>(it->offset);
    const auto end = begin + static_cast<std::ptrdiff_t>(it->public_entry.stored_size);
    ByteVector payload(begin, end);
    auto plain = transform_bytes(payload, key_, it->nonce);
    if (fnv1a64(plain.data(), plain.size()) != it->public_entry.checksum) {
        return make_data_error("checksum mismatch; wrong key or corrupted pack entry: " + it->public_entry.path);
    }
    return DataResult(std::move(plain));
}

Result PackReader::extract_all(const std::filesystem::path& output_dir) const
{
    for (const auto& entry : entries_) {
        auto data = read(entry.path);
        if (!data.ok()) {
            return make_error(data.error());
        }
        auto result = write_all(output_dir / std::filesystem::path(entry.path), data.data());
        if (!result.ok()) {
            return result;
        }
    }
    return Result();
}

ByteVector obfuscate_bytes(const ByteVector& input, std::string_view key, std::uint64_t nonce)
{
    return transform_bytes(input, key, nonce);
}

ByteVector deobfuscate_bytes(const ByteVector& input, std::string_view key, std::uint64_t nonce)
{
    return transform_bytes(input, key, nonce);
}

Result encode_file(const std::filesystem::path& input_path,
                   const std::filesystem::path& output_path,
                   std::string_view key)
{
    std::string error;
    const auto plain = read_all(input_path, error);
    if (!error.empty()) {
        return make_error(error);
    }
    const auto nonce = make_nonce(key, input_path.generic_string(), plain.size());
    return write_all(output_path, encode_blob(plain, key, nonce));
}

DataResult read_encoded_file(const std::filesystem::path& input_path, std::string_view key)
{
    std::string error;
    const auto encoded = read_all(input_path, error);
    if (!error.empty()) {
        return make_data_error(error);
    }
    return decode_blob(encoded, key);
}

Result decode_file(const std::filesystem::path& input_path,
                   const std::filesystem::path& output_path,
                   std::string_view key)
{
    auto decoded = read_encoded_file(input_path, key);
    if (!decoded.ok()) {
        return make_error(decoded.error());
    }
    return write_all(output_path, decoded.data());
}

Result pack_directory(const std::filesystem::path& input_dir,
                      const std::filesystem::path& output_pack,
                      std::string_view key)
{
    std::string error;
    const auto files = list_regular_files(input_dir, error);
    if (!error.empty()) {
        return make_error(error);
    }

    struct PendingEntry {
        InternalPackEntry entry;
        ByteVector payload;
    };
    std::vector<PendingEntry> pending;
    pending.reserve(files.size());

    for (const auto& file : files) {
        auto plain = read_all(file, error);
        if (!error.empty()) {
            return make_error(error);
        }

        PendingEntry pending_entry;
        pending_entry.entry.public_entry.path = normalize_pack_path(input_dir, file);
        pending_entry.entry.public_entry.original_size = static_cast<std::uint64_t>(plain.size());
        pending_entry.entry.public_entry.stored_size = static_cast<std::uint64_t>(plain.size());
        pending_entry.entry.public_entry.checksum = fnv1a64(plain.data(), plain.size());
        pending_entry.entry.nonce = make_nonce(key, pending_entry.entry.public_entry.path, plain.size());
        pending_entry.payload = transform_bytes(plain, key, pending_entry.entry.nonce);
        pending.push_back(std::move(pending_entry));
    }

    ByteVector output;
    append_bytes(output, kPackMagic.data(), kPackMagic.size());
    append_le<std::uint32_t>(output, kFormatVersion);
    append_le<std::uint32_t>(output, static_cast<std::uint32_t>(pending.size()));

    for (const auto& item : pending) {
        const auto& path = item.entry.public_entry.path;
        if (path.size() > std::numeric_limits<std::uint32_t>::max()) {
            return make_error("pack entry path is too long: " + path);
        }
        append_le<std::uint32_t>(output, static_cast<std::uint32_t>(path.size()));
        append_le<std::uint64_t>(output, item.entry.public_entry.original_size);
        append_le<std::uint64_t>(output, item.entry.public_entry.stored_size);
        append_le<std::uint64_t>(output, item.entry.public_entry.checksum);
        append_le<std::uint64_t>(output, item.entry.nonce);
        append_bytes(output, path.data(), path.size());
    }

    for (const auto& item : pending) {
        output.insert(output.end(), item.payload.begin(), item.payload.end());
    }

    return write_all(output_pack, output);
}

Result unpack_file(const std::filesystem::path& input_pack,
                   const std::filesystem::path& output_dir,
                   std::string_view key)
{
    PackReader reader(input_pack, std::string(key));
    if (!reader.ok()) {
        return make_error(reader.error());
    }
    return reader.extract_all(output_dir);
}

} // namespace assetveil

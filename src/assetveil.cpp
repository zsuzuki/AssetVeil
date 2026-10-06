#include "assetveil/assetveil.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <type_traits>
#include <unordered_set>

namespace assetveil {
namespace {

constexpr std::array<std::uint8_t, 8> kFileMagic = {'A', 'V', 'E', 'I', 'L', '0', '2', '\0'};
constexpr std::array<std::uint8_t, 8> kPackMagic = {'A', 'V', 'P', 'A', 'C', 'K', '2', '\0'};
constexpr std::array<std::uint8_t, 8> kLegacyFileMagic = {'A', 'V', 'E', 'I', 'L', '0', '1', '\0'};
constexpr std::array<std::uint8_t, 8> kLegacyPackMagic = {'A', 'V', 'P', 'A', 'C', 'K', '1', '\0'};
constexpr std::uint32_t kFormatVersion = 2;
constexpr std::size_t kTagSize = crypto_aead_xchacha20poly1305_ietf_ABYTES;
constexpr std::size_t kFileHeaderSize = 44;
constexpr std::size_t kPackHeaderSize = 48;
constexpr std::size_t kEntryFixedSize = 44;
using Nonce = std::array<std::uint8_t, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>;
using Digest = std::array<std::uint8_t, crypto_generichash_BYTES>;
static_assert(Nonce{}.size() == 24 && Digest{}.size() == 32 && kTagSize == 16);

struct CryptoKey {
    std::array<std::uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> bytes{};
    ~CryptoKey() { sodium_memzero(bytes.data(), bytes.size()); }
    CryptoKey() = default;
    CryptoKey(const CryptoKey&) = delete;
    CryptoKey& operator=(const CryptoKey&) = delete;
};

struct RevealedKey {
    std::string value;
    ~RevealedKey() { secure_clear(value); }
};

struct InternalPackEntry {
    PackEntry public_entry;
    Nonce nonce{};
    std::uint64_t offset = 0;
};

struct Manifest {
    std::vector<InternalPackEntry> entries;
    Digest digest{};
};

Result make_error(std::string message) { return Result(Error{std::move(message)}); }
DataResult make_data_error(std::string message) { return DataResult(Error{std::move(message)}); }

bool derive_key(std::string_view input, CryptoKey& key, std::string& error)
{
    if (input.empty()) {
        error = "AssetVeil key must not be empty";
        return false;
    }
    static const int initialized = sodium_init();
    if (initialized < 0) {
        error = "failed to initialize libsodium";
        return false;
    }
    // Fast mapping of an application secret to 32 bytes, NOT password hardening.
    constexpr unsigned char domain[] = "AssetVeil-v2-key";
    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, key.bytes.size());
    crypto_generichash_update(&state, domain, sizeof(domain));
    crypto_generichash_update(&state, reinterpret_cast<const unsigned char*>(input.data()), input.size());
    crypto_generichash_final(&state, key.bytes.data(), key.bytes.size());
    sodium_memzero(&state, sizeof(state));
    return true;
}

Nonce random_nonce()
{
    Nonce nonce{};
    randombytes_buf(nonce.data(), nonce.size());
    return nonce;
}

template <typename T>
void append_le(ByteVector& out, T value)
{
    static_assert(std::is_unsigned<T>::value, "append_le requires unsigned integers");
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        out.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xffu));
    }
}

template <typename T>
bool read_le(const ByteVector& data, std::size_t& offset, T& value)
{
    static_assert(std::is_unsigned<T>::value, "read_le requires unsigned integers");
    if (offset > data.size() || sizeof(T) > data.size() - offset) {
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
    if (size != 0) {
        const auto* bytes = static_cast<const std::uint8_t*>(data);
        out.insert(out.end(), bytes, bytes + size);
    }
}

bool read_bytes(const ByteVector& data, std::size_t& offset, void* out, std::size_t size)
{
    if (offset > data.size() || size > data.size() - offset) {
        return false;
    }
    std::copy_n(data.data() + offset, size, static_cast<std::uint8_t*>(out));
    offset += size;
    return true;
}

bool stream_size(std::ifstream& file, std::uint64_t& size)
{
    file.seekg(0, std::ios::end);
    const auto end = file.tellg();
    if (end < 0) {
        return false;
    }
    size = static_cast<std::uint64_t>(end);
    file.seekg(0);
    return static_cast<bool>(file);
}

bool read_exact(std::ifstream& file, ByteVector& data, std::uint64_t size)
{
    if (size > data.max_size() || size > static_cast<std::uint64_t>(std::numeric_limits<std::streamsize>::max())) {
        return false;
    }
    data.resize(static_cast<std::size_t>(size));
    if (size != 0) {
        file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size));
    }
    return static_cast<bool>(file);
}

ByteVector read_all(const std::filesystem::path& path, std::string& error)
{
    std::ifstream file(path, std::ios::binary);
    std::uint64_t size = 0;
    ByteVector data;
    if (!file || !stream_size(file, size) || !read_exact(file, data, size)) {
        error = "failed to read input: " + path.string();
        return {};
    }
    return data;
}

Result write_all(const std::filesystem::path& path, const ByteVector& data)
{
    if (data.size() > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
        return make_error("output is too large");
    }
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
    if (!data.empty()) {
        file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
    file.close();
    if (!file) {
        return make_error("failed to write output: " + path.string());
    }
    return Result();
}

DataResult encrypt_payload(const ByteVector& plain, const CryptoKey& key, const Nonce& nonce,
                           const std::uint8_t* ad, std::size_t ad_size)
{
    ByteVector cipher;
    if (plain.size() > cipher.max_size() - kTagSize ||
        plain.size() > crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX) {
        return make_data_error("asset is too large to encrypt");
    }
    cipher.resize(plain.size() + kTagSize);
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(cipher.data(), nullptr, plain.data(), plain.size(),
                                                 ad, ad_size, nullptr, nonce.data(), key.bytes.data()) != 0) {
        return make_data_error("asset encryption failed");
    }
    return DataResult(std::move(cipher));
}

DataResult decrypt_payload(const ByteVector& cipher, const CryptoKey& key, const Nonce& nonce,
                           const std::uint8_t* ad, std::size_t ad_size)
{
    if (cipher.size() < kTagSize) {
        return make_data_error("truncated authentication tag");
    }
    ByteVector plain(cipher.size() - kTagSize);
    std::uint8_t empty = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plain.empty() ? &empty : plain.data(), nullptr, nullptr,
                                                 cipher.data(), cipher.size(), ad, ad_size,
                                                 nonce.data(), key.bytes.data()) != 0) {
        sodium_memzero(plain.data(), plain.size());
        return make_data_error("authentication failed; wrong key or corrupted data");
    }
    return DataResult(std::move(plain));
}

bool is_safe_pack_path(const std::string& path)
{
    // Validate the portable format on every OS, including Windows drive/UNC paths.
    if (path.empty() || path.front() == '/' || path.find_first_of("\\:<>\"|?*") != std::string::npos ||
        path.find('\0') != std::string::npos) {
        return false;
    }
    std::size_t begin = 0;
    while (begin < path.size()) {
        const auto end = path.find('/', begin);
        const auto part = path.substr(begin, end == std::string::npos ? end : end - begin);
        if (part.empty() || part == "." || part == ".." || part.back() == '.' || part.back() == ' ') {
            return false;
        }
        auto base = part.substr(0, part.find('.'));
        for (auto& ch : base) {
            if (ch >= 'a' && ch <= 'z') {
                ch = static_cast<char>(ch - 'a' + 'A');
            }
        }
        if (base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" ||
            (base.size() == 4 && (base.substr(0, 3) == "COM" || base.substr(0, 3) == "LPT") &&
             base[3] >= '1' && base[3] <= '9')) {
            return false;
        }
        if (end == std::string::npos) {
            return true;
        }
        begin = end + 1;
    }
    return false;
}

bool check_extract_path(const std::filesystem::path& path, std::string& error)
{
    std::filesystem::path current;
    for (const auto& part : path) {
        current /= part;
        std::error_code ec;
        const auto status = std::filesystem::symlink_status(current, ec);
        if (ec && ec != std::errc::no_such_file_or_directory) {
            error = "failed to inspect extraction path: " + current.string();
            return false;
        }
        if (std::filesystem::is_symlink(status)) {
            error = "refusing to extract through a symlink: " + current.string();
            return false;
        }
        if (std::filesystem::exists(status) &&
            !(current == path ? std::filesystem::is_regular_file(status) : std::filesystem::is_directory(status))) {
            error = "invalid extraction destination: " + current.string();
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
        return {};
    }
    std::filesystem::recursive_directory_iterator it(root, ec), end;
    while (!ec && it != end) {
        const auto status = it->symlink_status(ec);
        if (ec) {
            break;
        }
        if (std::filesystem::is_symlink(status)) {
            error = "refusing to pack a symlink: " + it->path().string();
            return {};
        }
        if (std::filesystem::is_regular_file(status)) {
            files.push_back(it->path());
        }
        it.increment(ec);
    }
    if (ec) {
        error = "failed to scan directory: " + ec.message();
        return {};
    }
    std::sort(files.begin(), files.end());
    return files;
}

Manifest read_manifest(std::ifstream& file, const CryptoKey& key, std::string& error)
{
    Manifest result;
    std::uint64_t file_size = 0;
    ByteVector manifest;
    if (!stream_size(file, file_size) || file_size < 8 || !read_exact(file, manifest, 8)) {
        error = "truncated AssetVeil pack header";
        return {};
    }
    if (std::equal(kLegacyPackMagic.begin(), kLegacyPackMagic.end(), manifest.begin())) {
        error = "insecure AssetVeil v1 pack is unsupported; repack from original assets";
        return {};
    }
    if (!std::equal(kPackMagic.begin(), kPackMagic.end(), manifest.begin())) {
        error = "invalid AssetVeil pack magic";
        return {};
    }
    file.seekg(0);
    if (file_size < kPackHeaderSize + kTagSize || !read_exact(file, manifest, kPackHeaderSize)) {
        error = "truncated AssetVeil pack header";
        return {};
    }
    std::size_t offset = 8;
    std::uint32_t version = 0, count = 0;
    std::uint64_t table_size = 0;
    Nonce nonce{};
    read_le(manifest, offset, version);
    read_le(manifest, offset, count);
    read_le(manifest, offset, table_size);
    read_bytes(manifest, offset, nonce.data(), nonce.size());
    if (version != kFormatVersion) {
        error = "unsupported AssetVeil pack version";
        return {};
    }
    if (table_size > file_size - kPackHeaderSize - kTagSize ||
        table_size > manifest.max_size() - kPackHeaderSize) {
        error = "invalid AssetVeil pack table size";
        return {};
    }
    ByteVector table, tag;
    if (!read_exact(file, table, table_size) || !read_exact(file, tag, kTagSize)) {
        error = "truncated AssetVeil pack table";
        return {};
    }
    append_bytes(manifest, table.data(), table.size());
    auto authenticated = decrypt_payload(tag, key, nonce, manifest.data(), manifest.size());
    if (!authenticated.ok()) {
        error = "pack manifest " + authenticated.error();
        return {};
    }
    // Only authenticated, bounded metadata may control allocations and file offsets.
    if (count > table.size() / (kEntryFixedSize + 1)) {
        error = "invalid AssetVeil pack entry count";
        return {};
    }
    result.entries.reserve(count);
    std::unordered_set<std::string> paths;
    offset = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint32_t path_size = 0;
        InternalPackEntry entry;
        if (!read_le(table, offset, path_size) ||
            !read_le(table, offset, entry.public_entry.original_size) ||
            !read_le(table, offset, entry.public_entry.stored_size) ||
            !read_bytes(table, offset, entry.nonce.data(), entry.nonce.size()) ||
            path_size > table.size() - offset) {
            error = "truncated AssetVeil pack entry table";
            return {};
        }
        entry.public_entry.path.assign(reinterpret_cast<const char*>(table.data() + offset), path_size);
        offset += path_size;
        if (!is_safe_pack_path(entry.public_entry.path) || !paths.insert(entry.public_entry.path).second) {
            error = "unsafe or duplicate AssetVeil pack entry path";
            return {};
        }
        if (entry.public_entry.stored_size < kTagSize ||
            entry.public_entry.stored_size - kTagSize != entry.public_entry.original_size) {
            error = "invalid AssetVeil pack entry size";
            return {};
        }
        result.entries.push_back(std::move(entry));
    }
    if (offset != table.size()) {
        error = "unexpected data in AssetVeil pack table";
        return {};
    }
    std::uint64_t payload_offset = manifest.size() + kTagSize;
    for (auto& entry : result.entries) {
        entry.offset = payload_offset;
        if (entry.public_entry.stored_size > file_size - payload_offset) {
            error = "truncated AssetVeil pack payload";
            return {};
        }
        payload_offset += entry.public_entry.stored_size;
    }
    if (payload_offset != file_size) {
        error = "unexpected trailing data in AssetVeil pack";
        return {};
    }
    crypto_generichash(result.digest.data(), result.digest.size(), manifest.data(), manifest.size(), nullptr, 0);
    return result;
}

} // namespace

Result::Result(Error error) : error_(std::move(error.message)) {}
bool Result::ok() const { return error_.empty(); }
const std::string& Result::error() const { return error_; }

void secure_clear(std::string& value)
{
    if (!value.empty()) {
        sodium_memzero(&value[0], value.size());
    }
    value.clear();
}

Key::Key(std::string_view plain)
{
    // This mask only obscures the in-memory representation; it is not encryption.
    seed_ = 0xa9f4d38c72b51e6dull ^ (plain.size() * 0x517cc1b727220a95ull);
    bytes_.resize(plain.size());
    for (std::size_t i = 0; i < plain.size(); ++i) {
        bytes_[i] = static_cast<std::uint8_t>(plain[i]) ^ detail::key_mask(i, seed_);
    }
}

std::string Key::reveal() const
{
    std::string plain(bytes_.size(), '\0');
    for (std::size_t i = 0; i < bytes_.size(); ++i) {
        plain[i] = static_cast<char>(bytes_[i] ^ detail::key_mask(i, seed_));
    }
    return plain;
}
std::size_t Key::size() const { return bytes_.size(); }

DataResult::DataResult(ByteVector data) : data_(std::move(data)) {}
DataResult::DataResult(Error error) : error_(std::move(error.message)) {}
bool DataResult::ok() const { return error_.empty(); }
const std::string& DataResult::error() const { return error_; }
const ByteVector& DataResult::data() const { return data_; }
ByteVector&& DataResult::take_data() { return std::move(data_); }

DataResult encrypt_bytes(const ByteVector& input, std::string_view key)
{
    CryptoKey crypto_key;
    std::string error;
    if (!derive_key(key, crypto_key, error)) {
        return make_data_error(error);
    }
    const auto nonce = random_nonce();
    ByteVector output;
    output.reserve(kFileHeaderSize);
    append_bytes(output, kFileMagic.data(), kFileMagic.size());
    append_le<std::uint32_t>(output, kFormatVersion);
    append_bytes(output, nonce.data(), nonce.size());
    append_le<std::uint64_t>(output, input.size());
    auto cipher = encrypt_payload(input, crypto_key, nonce, output.data(), output.size());
    if (!cipher.ok()) {
        return cipher;
    }
    if (cipher.data().size() > output.max_size() - output.size()) {
        return make_data_error("encoded asset is too large");
    }
    append_bytes(output, cipher.data().data(), cipher.data().size());
    return DataResult(std::move(output));
}

DataResult decrypt_bytes(const ByteVector& input, std::string_view key)
{
    CryptoKey crypto_key;
    std::string error;
    if (!derive_key(key, crypto_key, error)) {
        return make_data_error(error);
    }
    std::size_t offset = 0;
    std::array<std::uint8_t, 8> magic{};
    if (!read_bytes(input, offset, magic.data(), magic.size())) {
        return make_data_error("truncated AssetVeil header");
    }
    if (magic == kLegacyFileMagic) {
        return make_data_error("insecure AssetVeil v1 file is unsupported; encode from original assets");
    }
    if (magic != kFileMagic) {
        return make_data_error("invalid AssetVeil file magic");
    }
    std::uint32_t version = 0;
    std::uint64_t size = 0;
    Nonce nonce{};
    if (!read_le(input, offset, version) || !read_bytes(input, offset, nonce.data(), nonce.size()) ||
        !read_le(input, offset, size) || input.size() - offset < kTagSize) {
        return make_data_error("truncated AssetVeil header or tag");
    }
    if (version != kFormatVersion) {
        return make_data_error("unsupported AssetVeil format version");
    }
    if (size != input.size() - offset - kTagSize) {
        return make_data_error("encoded payload size does not match header");
    }
    ByteVector cipher(input.begin() + static_cast<std::ptrdiff_t>(offset), input.end());
    return decrypt_payload(cipher, crypto_key, nonce, input.data(), offset);
}

PackReader::PackReader(const std::filesystem::path& pack_path, std::string key)
    : PackReader(pack_path, Key(key))
{
    secure_clear(key);
}

PackReader::PackReader(const std::filesystem::path& pack_path, Key key)
    : pack_path_(pack_path), key_(std::move(key))
{
    CryptoKey crypto_key;
    RevealedKey plain_key{key_.reveal()};
    if (!derive_key(plain_key.value, crypto_key, error_)) {
        return;
    }
    std::ifstream file(pack_path_, std::ios::binary);
    if (!file) {
        error_ = "failed to open pack: " + pack_path_.string();
        return;
    }
    auto manifest = read_manifest(file, crypto_key, error_);
    if (!error_.empty()) {
        return;
    }
    manifest_digest_ = manifest.digest;
    for (auto& entry : manifest.entries) {
        entries_.push_back(std::move(entry.public_entry));
        data_offsets_.push_back(entry.offset);
        nonces_.push_back(entry.nonce);
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
    const auto it = std::find_if(entries_.begin(), entries_.end(), [&](const PackEntry& entry) {
        return entry.path == virtual_path;
    });
    if (it == entries_.end()) {
        return make_data_error("entry not found: " + std::string(virtual_path));
    }
    const auto index = static_cast<std::size_t>(it - entries_.begin());
    std::ifstream file(pack_path_, std::ios::binary);
    file.seekg(static_cast<std::streamoff>(data_offsets_[index]));
    ByteVector cipher;
    if (!file || !read_exact(file, cipher, it->stored_size)) {
        return make_data_error("failed to read pack entry: " + it->path);
    }
    CryptoKey crypto_key;
    RevealedKey plain_key{key_.reveal()};
    std::string error;
    if (!derive_key(plain_key.value, crypto_key, error)) {
        return make_data_error(error);
    }
    return decrypt_payload(cipher, crypto_key, nonces_[index], manifest_digest_.data(), manifest_digest_.size());
}

Result PackReader::extract_all(const std::filesystem::path& output_dir) const
{
    if (!ok()) {
        return make_error(error_);
    }
    // Resolve user-selected ancestors (e.g. macOS /var -> /private/var), while
    // still rejecting a symlink at the extraction root or anywhere inside it.
    std::error_code ec;
    const auto absolute_output = std::filesystem::absolute(output_dir, ec).lexically_normal();
    if (ec) {
        return make_error("failed to resolve extraction directory: " + ec.message());
    }
    const auto parent = std::filesystem::weakly_canonical(absolute_output.parent_path(), ec);
    if (ec) {
        return make_error("failed to resolve extraction parent: " + ec.message());
    }
    const auto output_root = parent / absolute_output.filename();
    for (const auto& entry : entries_) {
        const auto output = output_root / std::filesystem::path(entry.path);
        std::string error;
        if (!check_extract_path(output, error)) {
            return make_error(error);
        }
        auto data = read(entry.path);
        if (!data.ok()) {
            return make_error(data.error());
        }
        auto result = write_all(output, data.data());
        if (!result.ok()) {
            return result;
        }
    }
    return Result();
}

Result encode_file(const std::filesystem::path& input_path, const std::filesystem::path& output_path,
                   std::string_view key)
{
    std::string error;
    auto plain = read_all(input_path, error);
    if (!error.empty()) {
        return make_error(error);
    }
    auto encoded = encrypt_bytes(plain, key);
    if (!encoded.ok()) {
        return make_error(encoded.error());
    }
    return write_all(output_path, encoded.data());
}

DataResult read_encoded_file(const std::filesystem::path& input_path, std::string_view key)
{
    std::string error;
    auto encoded = read_all(input_path, error);
    if (!error.empty()) {
        return make_data_error(error);
    }
    return decrypt_bytes(encoded, key);
}

Result decode_file(const std::filesystem::path& input_path, const std::filesystem::path& output_path,
                   std::string_view key)
{
    auto decoded = read_encoded_file(input_path, key);
    if (!decoded.ok()) {
        return make_error(decoded.error());
    }
    return write_all(output_path, decoded.data());
}

Result pack_directory(const std::filesystem::path& input_dir, const std::filesystem::path& output_pack,
                      std::string_view key)
{
    CryptoKey crypto_key;
    std::string error;
    if (!derive_key(key, crypto_key, error)) {
        return make_error(error);
    }
    std::error_code ec;
    const auto root = std::filesystem::weakly_canonical(input_dir, ec);
    if (ec) {
        return make_error("failed to resolve input directory: " + ec.message());
    }
    const auto output_path = std::filesystem::weakly_canonical(output_pack, ec);
    if (ec) {
        return make_error("failed to resolve output pack: " + ec.message());
    }
    const auto relative_output = output_path.lexically_relative(root);
    if (output_path == root || (!relative_output.empty() && !relative_output.has_root_path() &&
                               *relative_output.begin() != "..")) {
        return make_error("output pack must be outside the input directory");
    }
    const auto files = list_regular_files(root, error);
    if (!error.empty()) {
        return make_error(error);
    }
    if (files.size() > std::numeric_limits<std::uint32_t>::max()) {
        return make_error("too many pack entries");
    }
    std::vector<InternalPackEntry> entries;
    ByteVector table;
    std::unordered_set<std::string> paths;
    for (const auto& path : files) {
        InternalPackEntry entry;
        entry.public_entry.path = path.lexically_relative(root).generic_string();
        if (!is_safe_pack_path(entry.public_entry.path) || !paths.insert(entry.public_entry.path).second ||
            entry.public_entry.path.size() > std::numeric_limits<std::uint32_t>::max()) {
            return make_error("unsafe or duplicate pack entry path: " + entry.public_entry.path);
        }
        entry.public_entry.original_size = std::filesystem::file_size(path, ec);
        if (ec || entry.public_entry.original_size > std::numeric_limits<std::uint64_t>::max() - kTagSize) {
            return make_error("failed to measure pack entry: " + path.string());
        }
        entry.public_entry.stored_size = entry.public_entry.original_size + kTagSize;
        entry.nonce = random_nonce();
        append_le<std::uint32_t>(table, static_cast<std::uint32_t>(entry.public_entry.path.size()));
        append_le<std::uint64_t>(table, entry.public_entry.original_size);
        append_le<std::uint64_t>(table, entry.public_entry.stored_size);
        append_bytes(table, entry.nonce.data(), entry.nonce.size());
        append_bytes(table, entry.public_entry.path.data(), entry.public_entry.path.size());
        entries.push_back(std::move(entry));
    }
    const auto manifest_nonce = random_nonce();
    ByteVector output;
    append_bytes(output, kPackMagic.data(), kPackMagic.size());
    append_le<std::uint32_t>(output, kFormatVersion);
    append_le<std::uint32_t>(output, static_cast<std::uint32_t>(entries.size()));
    append_le<std::uint64_t>(output, table.size());
    append_bytes(output, manifest_nonce.data(), manifest_nonce.size());
    append_bytes(output, table.data(), table.size());
    Digest digest{};
    crypto_generichash(digest.data(), digest.size(), output.data(), output.size(), nullptr, 0);
    auto tag = encrypt_payload({}, crypto_key, manifest_nonce, output.data(), output.size());
    if (!tag.ok()) {
        return make_error(tag.error());
    }
    append_bytes(output, tag.data().data(), tag.data().size());
    for (std::size_t i = 0; i < files.size(); ++i) {
        auto plain = read_all(files[i], error);
        if (!error.empty()) {
            return make_error(error);
        }
        if (plain.size() != entries[i].public_entry.original_size) {
            return make_error("asset size changed while packing: " + files[i].string());
        }
        auto cipher = encrypt_payload(plain, crypto_key, entries[i].nonce, digest.data(), digest.size());
        if (!cipher.ok()) {
            return make_error(cipher.error());
        }
        if (cipher.data().size() > output.max_size() - output.size()) {
            return make_error("pack is too large");
        }
        append_bytes(output, cipher.data().data(), cipher.data().size());
    }
    return write_all(output_pack, output);
}

Result unpack_file(const std::filesystem::path& input_pack, const std::filesystem::path& output_dir,
                   std::string_view key)
{
    PackReader reader(input_pack, std::string(key));
    return reader.extract_all(output_dir);
}

Result encode_file(const std::filesystem::path& input_path, const std::filesystem::path& output_path, const Key& key)
{
    RevealedKey plain{key.reveal()};
    return encode_file(input_path, output_path, plain.value);
}
Result decode_file(const std::filesystem::path& input_path, const std::filesystem::path& output_path, const Key& key)
{
    RevealedKey plain{key.reveal()};
    return decode_file(input_path, output_path, plain.value);
}
DataResult read_encoded_file(const std::filesystem::path& input_path, const Key& key)
{
    RevealedKey plain{key.reveal()};
    return read_encoded_file(input_path, plain.value);
}
Result pack_directory(const std::filesystem::path& input_dir, const std::filesystem::path& output_pack, const Key& key)
{
    RevealedKey plain{key.reveal()};
    return pack_directory(input_dir, output_pack, plain.value);
}
Result unpack_file(const std::filesystem::path& input_pack, const std::filesystem::path& output_dir, const Key& key)
{
    PackReader reader(input_pack, key);
    return reader.extract_all(output_dir);
}

} // namespace assetveil

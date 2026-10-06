#include "assetveil/assetveil.hpp"
#include <sodium.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>

namespace {
using assetveil::ByteVector;
using Path = std::filesystem::path;
constexpr char kSecret[] = "regression-only-application-secret";

void require(bool ok, const std::string& message)
{
    if (!ok) {
        throw std::runtime_error(message);
    }
}
void write(const Path& path, const ByteVector& bytes)
{
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    require(static_cast<bool>(out), "fixture write failed");
}
ByteVector read(const Path& path)
{
    std::ifstream in(path, std::ios::binary);
    return ByteVector(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}
template <typename T>
void append(ByteVector& data, T value)
{
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        data.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
    }
}
std::uint64_t uint64_at(const ByteVector& data, std::size_t offset)
{
    std::uint64_t result = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        result |= static_cast<std::uint64_t>(data.at(offset + i)) << (8 * i);
    }
    return result;
}
std::array<unsigned char, 32> sodium_key()
{
    // Independent single-part derivation for format interoperability tests.
    constexpr unsigned char domain[] = "AssetVeil-v2-key";
    ByteVector input(domain, domain + sizeof(domain));
    input.insert(input.end(), kSecret, kSecret + sizeof(kSecret) - 1);
    std::array<unsigned char, 32> key{};
    crypto_generichash(key.data(), key.size(), input.data(), input.size(), nullptr, 0);
    return key;
}
ByteVector make_pack(ByteVector table, std::uint32_t count, ByteVector payload)
{
    ByteVector pack{'A', 'V', 'P', 'A', 'C', 'K', '2', 0};
    append<std::uint32_t>(pack, 2);
    append<std::uint32_t>(pack, count);
    append<std::uint64_t>(pack, table.size());
    pack.resize(48, 0); // Deterministic test-only nonce; never used in production.
    pack.insert(pack.end(), table.begin(), table.end());
    std::array<unsigned char, 16> tag{};
    auto key = sodium_key();
    require(crypto_aead_xchacha20poly1305_ietf_encrypt(tag.data(), nullptr, nullptr, 0,
                pack.data(), pack.size(), nullptr, pack.data() + 24, key.data()) == 0, "fixture auth failed");
    pack.insert(pack.end(), tag.begin(), tag.end());
    pack.insert(pack.end(), payload.begin(), payload.end());
    return pack;
}
ByteVector entry_table(const std::string& path, std::uint64_t original = 0, std::uint64_t stored = 16)
{
    ByteVector entry;
    append<std::uint32_t>(entry, static_cast<std::uint32_t>(path.size()));
    append<std::uint64_t>(entry, original);
    append<std::uint64_t>(entry, stored);
    entry.resize(44, 0);
    entry.insert(entry.end(), path.begin(), path.end());
    return entry;
}
void reject_data(const assetveil::DataResult& result, const std::string& label)
{
    require(!result.ok() && result.data().empty() && !result.error().empty(), label);
}
void byte_tests()
{
    for (std::size_t size : {0u, 1u, 7u, 8u, 9u, 1024u, 262144u}) {
        ByteVector plain(size);
        randombytes_buf(plain.data(), plain.size());
        auto encrypted = assetveil::encrypt_bytes(plain, kSecret);
        require(encrypted.ok() && encrypted.data().size() == plain.size() + 60, "byte encryption failed");
        auto decoded = assetveil::decrypt_bytes(encrypted.data(), kSecret);
        require(decoded.ok() && decoded.data() == plain, "byte roundtrip failed");
        reject_data(assetveil::decrypt_bytes(encrypted.data(), "wrong-secret"), "wrong key accepted");
        reject_data(assetveil::decrypt_bytes(encrypted.data(), ""), "empty key accepted");
        auto again = assetveil::encrypt_bytes(plain, kSecret);
        require(again.ok() && !std::equal(encrypted.data().begin() + 12, encrypted.data().begin() + 36,
                                       again.data().begin() + 12), "nonce reused");
        ByteVector independent(size + 1);
        auto key = sodium_key();
        unsigned long long length = 0;
        require(crypto_aead_xchacha20poly1305_ietf_decrypt(independent.data(), &length, nullptr,
                    encrypted.data().data() + 44, encrypted.data().size() - 44,
                    encrypted.data().data(), 44, encrypted.data().data() + 12, key.data()) == 0 &&
                    length == size && std::equal(plain.begin(), plain.end(), independent.begin()),
                "libsodium interoperability failed");
    }
    reject_data(assetveil::encrypt_bytes({1, 2, 3}, ""), "empty encryption key accepted");
    const ByteVector plain(128, 42);
    auto encrypted = assetveil::encrypt_bytes(plain, kSecret).take_data();
    for (std::size_t i = 0; i < encrypted.size(); ++i) {
        auto corrupt = encrypted;
        corrupt[i] ^= 1;
        reject_data(assetveil::decrypt_bytes(corrupt, kSecret), "modified file accepted");
        reject_data(assetveil::decrypt_bytes(ByteVector(encrypted.begin(), encrypted.begin() + i), kSecret),
                    "truncated file accepted");
    }
    encrypted.push_back(0);
    reject_data(assetveil::decrypt_bytes(encrypted, kSecret), "trailing file data accepted");
    ByteVector legacy{'A', 'V', 'E', 'I', 'L', '0', '1', 0};
    legacy.resize(36, 0);
    auto result = assetveil::decrypt_bytes(legacy, kSecret);
    reject_data(result, "v1 file accepted");
    require(result.error().find("v1") != std::string::npos, "v1 migration message missing");
    constexpr auto generated = assetveil::KeyGen("regression-only-application-secret");
    require(generated.reveal() == kSecret && generated.runtime_key().reveal() == kSecret, "key wrapper failed");
    std::string temporary = kSecret;
    assetveil::secure_clear(temporary);
    require(temporary.empty(), "secure_clear failed");
}
void malformed_pack_tests(const Path& root)
{
    const auto path = root / "malformed.avp";
    auto reject = [&](const ByteVector& bytes) {
        write(path, bytes);
        assetveil::PackReader reader(path, kSecret);
        require(!reader.ok() && reader.entries().empty(), "malformed manifest accepted");
        require(!reader.extract_all(root / "bad-extract").ok(), "invalid reader extraction succeeded");
    };
    for (const auto& unsafe : std::vector<std::string>{"../x", "/x", "a/../x", "a//b", "a/", ".", "a/./b",
             "C:/x", "a\\b", "//server/x", "a:b", "a.", "a ", "NUL", "con.txt", "a/LPT1.png", "a*", std::string("a\0b", 3)}) {
        reject(make_pack(entry_table(unsafe), 1, ByteVector(16)));
    }
    auto duplicate = entry_table("a");
    auto second = entry_table("a");
    duplicate.insert(duplicate.end(), second.begin(), second.end());
    reject(make_pack(duplicate, 2, ByteVector(32)));
    reject(make_pack({}, std::numeric_limits<std::uint32_t>::max(), {}));
    reject(make_pack(entry_table("a", 1, 16), 1, ByteVector(16)));
    reject(make_pack(entry_table("a", std::numeric_limits<std::uint64_t>::max(), 15), 1, ByteVector(15)));
    reject(make_pack(ByteVector(3), 0, {}));
    auto truncated = entry_table("a");
    truncated.pop_back();
    reject(make_pack(truncated, 1, ByteVector(16)));
    auto oversized_path = entry_table("a");
    std::fill_n(oversized_path.begin(), 4, 0xff);
    reject(make_pack(oversized_path, 1, ByteVector(16)));
    for (std::size_t length = 1; length < 128; ++length) {
        ByteVector random_table(length);
        randombytes_buf(random_table.data(), random_table.size());
        reject(make_pack(random_table, static_cast<std::uint32_t>(length % 4), {}));
    }
    ByteVector legacy{'A', 'V', 'P', 'A', 'C', 'K', '1', 0};
    legacy.resize(16, 0);
    reject(legacy);
}
void pack_tests(const Path& root)
{
    const auto assets = root / "assets";
    ByteVector first(128, 0x42), second(128, 0x81);
    write(assets / "a.glb", first);
    write(assets / "b.png", second);
    write(assets / "nested" / "empty", {});
    const auto path = root / "assets.avp";
    require(assetveil::pack_directory(assets, path, kSecret).ok(), "pack failed");
    const auto packed = read(path);
    assetveil::PackReader reader(path, kSecret);
    require(reader.ok() && reader.entries().size() == 3, "manifest load failed");
    require(reader.read("a.glb").data() == first && reader.read("b.png").data() == second, "pack read failed");
    require(reader.read("nested/empty").ok() && reader.read("nested/empty").data().empty(), "empty asset failed");
    reject_data(reader.read("missing"), "missing entry accepted");
    require(!assetveil::PackReader(path, "wrong-secret").ok(), "wrong pack key accepted");
    require(!assetveil::PackReader(path, "").ok(), "empty pack key accepted");
    require(!assetveil::pack_directory(assets, root / "bad-key.avp", "").ok(), "empty pack encryption key accepted");
    require(!assetveil::pack_directory(assets, assets / "self.avp", kSecret).ok(), "self-including pack accepted");
    const auto manifest_end = static_cast<std::size_t>(48 + uint64_at(packed, 16) + 16);
    const auto corrupt_path = root / "corrupt.avp";
    for (std::size_t i = 0; i < manifest_end; ++i) {
        auto corrupt = packed;
        corrupt[i] ^= 1;
        write(corrupt_path, corrupt);
        assetveil::PackReader damaged(corrupt_path, kSecret);
        require(!damaged.ok() && damaged.entries().empty(), "changed manifest accepted");
    }
    for (std::size_t i = manifest_end; i < manifest_end + first.size() + 16; ++i) {
        auto corrupt = packed;
        corrupt[i] ^= 1;
        write(corrupt_path, corrupt);
        assetveil::PackReader damaged(corrupt_path, kSecret);
        require(damaged.ok(), "lazy payload auth unexpectedly scanned data");
        reject_data(damaged.read("a.glb"), "changed payload accepted");
        require(damaged.read("b.png").ok(), "untouched payload failed");
    }
    auto swapped = packed;
    std::swap_ranges(swapped.begin() + manifest_end, swapped.begin() + manifest_end + 144,
                     swapped.begin() + manifest_end + 144);
    write(corrupt_path, swapped);
    reject_data(assetveil::PackReader(corrupt_path, kSecret).read("a.glb"), "swapped entries accepted");
    const auto other_path = root / "other.avp";
    require(assetveil::pack_directory(assets, other_path, kSecret).ok(), "second pack failed");
    const auto other = read(other_path);
    require(!std::equal(packed.begin() + 24, packed.begin() + 48, other.begin() + 24), "manifest nonce reused");
    require(!std::equal(packed.begin() + 68, packed.begin() + 92, other.begin() + 68), "entry nonce reused");
    auto spliced = packed;
    std::copy_n(other.begin() + manifest_end, 144, spliced.begin() + manifest_end);
    write(corrupt_path, spliced);
    reject_data(assetveil::PackReader(corrupt_path, kSecret).read("a.glb"), "cross-pack payload accepted");
    write(path, spliced);
    reject_data(reader.read("a.glb"), "replacement after reader construction accepted");
    write(path, packed);
    auto trailing = packed;
    trailing.push_back(0);
    write(corrupt_path, trailing);
    require(!assetveil::PackReader(corrupt_path, kSecret).ok(), "pack trailing data accepted");
    trailing.resize(packed.size() - 1);
    write(corrupt_path, trailing);
    require(!assetveil::PackReader(corrupt_path, kSecret).ok(), "truncated pack accepted");
    require(reader.extract_all(root / "extracted").ok(), "extraction failed");
    require(read(root / "extracted" / "a.glb") == first, "extraction mismatch");
    std::filesystem::create_directories(root / "empty-dir");
    const auto empty_path = root / "empty.avp";
    require(assetveil::pack_directory(root / "empty-dir", empty_path, kSecret).ok(), "empty pack failed");
    assetveil::PackReader empty(empty_path, kSecret);
    require(empty.ok() && empty.entries().empty() && empty.extract_all(root / "empty-out").ok(), "empty pack invalid");
    require(!assetveil::PackReader(empty_path, "wrong-secret").ok(), "empty pack wrong key accepted");
    std::error_code ec;
    std::filesystem::create_directory_symlink(root / "extracted", root / "symlink-out", ec);
    if (!ec) {
        require(!reader.extract_all(root / "symlink-out").ok(), "symlink extraction accepted");
        std::filesystem::create_symlink(assets / "a.glb", assets / "linked.glb");
        require(!assetveil::pack_directory(assets, root / "linked.avp", kSecret).ok(), "input symlink accepted");
    }
}

void sparse_pack_test(const Path& root)
{
    // A valid authenticated manifest with a large unused entry. Reading the small
    // entry must seek to its range, without loading or authenticating the large one.
    constexpr std::uint64_t large_size = 512ull * 1024 * 1024;
    const ByteVector plain{'s', 'm', 'a', 'l', 'l'};
    auto table = entry_table("large", large_size, large_size + 16);
    const auto small = entry_table("small", plain.size(), plain.size() + 16);
    table.insert(table.end(), small.begin(), small.end());
    auto header = make_pack(table, 2, {});
    std::array<unsigned char, 32> digest{};
    crypto_generichash(digest.data(), digest.size(), header.data(), header.size() - 16, nullptr, 0);
    std::array<unsigned char, 24> nonce{};
    auto key = sodium_key();
    ByteVector cipher(plain.size() + 16);
    crypto_aead_xchacha20poly1305_ietf_encrypt(cipher.data(), nullptr, plain.data(), plain.size(),
                digest.data(), digest.size(), nullptr, nonce.data(), key.data());
    const auto path = root / "sparse.avp";
    write(path, header);
    std::fstream out(path, std::ios::binary | std::ios::in | std::ios::out);
    out.seekp(static_cast<std::streamoff>(header.size() + large_size + 16));
    out.write(reinterpret_cast<const char*>(cipher.data()), static_cast<std::streamsize>(cipher.size()));
    out.close();
    assetveil::PackReader reader(path, kSecret);
    require(reader.ok() && reader.read("small").data() == plain, "range read of sparse pack failed");
}
} // namespace

int main()
{
    require(sodium_init() >= 0, "sodium_init failed");
    std::array<unsigned char, 8> id{};
    randombytes_buf(id.data(), id.size());
    const auto root = std::filesystem::temp_directory_path() / ("assetveil-security-" + std::to_string(id[0]) +
                     "-" + std::to_string(uint64_at(ByteVector(id.begin(), id.end()), 0)));
    try {
        byte_tests();
        malformed_pack_tests(root);
        pack_tests(root);
        sparse_pack_test(root);
        std::filesystem::remove_all(root);
        std::cout << "Authenticated bytes, packs, malformed metadata, key handling and range reads passed\n";
    } catch (const std::exception& error) {
        std::filesystem::remove_all(root);
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}

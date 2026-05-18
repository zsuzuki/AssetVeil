# AssetVeil

[日本語 README](README_jp.md)

AssetVeil is a small C++17 library and CLI for fast, lightweight game asset
obfuscation and packing.

It is intentionally not strong encryption or DRM. The goal is to avoid shipping
plain asset files and to provide a practical "we applied basic protection"
layer for purchased or licensed assets, while keeping runtime decoding fast and
file sizes close to the original data.

## Features

- Fast stream-style byte obfuscation
- No compression and no large data expansion
- Single-file encode/decode
- Directory packing and unpacking
- C++ library API for runtime loading
- CLI for build pipelines

## Build

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

## CLI

```sh
assetveil encode input.png input.png.av --key my-key
assetveil decode input.png.av restored.png --key my-key

assetveil pack assets game_assets.avp --key my-key
assetveil list game_assets.avp
assetveil unpack game_assets.avp restored_assets --key my-key
```

## C++ API

```cpp
#include <assetveil/assetveil.hpp>

auto decoded = assetveil::read_encoded_file("texture.png.av", "my-key");
if (decoded.ok()) {
    const auto& bytes = decoded.data();
}

assetveil::PackReader pack("game_assets.avp", "my-key");
auto player = pack.read("textures/player.png");
```

## Key Obfuscation Helper

For keys embedded in C++ code, `KeyGen` can keep the literal from being stored
as a plain member value after construction.

```cpp
constexpr auto key = assetveil::KeyGen("my-key");

auto decoded = assetveil::read_encoded_file("texture.png.av", key);
assetveil::PackReader pack("game_assets.avp", key);
```

This is still only a light obfuscation helper. The key must be revealed briefly
when decoding, and a determined attacker can recover it from the program.

## Security Note

AssetVeil is a deterrent and convenience layer, not a cryptographic security
boundary. If the game binary contains the key and decoding code, a motivated
attacker can recover the assets. Use it when speed, small output size, and
simple integration matter more than strong secrecy.

## License

MIT License. See [LICENSE](LICENSE).

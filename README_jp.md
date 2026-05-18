# AssetVeil

AssetVeil は、ゲーム用アセットを高速かつ軽量に難読化し、必要に応じて複数ファイルをまとめるための C++17 ライブラリと CLI です。

これは強固な暗号化や DRM を目的にしたものではありません。平文のアセットファイルをそのまま配布しないこと、購入・ライセンス済みアセットに対して「基本的な保護をかけている」と説明できる程度の実用的な保護層を、速度と扱いやすさを優先して提供することを目的にしています。

## 特徴

- 高速なストリーム式バイト難読化
- 圧縮なし、大きなデータ増加なし
- 単体ファイルのエンコード・デコード
- ディレクトリのパック・アンパック
- ランタイム読み込み用の C++ ライブラリ API
- ビルドパイプラインに組み込みやすい CLI

## ビルド

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

## キー難読化ヘルパー

C++ コードに埋め込むキーには `KeyGen` を使えます。文字列リテラルをそのままメンバー値として保持せず、コンパイル時に軽く変換した状態で持つための補助です。

```cpp
constexpr auto key = assetveil::KeyGen("my-key");

auto decoded = assetveil::read_encoded_file("texture.png.av", key);
assetveil::PackReader pack("game_assets.avp", key);
```

これはあくまで軽い難読化です。デコード時には一時的にキーを復元する必要があり、十分な動機を持った解析者からキーを完全に隠すものではありません。

## セキュリティについて

AssetVeil は、攻撃を完全に防ぐための暗号境界ではありません。ゲーム本体にキーと復号コードが含まれる以上、十分な動機を持った解析者はアセットを復元できます。

その代わり、AssetVeil は以下の用途に向いています。

- 配布物に平文アセットを直接含めたくない
- 速度とサイズを優先したい
- 簡単なビルド前処理として導入したい
- 強固な DRM ではなく、軽量な難読化で十分

## ライセンス

MIT License です。詳細は [LICENSE](LICENSE) を参照してください。

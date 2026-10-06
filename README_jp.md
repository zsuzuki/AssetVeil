# AssetVeil

AssetVeil は、ゲーム用アセットを暗号化して配布し、ランタイムでは必要なデータをメモリへ復号する C++17 ライブラリと開発用 CLI です。

v0.2 / ファイル形式 v2 では、libsodium の [XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction) を使用します。旧形式の「先頭8バイトが分かれば鍵なしで全体を復元できる」問題と、nonce の再利用を修正しています。DRM やライセンス適合性の保証を提供するものではありません。

## 特徴

- 単体ファイルの暗号化と、複数ファイルのパック
- 暗号化ごとに新しい24バイトのランダム nonce を生成
- ヘッダー、パックのファイル名・サイズ・nonce、各アセットを認証
- 誤った鍵や改ざんを検出した場合、復号データを返さない
- パックの管理情報を一度読み込み、アセット読み込み時は対象範囲だけを読み出す
- 圧縮なし。単体ファイルは60バイト、パックは64バイト＋各エントリのパス長＋60バイト増加
- `Key` / `KeyGen` と既存のファイル読み込み API を継続して利用可能

## ビルド

libsodium 1.0.12 以上が必要です。macOS なら `brew install libsodium` で導入できます。CMake は pkg-config、または `CMAKE_PREFIX_PATH` からライブラリを探します。

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

CLI とテストが不要なゲーム用ビルドでは、次のようにします。`add_subdirectory` でゲーム側から取り込む場合も、CLI とテストはデフォルトで無効です。

```sh
cmake -S . -B build/runtime -G Ninja \
  -DASSETVEIL_BUILD_CLI=OFF -DASSETVEIL_BUILD_TESTS=OFF
cmake --build build/runtime
```

ゲーム側は `target_link_libraries(game PRIVATE assetveil)` でリンクします。libsodium を動的リンクする場合は、そのライブラリも配布物に含めてください。Windows で静的な libsodium をリンクする場合は `-DASSETVEIL_SODIUM_STATIC=ON` を指定します。

## CLI と鍵

鍵には、ゲームごとに生成した十分にランダムな値を使ってください。文字列 API は空の鍵を拒否し、入力をドメイン分離した BLAKE2b で32バイトへ変換します。これは高速な鍵の変換であり、人間が作った短いパスワードを強化する処理ではありません。

例として、非公開のビルド用ディレクトリに32バイト分のランダム値を16進文字列で保存できます。

```sh
mkdir -p private
umask 077
openssl rand -hex 32 | tr -d '\n' > private/game.key

assetveil encode input.png input.png.av --key-file private/game.key
assetveil decode input.png.av restored.png --key-file private/game.key

assetveil pack assets game_assets.avp --key-file private/game.key
assetveil list game_assets.avp --key-file private/game.key
assetveil unpack game_assets.avp restored_assets --key-file private/game.key
```

`--key-file` は改行も含めてファイルの全バイトを鍵として扱います。C++ 側にも同じバイト列を渡してください。`--key <key>` も利用できますが、秘密をシェル履歴やプロセスの引数に残さないため、ビルド処理では `--key-file` を推奨します。一覧取得にも正しい鍵が必要です。

パックの出力先は入力ディレクトリの外に指定してください。入力内の symlink はパックを中止します。アンパックは出力ディレクトリ自体とその配下の symlink を拒否します。アンパック先には、ほかのプロセスが同時に書き換えない専用ディレクトリを使用してください。

## C++ API

```cpp
#include <assetveil/assetveil.hpp>
#include "private/game_asset_key.hpp" // 非公開のビルド工程で生成する鍵定義

// game_asset_key は std::string、assetveil::Key、KeyGen のいずれでも利用可能。
auto decoded = assetveil::read_encoded_file("texture.png.av", game_asset_key);
if (!decoded.ok()) {
    // エラーを扱い、平文ファイルの読み込みへフォールバックしない。
    return;
}
const auto& bytes = decoded.data(); // 画像・モデルローダーへメモリで渡す

assetveil::PackReader pack("game_assets.avp", game_asset_key);
if (!pack.ok()) {
    return;
}
auto model = pack.read("models/player.glb");
if (model.ok()) {
    const auto& model_bytes = model.data();
}
```

バイト配列だけを扱う場合は、nonce を自分で作らずに次の API を利用します。

```cpp
auto encrypted = assetveil::encrypt_bytes(input_bytes, application_secret);
if (encrypted.ok()) {
    auto decrypted = assetveil::decrypt_bytes(encrypted.data(), application_secret);
}
```

`PackReader` は管理情報を構築時に検証して保持します。各アセットの暗号文は `read()` 時に認証します。そのため `ok()` は全アセットを事前検証したことを意味しません。パックを更新した場合は新しい reader を作成してください。

## キー難読化ヘルパー

```cpp
// 説明用の公開キー。製品では非公開ビルド設定から生成したキーを使う。
constexpr auto key = assetveil::KeyGen("example-only-do-not-use-in-production");
auto decoded = assetveil::read_encoded_file("texture.png.av", key);
```

`KeyGen` は文字列を軽く難読化して保持する補助です。コンパイラーが平文を残さない保証はなく、ゲーム本体から鍵を完全に隠すものでもありません。

## v1 からの移行

- 旧 v1 ファイル・パックは読み込みを拒否します。元アセットから v2 で再エンコード／再パックし、読み込み側も更新してください。
- `encode_file` / `decode_file` / `read_encoded_file` / `pack_directory` / `unpack_file` / `PackReader` の呼び出し方は維持しています。ただし `list` は鍵が必須です。
- 低レベルの `obfuscate_bytes` / `deobfuscate_bytes` は削除しました。`encrypt_bytes` / `decrypt_bytes` に移行し、`DataResult` のエラーを処理してください。呼び出し側から64bit nonce を渡す API はありません。
- `PackEntry::checksum` はソース互換性のため残していますが、v2 では常に0です。検証には認証タグを使用し、平文のチェックサムを保存しません。

[形式仕様と検証記録](docs/security-review-2026-10-06.md) に再現方法と検証範囲を記載しています。

## 配布するゲーム側の注意点

- 購入した元アセット、鍵ファイル、鍵を含む設定・生成ヘッダーを公開リポジトリや配布物に含めないでください。
- 製品版は復号結果をメモリから直接使用し、平文ファイルの展開・デバッグ用エクスポートを組み込まないでください。`decode` / `unpack` は開発用機能です。
- ゲーム本体が復号する以上、実行ファイルの解析やメモリ取得による復元は可能です。暗号化の修正はこの限界を変えません。
- 個別アセットの利用条件への適合は別途確認してください。

## ライセンス

MIT License。詳細は [LICENSE](LICENSE) を参照してください。

# AssetVeil 検証・修正記録（2026-10-06）

対象は `bbb0fed` の実装と、ローカルで修正した v0.2 / ファイル形式 v2。購入アセットや本番の鍵は使用していない。

## 確認した問題と修正

| 問題 | 修正 |
|---|---|
| SplitMix64 の出力を既知の先頭8バイトから逆算でき、鍵なしで全体を復元できる | libsodium の XChaCha20-Poly1305 に置き換え |
| 同じ鍵・パス・サイズで nonce が再利用される | 暗号化ごとに24バイトのランダム nonce を生成 |
| FNV チェックサムに鍵がなく、パックの管理情報が認証されない | ファイルのヘッダーと本文、パックの管理情報と各本文を AEAD で認証 |
| 空の鍵をライブラリが許容し、誤った鍵でもパック一覧が取得できる | 空の鍵を拒否し、管理情報の認証後に一覧を返す |
| `PackReader::read()` が毎回パック全体を読み込み・解析する | 管理情報を保持し、対象エントリの範囲だけを読み出す |
| 不正な reader の `extract_all()` が成功として終了する | エラーを返す |
| パス検証が OS に依存し、出力先の symlink を辿れる | 共通のパス検証、重複パス拒否、出力配下の symlink 拒否 |
| CLI が鍵を引数でのみ受け取る | `--key-file` を追加。開発用 CLI はランタイム用ビルドから除外可能 |
| `add_subdirectory` で取り込むと呼び出し側へ C++17 の要件が伝わらない | `target_compile_features(assetveil PUBLIC cxx_std_17)` を追加 |

v1 の復号へフォールバックしない。元データからの再パックが必要。既存の高レベル API と `Key` / `KeyGen` は維持したが、認証できない低レベルの nonce 指定 API は削除した。

## 既知平文攻撃の再現

`tests/known_plaintext.py` は実際の CLI で、GLB 2.0 の三角形モデル10件と PNG 画像10件を個別のランダムなテスト鍵で処理する。復元関数に渡すのは暗号文と先頭8バイトだけで、鍵は渡さない。復元後の全バイトを元データと比較する。同じ鍵・入力を再エンコードして nonce も比較する。

| 結果 | v1 | v2 |
|---|---:|---:|
| 鍵なしで全バイトを復元 | 20/20 | 0/20 |
| 再エンコード時の nonce 再利用 | 20/20 | 0/20 |

v1 の CLI に対する実行では `--expect-vulnerable` を付ける。修正版では次を実行する。

```sh
python3 tests/known_plaintext.py build/release/assetveil
```

このテストは報告された攻撃の回帰確認であり、暗号方式の安全性そのものを証明するものではない。

## v2 の形式

整数は little-endian。暗号化は libsodium の combined mode。認証タグは16バイト。文字列の鍵は `BLAKE2b-256("AssetVeil-v2-key\0" || key_bytes)` で暗号鍵に変換する。ランダムなアプリケーション秘密を前提とした高速な変換で、パスワード用 KDF ではない。

単体ファイル:

| フィールド | バイト数 |
|---|---:|
| `AVEIL02\0` | 8 |
| version = 2 | 4 |
| nonce | 24 |
| original_size | 8 |
| 暗号文＋認証タグ | original_size + 16 |

先頭44バイト全体を additional data（AD）として認証する。長さの不一致、余分な末尾データ、認証失敗を拒否する。

パック:

| フィールド | バイト数 |
|---|---:|
| `AVPACK2\0` | 8 |
| version = 2 | 4 |
| entry_count | 4 |
| table_size | 8 |
| 管理情報用 nonce | 24 |
| エントリテーブル | table_size |
| 管理情報の認証タグ | 16 |
| 各エントリの暗号文＋タグ | 各 original_size + 16 |

テーブルの各エントリは `path_size:u32, original_size:u64, stored_size:u64, nonce:24 bytes, path:path_size bytes`。`stored_size = original_size + 16`。

ヘッダー48バイトとテーブル全体を AD とし、空の本文を暗号化して管理情報のタグを作る。認証前にはエントリ数による reserve、パスの利用、エントリのオフセット計算を行わない。テーブル長は実ファイルサイズで制限する。

各エントリの本文は独立したランダム nonce で暗号化し、`BLAKE2b-256(ヘッダー || テーブル)` を AD にする。この値にはパックの nonce、全エントリのパス・サイズ・nonce が含まれる。エントリの差し替え、並べ替え、別パックからのコピーは、読み込み時の認証に失敗する。ファイル名・サイズは暗号化せず公開される。

## 検証範囲

macOS / AppleClang 21 / libsodium 1.0.22 で確認した。

- Release ビルドと既存 roundtrip テスト
- 空・1・7・8・9・1024・262144バイトの復号と、libsodium API による相互確認
- 単体ファイルの各バイト改ざん、全位置での切り詰め、末尾追加、誤った鍵、空の鍵
- 管理情報の各バイト改ざん、本文・タグの各バイト改ざん、エントリ入れ替え、同じ鍵の別パックからの本文コピー
- 正しいタグを持つ不正な管理情報（過大な count、サイズ不一致、重複・unsafe パス、Windows の drive/UNC/device 名、NUL、切り詰め、不正テーブル）
- 空アセット、空パック、旧形式拒否、symlink、入力内の出力パック拒否
- CLI の鍵ファイル（NUL・改行を含む）、認証付き list、復号失敗時に既存の出力を上書きしないこと
- 512MiB の未使用エントリを含む sparse pack から小さいエントリだけを読み出すこと
- AddressSanitizer / UBSan ビルドで同じ4件の CTest が成功
- `add_subdirectory` から CLI・テストを含めず、静的 libsodium をリンクした利用側サンプルをビルド・実行（pkg-config を使わない探索経路も確認）

通常の再現手順:

```sh
cmake -S . -B build/release -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_FLAGS='-Wall -Wextra -Wpedantic'
cmake --build build/release
ctest --test-dir build/release --output-on-failure

cmake -S . -B build/sanitize -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS='-Wall -Wextra -Wpedantic -fsanitize=address,undefined -fno-omit-frame-pointer' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
cmake --build build/sanitize
ctest --test-dir build/sanitize --output-on-failure
```

Python がない環境では、C++ の2件を登録する。CLI 回帰テストを含む4件の実行には Python 3 が必要。

## 実装上の限界

- ライブラリの修正とローカルテストまでを実施した。利用先ゲームの配布物検査、実アセットの再パック、Windows/Linux での実行検証は含まない。
- `PackReader::ok()` は管理情報の認証結果。本文は必要なものを `read()` した時点で認証する。
- パック作成と単体ファイル処理はメモリ上で行う。巨大なパックの作成をストリーミング化したものではない。
- アンパック時の symlink 検査は、同時に別プロセスがパスを変更する攻撃への保証を提供しない。専用の出力先を使う。
- ゲーム実行ファイルの解析・メモリ取得によるアセット抽出は防げない。`KeyGen` は軽い難読化の補助。
- 個別の商用アセットのライセンス適合性を認定したものではない。

参考: [libsodium XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)、[Generic hashing](https://doc.libsodium.org/hashing/generic_hashing)。

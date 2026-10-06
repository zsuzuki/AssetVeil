"""Regression for the v1 known-header attack; runs against the real CLI."""

import argparse
import json
import pathlib
import secrets
import struct
import subprocess
import tempfile
import zlib

MASK = (1 << 64) - 1
STEP = 0x9E3779B97F4A7C15


def glb_fixture():
    model = {
        "asset": {"version": "2.0"},
        "buffers": [{"byteLength": 36}],
        "bufferViews": [{"buffer": 0, "byteLength": 36, "target": 34962}],
        "accessors": [{"bufferView": 0, "componentType": 5126, "count": 3,
                       "type": "VEC3", "min": [0, 0, 0], "max": [1, 1, 0]}],
        "meshes": [{"primitives": [{"attributes": {"POSITION": 0}}]}],
        "nodes": [{"mesh": 0}], "scenes": [{"nodes": [0]}], "scene": 0,
        "extras": {"fixture": secrets.token_hex(64)},
    }
    metadata = json.dumps(model, separators=(",", ":")).encode()
    metadata += b" " * (-len(metadata) % 4)
    vertices = struct.pack("<9f", 0, 0, 0, 1, 0, 0, 0, 1, 0)
    chunks = struct.pack("<II", len(metadata), 0x4E4F534A) + metadata
    chunks += struct.pack("<II", len(vertices), 0x004E4942) + vertices
    return b"glTF" + struct.pack("<II", 2, 12 + len(chunks)) + chunks


def png_fixture():
    def chunk(kind, data):
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data)))

    pixels = b"".join(b"\0" + secrets.token_bytes(64 * 4) for _ in range(64))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", 64, 64, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b""))


def unxorshift(value, shift):
    result = value
    for _ in range(64 // shift):
        result = value ^ (result >> shift)
    return result


def mix(value):
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & MASK
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & MASK
    return value ^ (value >> 31)


def recover_without_key(ciphertext, known_header):
    first_block = bytes(
        ((ciphertext[i] ^ known_header[i]) - i * 131) & 255
        for i in range(8)
    )
    value = unxorshift(int.from_bytes(first_block, "little"), 31)
    value = (value * pow(0x94D049BB133111EB, -1, 1 << 64)) & MASK
    value = unxorshift(value, 27)
    value = (value * pow(0xBF58476D1CE4E5B9, -1, 1 << 64)) & MASK
    state = unxorshift(value, 30)
    plain = bytearray()
    for start in range(0, len(ciphertext), 8):
        block = mix(state).to_bytes(8, "little")
        for j, cipher_byte in enumerate(ciphertext[start : start + 8]):
            plain.append(cipher_byte ^ ((block[j] + (start + j) * 131) & 255))
        state = (state + STEP) & MASK
    return bytes(plain)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cli", type=pathlib.Path)
    parser.add_argument("--expect-vulnerable", action="store_true")
    args = parser.parse_args()
    recovered = 0
    repeated_nonce = 0
    cases = 0
    cli = str(args.cli.resolve())
    with tempfile.TemporaryDirectory(prefix="assetveil-known-header-") as folder:
        root = pathlib.Path(folder)
        for fixture in (glb_fixture, png_fixture):
            for _ in range(10):
                plain = fixture()
                header = plain[:8]
                (root / "plain").write_bytes(plain)
                key = secrets.token_hex(32)
                outputs = []
                for filename in ("first.av", "second.av"):
                    subprocess.run(
                        [cli, "encode", str(root / "plain"), str(root / filename), "--key", key],
                        check=True,
                    )
                    outputs.append((root / filename).read_bytes())
                version = struct.unpack_from("<I", outputs[0], 8)[0]
                if version == 1:
                    payload = outputs[0][36:]
                    nonces = [encoded[12:20] for encoded in outputs]
                elif version == 2:
                    payload = outputs[0][44:-16]
                    nonces = [encoded[12:36] for encoded in outputs]
                else:
                    raise AssertionError(f"unexpected format version: {version}")
                recovered += recover_without_key(payload, header) == plain
                repeated_nonce += nonces[0] == nonces[1]
                cases += 1
    print(f"known-header whole-file recovery: {recovered}/{cases}; repeated nonces: {repeated_nonce}/{cases}")
    expected = cases if args.expect_vulnerable else 0
    assert recovered == expected
    assert repeated_nonce == expected


if __name__ == "__main__":
    main()

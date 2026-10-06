"""CLI checks for secret files and fail-closed decoding."""
import pathlib
import secrets
import subprocess
import sys
import tempfile

cli = str(pathlib.Path(sys.argv[1]).resolve())


def run(*args, success=True):
    result = subprocess.run([cli, *map(str, args)], capture_output=True)
    assert (result.returncode == 0) == success, result.stderr.decode()
    return result


with tempfile.TemporaryDirectory(prefix="assetveil-cli-") as folder:
    root = pathlib.Path(folder)
    key = root / "game.key"
    # Key files are read byte-for-byte, including NUL and newline.
    key.write_bytes(secrets.token_bytes(32) + b"\0\n")
    wrong = root / "wrong.key"
    wrong.write_bytes(secrets.token_bytes(32))
    empty = root / "empty.key"
    empty.write_bytes(b"")
    plain = root / "plain.glb"
    content = b"glTF\x02\0\0\0" + secrets.token_bytes(128)
    plain.write_bytes(content)
    encoded = root / "encoded.av"
    restored = root / "restored.glb"
    run("encode", plain, encoded, "--key-file", key)
    run("decode", encoded, restored, "--key-file", key)
    assert restored.read_bytes() == content
    sentinel = b"existing output must survive failure"
    restored.write_bytes(sentinel)
    run("decode", encoded, restored, "--key-file", wrong, success=False)
    assert restored.read_bytes() == sentinel
    corrupt = bytearray(encoded.read_bytes())
    corrupt[-1] ^= 1
    encoded.write_bytes(corrupt)
    run("decode", encoded, restored, "--key-file", key, success=False)
    assert restored.read_bytes() == sentinel
    for key_file in (empty, root / "missing.key"):
        output = root / "failed.av"
        run("encode", plain, output, "--key-file", key_file, success=False)
        assert not output.exists()
    run("encode", plain, root / "failed.av", "--key", "", success=False)
    assets = root / "assets"
    assets.mkdir()
    (assets / "model.glb").write_bytes(content)
    pack = root / "game.avp"
    run("pack", assets, pack, "--key-file", key)
    assert b"model.glb" in run("list", pack, "--key-file", key).stdout
    assert not run("list", pack, "--key-file", wrong, success=False).stdout
    run("list", pack, success=False)
    run("list", pack, "--key-file", key, "--key", "extra", success=False)
    run("unpack", pack, root / "unpacked", "--key-file", key)
    assert (root / "unpacked" / "model.glb").read_bytes() == content
    run("unpack", pack, root / "failed-extract", "--key-file", wrong, success=False)
    assert not (root / "failed-extract").exists()
print("CLI secret-file, authenticated listing and output preservation checks passed")

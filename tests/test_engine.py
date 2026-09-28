import math
import random

import pytest

from safecrypt.container import HEADER_LEN, read_header
from safecrypt.crypto import TAG_LEN, Cipher, KdfParams
from safecrypt.engine import decrypt_file, encrypt_file
from safecrypt.errors import (
    AuthenticationError,
    InvalidFormatError,
    TruncatedFileError,
)

PW = b"parol-12345678"
FAST = KdfParams(time_cost=1, memory_cost=64, parallelism=1)
MIB = 1024 * 1024
CHUNK = 1024
ENC_CHUNK = CHUNK + TAG_LEN


def rand(n: int) -> bytes:
    return random.Random(n).randbytes(n)


def enc(src, dst, **kw):
    kw.setdefault("kdf_params", FAST)
    encrypt_file(src, dst, PW, **kw)


def files(directory) -> list[str]:
    return sorted(p.name for p in directory.iterdir())


@pytest.fixture
def sample(tmp_path):
    """3 ta to'liq bo'lak + 100 baytlik oxirgi bo'lak (chunk_size=1024)."""
    src = tmp_path / "asl.bin"
    data = rand(3 * CHUNK + 100)
    src.write_bytes(data)
    encrypted = tmp_path / "asl.bin.scr"
    enc(src, encrypted, chunk_size=CHUNK)
    return data, encrypted


def assert_rejected(tmp_path, blob: bytes, exc) -> None:
    bad = tmp_path / "buzuq.scr"
    bad.write_bytes(blob)
    out = tmp_path / "chiqish.bin"
    with pytest.raises(exc):
        decrypt_file(bad, out, PW)
    assert not out.exists()
    assert not any(name.endswith(".tmp") for name in files(tmp_path))


# ---------- T1: round-trip ----------

@pytest.mark.parametrize("size", [0, 1, MIB - 1, MIB, MIB + 1])
def test_roundtrip_default_chunk(tmp_path, size):
    src, encrypted, dst = tmp_path / "a", tmp_path / "a.scr", tmp_path / "b"
    data = rand(size)
    src.write_bytes(data)
    enc(src, encrypted)
    assert encrypted.stat().st_size == HEADER_LEN + size + TAG_LEN * max(1, math.ceil(size / MIB))
    decrypt_file(encrypted, dst, PW)
    assert dst.read_bytes() == data


@pytest.mark.parametrize("cipher", list(Cipher))
@pytest.mark.parametrize("size", [0, 1, 1023, 1024, 1025, 2048, 2049, 5000])
def test_roundtrip_small_chunks(tmp_path, cipher, size):
    src, encrypted, dst = tmp_path / "a", tmp_path / "a.scr", tmp_path / "b"
    data = rand(size)
    src.write_bytes(data)
    enc(src, encrypted, cipher=cipher, chunk_size=CHUNK)
    decrypt_file(encrypted, dst, PW)
    assert dst.read_bytes() == data


# ---------- T2: noto'g'ri parol ----------

def test_wrong_password(tmp_path, sample):
    _, encrypted = sample
    out = tmp_path / "out.bin"
    with pytest.raises(AuthenticationError):
        decrypt_file(encrypted, out, b"boshqa-parol-99")
    assert files(tmp_path) == ["asl.bin", "asl.bin.scr"]


def test_failed_decrypt_keeps_existing_output(tmp_path, sample):
    _, encrypted = sample
    out = tmp_path / "out.bin"
    out.write_bytes(b"eski")
    with pytest.raises(AuthenticationError):
        decrypt_file(encrypted, out, b"boshqa-parol-99", overwrite=True)
    assert out.read_bytes() == b"eski"


# ---------- T3: bir baytni o'zgartirish ----------

@pytest.mark.parametrize(
    "pos, exc",
    [
        (7, InvalidFormatError),                    # zaxira bayt
        (17, AuthenticationError),                  # salt
        (33, AuthenticationError),                  # nonce prefiksi
        (44, AuthenticationError),                  # bo'lak o'lchami
        (HEADER_LEN + 10, AuthenticationError),     # shifrlangan ma'lumot
        (HEADER_LEN + CHUNK, AuthenticationError),  # 0-bo'lak tegi
        (-1, AuthenticationError),                  # oxirgi teg
    ],
)
def test_single_byte_flip(tmp_path, sample, pos, exc):
    _, encrypted = sample
    blob = bytearray(encrypted.read_bytes())
    blob[pos] ^= 0x01
    assert_rejected(tmp_path, bytes(blob), exc)


# ---------- T4: kesib olish ----------

@pytest.mark.parametrize(
    "cut, exc",
    [
        (10, InvalidFormatError),                            # sarlavha ichida
        (HEADER_LEN, TruncatedFileError),                    # bo'laklar yo'q
        (HEADER_LEN + 5, TruncatedFileError),                # tegdan qisqa
        (HEADER_LEN + 2 * ENC_CHUNK, TruncatedFileError),    # bo'lak chegarasida
        (HEADER_LEN + 3 * ENC_CHUNK, TruncatedFileError),    # oxirgi bo'lak butunlay yo'q
        (HEADER_LEN + 500, (TruncatedFileError, AuthenticationError)),  # bo'lak o'rtasida
        (-1, AuthenticationError),                           # tegning oxirgi baytisiz
    ],
)
def test_truncation(tmp_path, sample, cut, exc):
    _, encrypted = sample
    assert_rejected(tmp_path, encrypted.read_bytes()[:cut], exc)


# ---------- T5: bo'laklar o'rnini almashtirish; ortiqcha ma'lumot ----------

def test_chunk_swap(tmp_path, sample):
    _, encrypted = sample
    blob = encrypted.read_bytes()
    c0 = blob[HEADER_LEN : HEADER_LEN + ENC_CHUNK]
    c1 = blob[HEADER_LEN + ENC_CHUNK : HEADER_LEN + 2 * ENC_CHUNK]
    swapped = blob[:HEADER_LEN] + c1 + c0 + blob[HEADER_LEN + 2 * ENC_CHUNK :]
    assert_rejected(tmp_path, swapped, AuthenticationError)


@pytest.mark.parametrize("extra", [b"x", bytes(TAG_LEN), bytes(ENC_CHUNK)])
def test_trailing_data_rejected(tmp_path, sample, extra):
    _, encrypted = sample
    assert_rejected(tmp_path, encrypted.read_bytes() + extra, AuthenticationError)


def test_trailing_data_after_full_last_chunk(tmp_path):
    src, encrypted = tmp_path / "a", tmp_path / "a.scr"
    src.write_bytes(rand(2 * CHUNK))  # oxirgi bo'lak ham to'liq
    enc(src, encrypted, chunk_size=CHUNK)
    assert_rejected(tmp_path, encrypted.read_bytes() + b"x", AuthenticationError)


# ---------- T6: har safar turlicha natija ----------

def test_two_encryptions_differ(tmp_path, sample):
    _, first = sample
    second = tmp_path / "ikkinchi.scr"
    enc(tmp_path / "asl.bin", second, chunk_size=CHUNK)
    assert first.read_bytes() != second.read_bytes()
    assert read_header(first).salt != read_header(second).salt


# ---------- T9: mavjud chiqish fayli ----------

def test_existing_output(tmp_path, sample):
    data, encrypted = sample
    src = tmp_path / "asl.bin"
    with pytest.raises(FileExistsError):
        enc(src, encrypted)
    enc(src, encrypted, overwrite=True)
    out = tmp_path / "out.bin"
    decrypt_file(encrypted, out, PW)
    assert out.read_bytes() == data


def test_same_input_and_output(tmp_path, sample):
    with pytest.raises(ValueError):
        enc(tmp_path / "asl.bin", tmp_path / "asl.bin", overwrite=True)


def test_missing_input(tmp_path):
    with pytest.raises(FileNotFoundError):
        enc(tmp_path / "yoq.bin", tmp_path / "yoq.scr")
    assert files(tmp_path) == []


# ---------- T10: unicode va bo'shliqli yo'llar ----------

def test_unicode_paths(tmp_path):
    folder = tmp_path / "Mening hujjatlarim ў"
    folder.mkdir()
    src = folder / "Hujjat — nusxa ñ.txt"
    src.write_bytes(rand(3000))
    encrypted = folder / "Hujjat — nusxa ñ.txt.scr"
    out = folder / "natija ғ.txt"
    enc(src, encrypted, chunk_size=CHUNK)
    decrypt_file(encrypted, out, PW)
    assert out.read_bytes() == src.read_bytes()


# ---------- T11: uzilish (Ctrl+C) ----------

def _boom(_: int) -> None:
    raise KeyboardInterrupt


def test_interrupt_encrypt_leaves_nothing(tmp_path):
    src = tmp_path / "a"
    src.write_bytes(rand(5000))
    with pytest.raises(KeyboardInterrupt):
        enc(src, tmp_path / "a.scr", chunk_size=CHUNK, progress=_boom)
    assert files(tmp_path) == ["a"]


def test_interrupt_decrypt_leaves_nothing(tmp_path, sample):
    _, encrypted = sample
    with pytest.raises(KeyboardInterrupt):
        decrypt_file(encrypted, tmp_path / "out.bin", PW, progress=_boom)
    assert files(tmp_path) == ["asl.bin", "asl.bin.scr"]


# ---------- Progress va info ----------

def test_progress_reports_all_bytes(tmp_path, sample):
    data, encrypted = sample
    seen: list[int] = []
    decrypt_file(encrypted, tmp_path / "out.bin", PW, progress=seen.append)
    assert sum(seen) == len(data)


def test_header_info(sample):
    _, encrypted = sample
    header = read_header(encrypted)
    assert header.cipher is Cipher.AES_256_GCM
    assert header.chunk_size == CHUNK
    assert header.kdf == FAST
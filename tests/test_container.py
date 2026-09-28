import pytest

from safecrypt.container import (
    DEFAULT_CHUNK_SIZE,
    HEADER_LEN,
    MAX_CHUNK_SIZE,
    MIN_CHUNK_SIZE,
    Header,
    read_header,
)
from safecrypt.crypto import Cipher, KdfParams
from safecrypt.errors import (
    InvalidFormatError,
    UnsafeParametersError,
    UnsupportedVersionError,
)


def make_header(**over) -> Header:
    fields = dict(
        cipher=Cipher.AES_256_GCM,
        kdf=KdfParams(3, 65536, 4),
        salt=bytes(range(16)),
        nonce_prefix=b"ABCDEFGH",
        chunk_size=DEFAULT_CHUNK_SIZE,
    )
    fields.update(over)
    return Header(**fields)


def patch(data: bytes, offset: int, new: bytes) -> bytes:
    return data[:offset] + new + data[offset + len(new):]


def test_layout_matches_spec():
    data = make_header().pack()
    assert len(data) == HEADER_LEN == 45
    assert data[0:4] == b"SCRY"
    assert (data[4], data[5], data[6], data[7]) == (1, 1, 1, 0)
    assert int.from_bytes(data[8:12], "big") == 3
    assert int.from_bytes(data[12:16], "big") == 65536
    assert data[16] == 4
    assert data[17:33] == bytes(range(16))
    assert data[33:41] == b"ABCDEFGH"
    assert int.from_bytes(data[41:45], "big") == 1024 * 1024


@pytest.mark.parametrize("cipher", list(Cipher))
def test_pack_unpack_roundtrip(cipher):
    header = make_header(cipher=cipher)
    assert Header.unpack(header.pack()) == header


@pytest.mark.parametrize("data", [b"", b"SCRY", make_header().pack()[:44]])
def test_short_header(data):
    with pytest.raises(InvalidFormatError):
        Header.unpack(data)


def test_bad_magic_and_reserved():
    data = make_header().pack()
    with pytest.raises(InvalidFormatError):
        Header.unpack(patch(data, 0, b"XXXX"))
    with pytest.raises(InvalidFormatError):
        Header.unpack(patch(data, 7, b"\x01"))


@pytest.mark.parametrize("offset", [4, 5, 6])  # versiya, cipher ID, KDF ID
def test_unknown_identifiers(offset):
    data = make_header().pack()
    with pytest.raises(UnsupportedVersionError):
        Header.unpack(patch(data, offset, b"\x09"))


@pytest.mark.parametrize("memory_kib", [2 * 1024 * 1024, 0xFFFFFFFF])
def test_huge_memory_cost_rejected(memory_kib):  # T7
    data = make_header().pack()
    with pytest.raises(UnsafeParametersError):
        Header.unpack(patch(data, 12, memory_kib.to_bytes(4, "big")))


@pytest.mark.parametrize("size", [0, MIN_CHUNK_SIZE - 1, MAX_CHUNK_SIZE + 1, 2**32 - 1])
def test_unsafe_chunk_size_rejected(size):
    data = make_header().pack()
    with pytest.raises(UnsafeParametersError):
        Header.unpack(patch(data, 41, size.to_bytes(4, "big")))
    with pytest.raises(UnsafeParametersError):
        make_header(chunk_size=size).pack()


def test_read_header_from_file(tmp_path):
    header = make_header()
    path = tmp_path / "x.scr"
    path.write_bytes(header.pack() + b"qolgan ma'lumot")
    assert read_header(path) == header
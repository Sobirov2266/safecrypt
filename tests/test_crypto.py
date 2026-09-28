import pytest

from safecrypt.crypto import (
    Cipher,
    KdfParams,
    cipher_from_id,
    decrypt_chunk,
    derive_key,
    encrypt_chunk,
    make_nonce,
    new_aead,
    random_bytes,
)
from safecrypt.errors import (
    AuthenticationError,
    UnsafeParametersError,
    UnsupportedVersionError,
)

FAST = KdfParams(time_cost=1, memory_cost=64, parallelism=1)


def test_derive_key_is_deterministic():
    salt = b"\x01" * 16
    assert derive_key(b"parol123", salt, FAST) == derive_key(b"parol123", salt, FAST)


def test_derive_key_depends_on_salt_and_password():
    k1 = derive_key(b"parol123", b"\x01" * 16, FAST)
    assert k1 != derive_key(b"parol123", b"\x02" * 16, FAST)
    assert k1 != derive_key(b"parol124", b"\x01" * 16, FAST)
    assert len(k1) == 32


def test_derive_key_accepts_bytearray():
    salt = b"\x01" * 16
    assert derive_key(bytearray(b"parol123"), salt, FAST) == derive_key(b"parol123", salt, FAST)


@pytest.mark.parametrize(
    "params",
    [
        KdfParams(time_cost=1, memory_cost=2 * 1024 * 1024, parallelism=1),  # xotira juda katta (T7)
        KdfParams(time_cost=0, memory_cost=64, parallelism=1),
        KdfParams(time_cost=1000, memory_cost=64, parallelism=1),
        KdfParams(time_cost=1, memory_cost=64, parallelism=0),
        KdfParams(time_cost=1, memory_cost=4, parallelism=1),  # 8*p dan kichik
    ],
)
def test_unsafe_params_rejected_before_kdf(params):
    with pytest.raises(UnsafeParametersError):
        derive_key(b"parol123", b"\x01" * 16, params)


@pytest.mark.parametrize("cipher", list(Cipher))
def test_encrypt_decrypt_roundtrip(cipher):
    aead = new_aead(cipher, b"k" * 32)
    nonce = make_nonce(b"p" * 8, 0)
    ct = encrypt_chunk(aead, nonce, b"salom dunyo", b"aad")
    assert len(ct) == len(b"salom dunyo") + 16
    assert decrypt_chunk(aead, nonce, ct, b"aad") == b"salom dunyo"


@pytest.mark.parametrize("cipher", list(Cipher))
def test_tampering_detected(cipher):
    aead = new_aead(cipher, b"k" * 32)
    nonce = make_nonce(b"p" * 8, 0)
    ct = bytearray(encrypt_chunk(aead, nonce, b"salom dunyo", b"aad"))
    ct[0] ^= 1
    with pytest.raises(AuthenticationError):
        decrypt_chunk(aead, nonce, bytes(ct), b"aad")


def test_wrong_aad_wrong_key_wrong_nonce_detected():
    aead = new_aead(Cipher.AES_256_GCM, b"k" * 32)
    nonce = make_nonce(b"p" * 8, 0)
    ct = encrypt_chunk(aead, nonce, b"data", b"aad")
    with pytest.raises(AuthenticationError):
        decrypt_chunk(aead, nonce, ct, b"boshqa-aad")
    with pytest.raises(AuthenticationError):
        decrypt_chunk(new_aead(Cipher.AES_256_GCM, b"x" * 32), nonce, ct, b"aad")
    with pytest.raises(AuthenticationError):
        decrypt_chunk(aead, make_nonce(b"p" * 8, 1), ct, b"aad")


def test_aes_gcm_known_vector():
    """AES-256-GCM etalon vektori (McGrew-Viega GCM spetsifikatsiyasi, Test Case 14)."""
    aead = new_aead(Cipher.AES_256_GCM, bytes(32))
    out = aead.encrypt(bytes(12), bytes(16), b"")
    assert out.hex() == (
        "cea7403d4d606b6e074ec5d3baf39d18"  # shifrmatn
        "d0d1c8a799996bf0265b98b5d48ab919"  # teg
    )


def test_make_nonce_layout():
    assert make_nonce(b"ABCDEFGH", 1) == b"ABCDEFGH\x00\x00\x00\x01"
    with pytest.raises(OverflowError):
        make_nonce(b"ABCDEFGH", 2**32)


def test_unknown_cipher_id():
    with pytest.raises(UnsupportedVersionError):
        cipher_from_id(99)


def test_random_bytes_unique():
    assert random_bytes(16) != random_bytes(16)


def test_derive_key_rejects_bad_salt_length():
    with pytest.raises(ValueError):
        derive_key(b"parol123", b"\x01" * 15, FAST)


def test_new_aead_rejects_bad_key_length():
    with pytest.raises(ValueError):
        new_aead(Cipher.AES_256_GCM, b"k" * 31)


def test_new_aead_rejects_unknown_cipher():
    with pytest.raises(UnsupportedVersionError):
        new_aead(99, b"k" * 32)


def test_make_nonce_rejects_bad_prefix_length():
    with pytest.raises(ValueError):
        make_nonce(b"short", 0)
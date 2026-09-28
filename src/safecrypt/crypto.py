"""Kriptografik o'ramlar: Argon2id (KDF) va AEAD (AES-GCM / ChaCha20-Poly1305)."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from enum import IntEnum

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from .errors import (
    AuthenticationError,
    UnsafeParametersError,
    UnsupportedVersionError,
)

KEY_LEN = 32
SALT_LEN = 16
NONCE_PREFIX_LEN = 8
NONCE_LEN = 12
TAG_LEN = 16

# Standart Argon2id parametrlari (texnik topshiriq, 5-bo'lim)
DEFAULT_TIME_COST = 3
DEFAULT_MEMORY_COST_KIB = 64 * 1024  # 64 MiB
DEFAULT_PARALLELISM = 4

# Sarlavhadan o'qilgan parametrlar uchun chegaralar (ishonchsiz kirish!)
MAX_TIME_COST = 10
MAX_MEMORY_COST_KIB = 1024 * 1024  # 1 GiB
MAX_PARALLELISM = 16


class Cipher(IntEnum):
    """Fayl sarlavhasidagi Cipher ID qiymatlari."""

    AES_256_GCM = 1
    CHACHA20_POLY1305 = 2


@dataclass(frozen=True)
class KdfParams:
    """Argon2id parametrlari."""

    time_cost: int = DEFAULT_TIME_COST
    memory_cost: int = DEFAULT_MEMORY_COST_KIB  # KiB
    parallelism: int = DEFAULT_PARALLELISM

    def validate(self) -> None:
        """Parametrlar xavfsiz chegarada ekanini tekshiradi."""
        if not 1 <= self.time_cost <= MAX_TIME_COST:
            raise UnsafeParametersError("Argon2 time_cost ruxsat etilgan oraliqdan tashqarida.")
        if not 1 <= self.parallelism <= MAX_PARALLELISM:
            raise UnsafeParametersError("Argon2 parallelism ruxsat etilgan oraliqdan tashqarida.")
        if not 8 * self.parallelism <= self.memory_cost <= MAX_MEMORY_COST_KIB:
            raise UnsafeParametersError("Argon2 memory_cost ruxsat etilgan oraliqdan tashqarida.")


def random_bytes(n: int) -> bytes:
    """Kriptografik xavfsiz tasodifiy baytlar."""
    return secrets.token_bytes(n)


def derive_key(password: bytes | bytearray, salt: bytes, params: KdfParams) -> bytes:
    """Paroldan 32 baytlik kalit hosil qiladi (Argon2id).

    Parametrlar KDF ishga tushishidan OLDIN tekshiriladi.
    """
    params.validate()
    if len(salt) != SALT_LEN:
        raise ValueError(f"Salt uzunligi {SALT_LEN} bayt bo'lishi kerak.")
    return hash_secret_raw(
        secret=bytes(password),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def cipher_from_id(cipher_id: int) -> Cipher:
    """Sarlavhadagi raqamdan algoritmni aniqlaydi."""
    try:
        return Cipher(cipher_id)
    except ValueError:
        raise UnsupportedVersionError(f"Noma'lum algoritm identifikatori: {cipher_id}") from None


def new_aead(cipher: Cipher, key: bytes) -> AESGCM | ChaCha20Poly1305:
    """Tanlangan algoritm uchun AEAD obyekti yaratadi."""
    if len(key) != KEY_LEN:
        raise ValueError(f"Kalit uzunligi {KEY_LEN} bayt bo'lishi kerak.")
    if cipher is Cipher.AES_256_GCM:
        return AESGCM(key)
    if cipher is Cipher.CHACHA20_POLY1305:
        return ChaCha20Poly1305(key)
    raise UnsupportedVersionError(f"Qo'llab-quvvatlanmaydigan algoritm: {cipher}")


def make_nonce(prefix: bytes, chunk_index: int) -> bytes:
    """nonce = prefiks (8 bayt) || bo'lak_raqami (4 bayt, big-endian)."""
    if len(prefix) != NONCE_PREFIX_LEN:
        raise ValueError(f"Nonce prefiksi {NONCE_PREFIX_LEN} bayt bo'lishi kerak.")
    if not 0 <= chunk_index < 2**32:
        raise OverflowError("Bo'lak raqami 32 bitdan oshib ketdi.")
    return prefix + chunk_index.to_bytes(4, "big")


def encrypt_chunk(
    aead: AESGCM | ChaCha20Poly1305, nonce: bytes, plaintext: bytes, aad: bytes
) -> bytes:
    """Bitta bo'lakni shifrlaydi. Natija: shifrmatn || teg (16 bayt)."""
    return aead.encrypt(nonce, plaintext, aad)


def decrypt_chunk(
    aead: AESGCM | ChaCha20Poly1305, nonce: bytes, ciphertext: bytes, aad: bytes
) -> bytes:
    """Bitta bo'lakni deshifrlaydi; teg mos kelmasa AuthenticationError."""
    try:
        return aead.decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise AuthenticationError(
            "Parol noto'g'ri yoki fayl o'zgartirilgan/buzilgan."
        ) from None
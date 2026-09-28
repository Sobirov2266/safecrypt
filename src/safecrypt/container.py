"""Shifrlangan fayl sarlavhasi (format versiyasi 1, 45 bayt, big-endian)."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from .crypto import (
    NONCE_PREFIX_LEN,
    SALT_LEN,
    Cipher,
    KdfParams,
    cipher_from_id,
)
from .errors import (
    InvalidFormatError,
    UnsafeParametersError,
    UnsupportedVersionError,
)

MAGIC = b"SCRY"
FORMAT_VERSION = 1
KDF_ARGON2ID = 1

# magic | versiya | cipher | kdf | zaxira | time | memory | parallelism | salt | nonce prefiksi | bo'lak o'lchami
_STRUCT = struct.Struct(">4sBBBBIIB16s8sI")
HEADER_LEN = _STRUCT.size  # 45

DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB
MIN_CHUNK_SIZE = 1024
# Sarlavhadagi bo'lak o'lchami ishonchsiz kirish: xotira sarfini cheklaymiz.
MAX_CHUNK_SIZE = 16 * 1024 * 1024  # 16 MiB


@dataclass(frozen=True)
class Header:
    """Shifrlangan fayl sarlavhasi."""

    cipher: Cipher
    kdf: KdfParams
    salt: bytes
    nonce_prefix: bytes
    chunk_size: int = DEFAULT_CHUNK_SIZE

    def validate(self) -> None:
        """Parametrlar xavfsiz chegarada ekanini tekshiradi."""
        if len(self.salt) != SALT_LEN or len(self.nonce_prefix) != NONCE_PREFIX_LEN:
            raise ValueError("Salt yoki nonce prefiksi uzunligi noto'g'ri.")
        self.kdf.validate()
        if not MIN_CHUNK_SIZE <= self.chunk_size <= MAX_CHUNK_SIZE:
            raise UnsafeParametersError("Bo'lak o'lchami ruxsat etilgan oraliqdan tashqarida.")

    def pack(self) -> bytes:
        """Sarlavhani 45 baytga o'rab beradi."""
        self.validate()
        return _STRUCT.pack(
            MAGIC,
            FORMAT_VERSION,
            int(self.cipher),
            KDF_ARGON2ID,
            0,
            self.kdf.time_cost,
            self.kdf.memory_cost,
            self.kdf.parallelism,
            self.salt,
            self.nonce_prefix,
            self.chunk_size,
        )

    @classmethod
    def unpack(cls, data: bytes) -> Header:
        """45 baytdan sarlavhani o'qiydi va tekshiradi (KDF ishga tushishidan oldin)."""
        if len(data) != HEADER_LEN:
            raise InvalidFormatError("Sarlavha to'liq emas.")
        (
            magic,
            version,
            cipher_id,
            kdf_id,
            reserved,
            time_cost,
            memory_cost,
            parallelism,
            salt,
            nonce_prefix,
            chunk_size,
        ) = _STRUCT.unpack(data)

        if magic != MAGIC:
            raise InvalidFormatError("Bu SafeCrypt fayli emas.")
        if version != FORMAT_VERSION:
            raise UnsupportedVersionError(f"Qo'llab-quvvatlanmaydigan format versiyasi: {version}")
        cipher = cipher_from_id(cipher_id)
        if kdf_id != KDF_ARGON2ID:
            raise UnsupportedVersionError(f"Noma'lum KDF identifikatori: {kdf_id}")
        if reserved != 0:
            raise InvalidFormatError("Sarlavha buzilgan.")

        header = cls(
            cipher=cipher,
            kdf=KdfParams(time_cost, memory_cost, parallelism),
            salt=salt,
            nonce_prefix=nonce_prefix,
            chunk_size=chunk_size,
        )
        header.validate()
        return header


def read_header(path: str | os.PathLike[str]) -> Header:
    """Fayl sarlavhasini parolsiz o'qiydi (`info` buyrug'i uchun)."""
    with open(path, "rb") as f:
        return Header.unpack(f.read(HEADER_LEN))
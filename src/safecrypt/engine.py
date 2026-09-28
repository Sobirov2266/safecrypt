"""Fayllarni bo'laklab shifrlash va deshifrlash."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

from .container import DEFAULT_CHUNK_SIZE, HEADER_LEN, Header
from .crypto import (
    NONCE_PREFIX_LEN,
    SALT_LEN,
    TAG_LEN,
    Cipher,
    KdfParams,
    decrypt_chunk,
    derive_key,
    encrypt_chunk,
    make_nonce,
    new_aead,
    random_bytes,
)
from .errors import AuthenticationError, TruncatedFileError

PathLike = str | os.PathLike[str]
ProgressCallback = Callable[[int], None]  # ishlangan (ochiq matn) baytlar soni

_FLAG_LAST = b"\x01"
_FLAG_MORE = b"\x00"


def _read_full(f: BinaryIO, n: int) -> bytes:
    """Aynan n bayt o'qiydi (faqat fayl tugaganda kamroq qaytaradi)."""
    data = f.read(n)
    if len(data) == n or not data:
        return data
    parts = [data]
    remaining = n - len(data)
    while remaining:
        part = f.read(remaining)
        if not part:
            break
        parts.append(part)
        remaining -= len(part)
    return b"".join(parts)


def _iter_chunks(f: BinaryIO, size: int) -> Iterator[tuple[bytes, bool]]:
    """(bo'lak, oxirgimi) juftliklarini beradi; xotirada ko'pi bilan 2 ta bo'lak turadi.

    Bo'sh fayl uchun bitta bo'sh oxirgi bo'lak qaytariladi.
    """
    current = _read_full(f, size)
    while True:
        nxt = _read_full(f, size) if len(current) == size else b""
        yield current, not nxt
        if not nxt:
            return
        current = nxt


def _check_paths(src: Path, dst: Path, overwrite: bool) -> None:
    if not src.is_file():
        raise FileNotFoundError(f"Fayl topilmadi: {src}")
    if dst.exists():
        if os.path.samefile(src, dst):
            raise ValueError("Kirish va chiqish fayli bir xil bo'lishi mumkin emas.")
        if not overwrite:
            raise FileExistsError(f"Chiqish fayli mavjud: {dst}")


@contextmanager
def _atomic_output(dst: Path) -> Iterator[BinaryIO]:
    """Vaqtinchalik faylga yozadi; muvaffaqiyatli tugasagina `dst` ga o'tkazadi.

    Xatolik yoki Ctrl+C bo'lsa vaqtinchalik fayl o'chiriladi.
    mkstemp POSIX da 0600 ruxsat bilan yaratadi.
    """
    fd, tmp_name = tempfile.mkstemp(dir=dst.parent, prefix=f".{dst.name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            yield f
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, dst)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def encrypt_file(
    src: PathLike,
    dst: PathLike,
    password: bytes | bytearray,
    *,
    cipher: Cipher = Cipher.AES_256_GCM,
    kdf_params: KdfParams | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overwrite: bool = False,
    progress: ProgressCallback | None = None,
) -> None:
    """`src` faylini parol bilan shifrlab, `dst` ga yozadi."""
    src_path, dst_path = Path(src), Path(dst)
    _check_paths(src_path, dst_path, overwrite)

    header = Header(
        cipher=cipher,
        kdf=kdf_params or KdfParams(),
        salt=random_bytes(SALT_LEN),
        nonce_prefix=random_bytes(NONCE_PREFIX_LEN),
        chunk_size=chunk_size,
    )
    header_bytes = header.pack()  # parametrlarni ham tekshiradi
    aead = new_aead(cipher, derive_key(password, header.salt, header.kdf))

    with open(src_path, "rb") as fin, _atomic_output(dst_path) as fout:
        fout.write(header_bytes)
        for index, (chunk, is_last) in enumerate(_iter_chunks(fin, chunk_size)):
            nonce = make_nonce(header.nonce_prefix, index)
            aad = header_bytes + (_FLAG_LAST if is_last else _FLAG_MORE)
            fout.write(encrypt_chunk(aead, nonce, chunk, aad))
            if progress:
                progress(len(chunk))


def _open_chunk(aead, nonce: bytes, chunk: bytes, header_bytes: bytes, is_last: bool) -> bytes:
    """Bo'lakni ochadi. Oxirgi bo'lak tekshiruvdan o'tmasa, fayl kesilganligini aniqlaydi."""
    flag = _FLAG_LAST if is_last else _FLAG_MORE
    try:
        return decrypt_chunk(aead, nonce, chunk, header_bytes + flag)
    except AuthenticationError:
        if is_last:
            try:  # bu bo'lak aslida "oxirgi emas" bo'lganmi?
                decrypt_chunk(aead, nonce, chunk, header_bytes + _FLAG_MORE)
            except AuthenticationError:
                pass
            else:
                raise TruncatedFileError("Fayl kesib olingan (oxirgi bo'lak yo'q).") from None
        raise


def decrypt_file(
    src: PathLike,
    dst: PathLike,
    password: bytes | bytearray,
    *,
    overwrite: bool = False,
    progress: ProgressCallback | None = None,
) -> None:
    """Shifrlangan `src` ni deshifrlab, `dst` ga yozadi."""
    src_path, dst_path = Path(src), Path(dst)
    _check_paths(src_path, dst_path, overwrite)

    with open(src_path, "rb") as fin:
        header_bytes = fin.read(HEADER_LEN)
        header = Header.unpack(header_bytes)  # KDF dan oldin tekshiruv
        aead = new_aead(header.cipher, derive_key(password, header.salt, header.kdf))

        with _atomic_output(dst_path) as fout:
            for index, (chunk, is_last) in enumerate(
                _iter_chunks(fin, header.chunk_size + TAG_LEN)
            ):
                if len(chunk) < TAG_LEN:
                    raise TruncatedFileError("Fayl kesib olingan yoki to'liq emas.")
                nonce = make_nonce(header.nonce_prefix, index)
                plain = _open_chunk(aead, nonce, chunk, header_bytes, is_last)
                fout.write(plain)
                if progress:
                    progress(len(plain))
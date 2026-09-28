"""SafeCrypt maxsus xatoliklari."""


class SafeCryptError(Exception):
    """Barcha maxsus xatoliklarning bazaviy sinfi."""

    exit_code = 1


class InvalidFormatError(SafeCryptError):
    """Magic mos kelmaydi yoki sarlavha to'liq emas."""

    exit_code = 4


class UnsupportedVersionError(SafeCryptError):
    """Format versiyasi yoki algoritm identifikatori noma'lum."""

    exit_code = 4


class UnsafeParametersError(SafeCryptError):
    """Sarlavhadagi parametrlar ruxsat etilgan chegaradan tashqarida."""

    exit_code = 4


class AuthenticationError(SafeCryptError):
    """Teg tekshiruvi muvaffaqiyatsiz: noto'g'ri parol yoki fayl o'zgartirilgan."""

    exit_code = 3


class TruncatedFileError(SafeCryptError):
    """Oxirgi bo'lak bayrog'i topilmasdan fayl tugadi."""

    exit_code = 4
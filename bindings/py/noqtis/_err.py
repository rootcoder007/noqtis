# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""The exceptions: one class per NQE* code of noqtis.h, all NoqtisError."""
from typing import Any, Dict, Tuple, Type


class NoqtisError(Exception):
    """A noqtis call failed; ``code`` is the library's NQE* code."""

    code = 0

    def __init__(self, code: int = 0, msg: str = "") -> None:
        super().__init__(msg or self.__doc__ or "noqtis error")
        self.code = code or type(self).code

    def __reduce__(self) -> Tuple[Any, Tuple[int, str]]:
        return (type(self), (self.code, str(self)))


class ArgError(NoqtisError, ValueError):
    """An argument is out of range (NQEARG)."""
    code = -1


class BufError(NoqtisError):
    """An output buffer is too small (NQEBUF)."""
    code = -2


class VerifyError(NoqtisError):
    """A signature, MAC or digest does not verify (NQEVRFY)."""
    code = -3


class DecodeError(NoqtisError, ValueError):
    """Input is not in the encoding the standard defines (NQEDEC)."""
    code = -4


class RandError(NoqtisError):
    """The operating system's random source failed (NQERNG)."""
    code = -5


class MemError(NoqtisError, MemoryError):
    """An allocation failed (NQEMEM)."""
    code = -6


class FileError(NoqtisError):
    """A file could not be read or written (NQEIO)."""
    code = -7


class UnsupportedError(NoqtisError):
    """An algorithm or option noqtis does not provide (NQENOSUP)."""
    code = -8


class LimitError(NoqtisError, ValueError):
    """Input exceeds a size or depth limit (NQELIM)."""
    code = -9


class StateError(NoqtisError):
    """A context was used out of order (NQESTATE)."""
    code = -10


ERRS: Dict[int, Type[NoqtisError]] = {
    c.code: c for c in (ArgError, BufError, VerifyError, DecodeError,
                        RandError, MemError, FileError, UnsupportedError,
                        LimitError, StateError)
}

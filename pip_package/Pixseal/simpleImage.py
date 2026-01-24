"""
Loader that prefers the Cython implementation and falls back to pure Python.
Use environment variable PIXSEAL_SIMPLEIMAGE_BACKEND to force a backend:
  - "cython": require compiled extension
  - "python": force pure Python implementation
"""

from os import getenv
from types import ModuleType
from typing import TYPE_CHECKING, cast

_backend: str = getenv("PIXSEAL_SIMPLEIMAGE_BACKEND", "auto").lower()
_impl: ModuleType

if _backend == "python":
    from . import simpleImage_py as _impl
else:
    try:
        from . import simpleImage_ext as _impl  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise ImportError("Cython backend requested but Pixseal.simpleImage_ext is not available. "
                          "Build the extension or choose the python backend.") from exc

_impl = cast(ModuleType, _impl)
if TYPE_CHECKING:
    from .simpleImage_py import ImageInput, SimpleImage
else:
    SimpleImage = _impl.SimpleImage
    ImageInput = _impl.ImageInput

print(f"[SimpleImage] Loaded from: {_impl.__name__}")

__all__: list[str] = ["SimpleImage", "ImageInput"]

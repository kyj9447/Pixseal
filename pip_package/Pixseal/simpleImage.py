"""
Loader that prefers the Cython implementation and falls back to pure Python.
Use environment variable PIXSEAL_SIMPLEIMAGE_BACKEND to force a backend:
  - "cython": require compiled extension
  - "python": force pure Python implementation
"""

from os import getenv

_backend = getenv("PIXSEAL_SIMPLEIMAGE_BACKEND", "auto").lower()

if _backend == "python":
    from .simpleImage_py import SimpleImage, ImageInput  # type: ignore
elif _backend == "cython":
    try:
        from .simpleImage_ext import SimpleImage, ImageInput  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "Cython backend requested but Pixseal.simpleImage_ext is not available. "
            "Build the extension or choose the python backend."
        ) from exc
else:
    try:  # pragma: no cover
        from .simpleImage_ext import SimpleImage, ImageInput  # type: ignore
    except ImportError:  # pragma: no cover
        from .simpleImage_py import SimpleImage, ImageInput  # type: ignore

__all__ = ["SimpleImage", "ImageInput"]

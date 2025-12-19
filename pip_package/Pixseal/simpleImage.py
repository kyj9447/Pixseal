"""
Loader that prefers the Cython implementation and falls back to pure Python.
Use environment variable PIXSEAL_SIMPLEIMAGE_BACKEND to force a backend:
  - "cython": require compiled extension
  - "python": force pure Python implementation
"""

from os import getenv

_backend = getenv("PIXSEAL_SIMPLEIMAGE_BACKEND", "auto").lower()
_loaded_module = "Pixseal.simpleImage_py"

if _backend == "python":
    from . import simpleImage_py as _impl  # type: ignore
elif _backend == "cython":
    try:
        from . import simpleImage_ext as _impl  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "Cython backend requested but Pixseal.simpleImage_ext is not available. "
            "Build the extension or choose the python backend."
        ) from exc
else:
    try:  # pragma: no cover
        from . import simpleImage_ext as _impl  # type: ignore
    except ImportError:  # pragma: no cover
        from . import simpleImage_py as _impl  # type: ignore

SimpleImage = _impl.SimpleImage  # type: ignore
ImageInput = _impl.ImageInput  # type: ignore
_loaded_module = _impl.__name__

print(f"[SimpleImage] Loaded from: {_loaded_module}")

__all__ = ["SimpleImage", "ImageInput"]

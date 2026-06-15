"""Allow ``python -m hyping.main`` from a source checkout.

The project uses a ``src/`` layout, so an uninstalled checkout normally needs
``PYTHONPATH=src``.  This small shim makes the repository root work as an import
location too, including when ``sudo`` drops the caller's environment.
"""

from pathlib import Path

_src_package = Path(__file__).resolve().parent.parent / "src" / "hyping"
if _src_package.is_dir():
    __path__.append(str(_src_package))  # type: ignore[name-defined]

del Path, _src_package

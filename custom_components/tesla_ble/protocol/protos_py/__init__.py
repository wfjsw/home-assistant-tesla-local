"""Generated protobuf Python modules.

This package imports the generated _pb2 modules and also registers
top-level names in ``sys.modules`` so that generated pb2 files which
use plain imports like ``import signatures_pb2`` will resolve when
the package is imported as ``protocol.protos_py``.
"""
from __future__ import annotations

from importlib import import_module
import sys

# List of generated modules in this package
_modules = [
    "car_server_pb2",
    "common_pb2",
    "errors_pb2",
    "keys_pb2",
    "managed_charging_pb2",
    "signatures_pb2",
    "universal_message_pb2",
    "vcsec_pb2",
    "vehicle_pb2",
]

# Import each module relatively and also register the short module name
# in sys.modules so generated code that does `import signatures_pb2`
# will find this package's module.
for _m in _modules:
    fullname = f"{__name__}.{_m}"
    try:
        mod = import_module(f".{_m}", __name__)
    except Exception:
        # Fallback: try absolute import if relative import fails
        mod = import_module(_m)
    # Expose as attribute on the package
    globals()[_m] = mod
    # Register short name so top-level imports resolve
    if _m not in sys.modules:
        sys.modules[_m] = mod

__all__ = _modules

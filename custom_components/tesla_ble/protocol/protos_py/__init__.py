"""Generated protobuf Python modules.

This package imports the generated _pb2 modules and also registers
top-level names in ``sys.modules`` so that generated pb2 files which
use plain imports like ``import signatures_pb2`` will resolve when
the package is imported as ``protocol.protos_py``.
"""
from __future__ import annotations

from importlib import import_module
import sys
from types import ModuleType

# List of generated modules in this package
__all__ = [
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

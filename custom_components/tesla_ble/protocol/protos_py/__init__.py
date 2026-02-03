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
    "tesla_car_server_pb2",
    "tesla_common_pb2",
    "tesla_errors_pb2",
    "tesla_keys_pb2",
    "tesla_managed_charging_pb2",
    "tesla_signatures_pb2",
    "tesla_universal_message_pb2",
    "tesla_vcsec_pb2",
    "tesla_vehicle_pb2",
]

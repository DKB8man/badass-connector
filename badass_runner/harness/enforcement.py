"""Compatibility imports for public enforcement wire mechanics.

The implementation lives in :mod:`badass_runner_protocol`, allowing this
runner to remain independent of the private cloud backend.
"""

from badass_runner_protocol.enforcement import (
    _denial_code,
    deserialize_enforcement_probe,
    sanitize_enforcement_observations,
)

__all__ = [
    "_denial_code",
    "deserialize_enforcement_probe",
    "sanitize_enforcement_observations",
]
"""id_scrambler - offline cleartext scrambling tool.

© 2026 Nokia
Licensed under the BSD 3-Clause License
SPDX-License-Identifier: BSD-3-Clause

The implementation lives in :mod:`id_scrambler.id_scrambler`; this package
module simply re-exports its public API so that ``id_scrambler:main`` (the
console-script entry point) and ``import id_scrambler`` keep working.
"""

from .id_scrambler import *
from .id_scrambler import __all__  # noqa: F401

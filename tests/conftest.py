"""© 2026 Nokia
Licensed under the BSD 3-Clause License
SPDX-License-Identifier: BSD-3-Clause
"""
import os
import sys

# Make the project modules (id_scrambler.py, yangpattern.py) importable.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

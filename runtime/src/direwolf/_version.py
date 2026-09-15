"""Project version.

Written by ``dwcheck version --write`` from the repository-root ``VERSION``
file; do not edit by hand.

Kept as a literal rather than read from installed distribution metadata:
``importlib.metadata`` transitively imports ``email``, which imports ``socket``.
A cognition runtime whose stated property is "no network route" should not
import the socket module to find out what version it is, and the import cost
lands on a cold start the product specification budgets in milliseconds.
"""

from __future__ import annotations

__version__ = "0.0.0"

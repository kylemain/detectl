"""detectl -- a CLI and Python library for interacting with multiple SIEM/EDR
platforms through a single, consistent interface.

Each supported platform is implemented as a self-contained adapter module
under detectl.adapters, all implementing the same abstract interface
(detectl.adapters.base.SIEMAdapter) for detection rules, tuning lists
(watchlists, exclusion/allow/block lists, suppression lists, KV stores),
alerts, and raw event queries.
"""

__version__ = "0.1.0"

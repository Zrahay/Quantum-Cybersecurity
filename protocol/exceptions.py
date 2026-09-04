"""Exceptions raised by M2. Track M2 (Shubhang).

All M2 failures derive from QDSProtocolError, so a caller in another track
can write one `except` clause and be sure it catches everything M2 throws.

`ProtocolNotSelectedError` used to live here, raised by every entry point
while the construction was undecided. P1 is now selected and implemented, so
it has been removed rather than left behind as an exception nothing can
raise. Nothing outside M2 imported it.
"""

from __future__ import annotations


class QDSProtocolError(Exception):
    """Base class for every M2 failure."""


class QuantumCoreError(QDSProtocolError):
    """The injected quantum core is unusable, or was asked for too much.

    Two distinct causes, deliberately sharing one type because the caller's
    remedy is the same -- pass a different core:

      * the object does not implement the QuantumCore interface at all
      * it implements it, but the underlying M1 primitive cannot return the
        data M2 asked for
    """

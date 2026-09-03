"""Exceptions raised by M2. Track M2 (Shubhang).

All M2 failures derive from QDSProtocolError, so a caller in another track
can write one `except` clause and be sure it catches everything M2 throws.

ProtocolNotSelectedError is the load-bearing one. The teleportation-based
QDS construction has NOT been chosen yet (see the Decision Log in Notion),
so there is no honest way to run keygen/sign/verify for real. Raising this
is how M2 says "the algorithm is missing" out loud instead of returning
plausible-looking numbers that a judge might mistake for cryptography.
"""

from __future__ import annotations


class QDSProtocolError(Exception):
    """Base class for every M2 failure."""


class ProtocolNotSelectedError(QDSProtocolError, NotImplementedError):
    """The QDS construction has not been chosen, so this cannot be done.

    Subclasses NotImplementedError as well as QDSProtocolError: callers who
    reasonably write `except NotImplementedError` around a stub still catch
    it, and `raise ProtocolNotSelectedError` reads correctly in a scaffold.

    Raised by keygen/sign/verify when QDSConfig.strict is set. It is NOT
    raised by default, because the placeholder return values are what the
    other five tracks currently integrate against -- see the module
    docstrings in signer.py and verifier.py for why that default exists.
    """


class QuantumCoreError(QDSProtocolError):
    """The injected quantum core is unusable, or was asked for too much.

    Two distinct causes, deliberately sharing one type because the caller's
    remedy is the same -- pass a different core:

      * the object does not implement the QuantumCore interface at all
      * it implements it, but the underlying M1 primitive is still a stub
        that cannot return the data M2 asked for
    """

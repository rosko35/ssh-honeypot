"""The simulated shell. Pure Python string processing, no host interaction."""

from .core import FakeShell, LineResult

__all__ = ["FakeShell", "LineResult"]

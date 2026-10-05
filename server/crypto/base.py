from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, runtime_checkable


class EnvelopeValidationError(ValueError):
    """Raised when an incoming encrypted envelope fails cipher-specific validation."""
    pass


@runtime_checkable
class CryptoAdapter(Protocol):
    """Protocol defining the actual contract implemented by InsiEDR crypto adapters."""
    scheme: str

    def decrypt(self, envelope: Mapping[str, object]) -> bytes:
        """Decrypt the cipher envelope and return decrypted JSON payload bytes."""
        ...

    def validate_envelope(self, envelope: Mapping[str, object]) -> None:
        """Validate cipher-specific required fields in the envelope."""
        ...


class BaseCryptoPlugin(ABC):
    """Abstract base class for registered crypto adapters."""
    scheme: str = "base"

    @abstractmethod
    def decrypt(self, envelope: Mapping[str, object]) -> bytes:
        raise NotImplementedError()

    def validate_envelope(self, envelope: Mapping[str, object]) -> None:
        """Default no-op envelope validation for adapters that don't need custom fields."""
        pass

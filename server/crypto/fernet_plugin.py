from __future__ import annotations

from typing import Mapping

from cryptography.fernet import Fernet, InvalidToken

from shared.crypto_utils import b64decode
from shared.protocol import CRYPTO_SCHEME_FERNET


class FernetPluginError(ValueError):
	pass


class FernetPlugin:
	scheme = CRYPTO_SCHEME_FERNET

	def __init__(self, key: bytes | str) -> None:
		self._fernet = Fernet(key.encode("ascii") if isinstance(key, str) else key)

	def validate_envelope(self, envelope: Mapping[str, object]) -> None:
		"""Validate required cipher-specific fields for Fernet."""
		if not envelope.get("token"):
			raise FernetPluginError("missing envelope field: token")

	def decrypt(self, envelope: Mapping[str, object]) -> bytes:
		if envelope.get("scheme") != self.scheme:
			raise FernetPluginError("wrong scheme")
		try:
			token = b64decode(str(envelope["token"]))
			try:
				return self._fernet.decrypt(token)
			except InvalidToken as exc:
				raise FernetPluginError("Fernet token authentication failed") from exc
		except KeyError as exc:
			raise FernetPluginError(f"missing field: {exc}") from exc


"""Unit tests for MCPClientWithAuthRetry.

Covers the M2 review-fix that prevents silent identity downgrade: when a
request already carries a forwarded end-user identity (`Authorization: Bearer
<user-jwt>`), an MCPAuthError from the server MUST be re-raised rather than
trigger the static-OAuth retry path that would silently replace the user's
identity with the provider's static client identity.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from core.mcp.auth_client import MCPClientWithAuthRetry
from core.mcp.error import MCPAuthError


class TestForwardIdentityShortCircuit:
    def test_forward_identity_active_reraises_without_retry(self):
        """When the request is identity-forwarded, a 401 from the server must
        propagate as-is — not trigger the OAuth retry that would overwrite
        the forwarded Authorization with a static client token."""
        client = MCPClientWithAuthRetry(
            server_url="https://mcp.example.com",
            headers={"Authorization": "Bearer user-jwt"},
            forward_identity_active=True,
        )

        with patch.object(client, "_has_retried", False):
            with pytest.raises(MCPAuthError):
                client._handle_auth_error(MCPAuthError("unauthorized"))

        # The forwarded Authorization header must not have been mutated.
        assert client.headers["Authorization"] == "Bearer user-jwt"
        # Retry flag must remain false — the short-circuit happens BEFORE
        # any retry bookkeeping.
        assert client._has_retried is False

    def test_forward_identity_active_takes_precedence_over_provider_entity(self):
        """Even with a provider_entity present (which would normally enable
        the retry path), forward_identity_active must short-circuit first."""
        sentinel_entity = object()
        client = MCPClientWithAuthRetry(
            server_url="https://mcp.example.com",
            provider_entity=sentinel_entity,  # type: ignore[arg-type]
            forward_identity_active=True,
        )

        with pytest.raises(MCPAuthError, match="forwarded-id-401"):
            client._handle_auth_error(MCPAuthError("forwarded-id-401"))

    def test_default_path_unchanged_without_provider_entity(self):
        """Backwards-compat: a client with neither forwarding nor a provider
        entity still raises immediately (legacy behavior)."""
        client = MCPClientWithAuthRetry(server_url="https://mcp.example.com")
        with pytest.raises(MCPAuthError, match="no-provider"):
            client._handle_auth_error(MCPAuthError("no-provider"))

    def test_default_constructor_defaults_forward_identity_to_false(self):
        """A client constructed without the new kwarg must default to False
        so existing callers see no behavior change."""
        client = MCPClientWithAuthRetry(server_url="https://mcp.example.com")
        assert client.forward_identity_active is False

"""Privacy tests: caller identity must not survive into feature output."""

from __future__ import annotations

from ng911_sip.privacy import Pseudonymiser


def test_tokens_are_stable_and_not_the_input(pseudonymiser):
    first = pseudonymiser.token("+15551234567")
    assert first == pseudonymiser.token("+15551234567")
    assert "5551234567" not in first
    assert len(first) == 16


def test_different_callers_get_different_tokens(pseudonymiser):
    assert pseudonymiser.token("+15551234567") != pseudonymiser.token("+15557654321")


def test_a_different_key_gives_different_tokens():
    a = Pseudonymiser(key=b"key-one")
    b = Pseudonymiser(key=b"key-two")
    assert a.token("+15551234567") != b.token("+15551234567")


def test_sip_uri_splits_into_hashed_user_and_clear_host(pseudonymiser):
    user, host = pseudonymiser.split_uri('"Caller" <sip:+15551234567@carrier.example>;tag=9')
    assert user == pseudonymiser.token("+15551234567")
    assert host == "carrier.example"  # infrastructure stays readable


def test_tel_uri_is_handled(pseudonymiser):
    user, _ = pseudonymiser.split_uri("<tel:+15551234567>")
    assert user is not None
    assert "5551234567" not in user


def test_service_urn_is_kept_verbatim(pseudonymiser):
    """urn:service:sos names a service, not a person, and must stay readable."""
    user, host = pseudonymiser.split_uri("<urn:service:sos>")
    assert user is None
    assert host == "urn:service:sos"


def test_sub_service_urn_is_kept(pseudonymiser):
    _, host = pseudonymiser.split_uri("<urn:service:sos.police>")
    assert host == "urn:service:sos.police"


def test_other_urn_namespaces_are_hashed(pseudonymiser):
    """urn:emergency:uid:callid:... embeds an incident identifier."""
    user, host = pseudonymiser.split_uri(
        "<urn:emergency:uid:callid:ABC123DEF456:example.com>;purpose=emergency-CallId"
    )
    assert host == "urn:emergency"
    assert user is not None
    assert "ABC123DEF456".lower() not in user.lower()


def test_missing_and_empty_values(pseudonymiser):
    assert pseudonymiser.token(None) is None
    assert pseudonymiser.token("   ") is None
    assert pseudonymiser.split_uri(None) == (None, None)
    assert pseudonymiser.split_uri("garbage with no uri") == (None, None)


def test_disabling_is_explicit_and_returns_the_original():
    """Opting out must be a deliberate act, used only on synthetic traffic."""
    plain = Pseudonymiser(key=b"k", enabled=False)
    assert plain.token("+15551234567") == "+15551234567"

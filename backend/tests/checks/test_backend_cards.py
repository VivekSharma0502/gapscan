"""Which card a backend appears on depends on whether it was confirmed and tested."""

from typing import Any

import pytest

from app.checks.baas import backends_found, backends_tested, backends_unanswered
from app.checks.base import (
    BaasDiscovery,
    BaasKind,
    BaasProbes,
    DiscoveredBackend,
    RtdbProbe,
    ScanContext,
    Severity,
    StorageProbe,
    SupabaseProbe,
    TableAccess,
    TableProbe,
)
from app.checks.catalog import CATALOG

HOST = "my-app-default-rtdb.firebaseio.com"
BUCKET = "my-app.appspot.com"
REF = "abcdefghijklmnopqrst"
RTDB = DiscoveredBackend(BaasKind.FIREBASE_RTDB, HOST)
STORAGE = DiscoveredBackend(BaasKind.FIREBASE_STORAGE, BUCKET)
SUPABASE = DiscoveredBackend(BaasKind.SUPABASE, REF)


def scan(*backends: DiscoveredBackend, probes: BaasProbes | None = None) -> ScanContext:
    return ScanContext(
        hostname="example.com",
        baas=BaasDiscovery(backends, (), 2, 2, 0),
        baas_probes=probes,
    )


def cards(ctx: ScanContext) -> dict[str, Any]:
    results = {
        "found": backends_found(ctx),
        "tested": backends_tested(ctx),
        "unanswered": backends_unanswered(ctx),
    }
    return {name: card for name, card in results.items() if card is not None}


def test_unconfirmed_backend_keeps_the_original_card() -> None:
    result = cards(scan(RTDB, probes=BaasProbes()))

    assert set(result) == {"found"}
    assert HOST in result["found"].evidence
    assert "hasn't tested" in result["found"].fix.what_it_means


def test_no_probe_step_counts_as_unconfirmed() -> None:
    assert set(cards(scan(RTDB))) == {"found"}


@pytest.mark.parametrize(
    "probes",
    [
        BaasProbes(rtdb=(RtdbProbe(HOST, False),)),
        BaasProbes(rtdb=(RtdbProbe(HOST, True, 3),)),
    ],
)
def test_confirmed_and_answered_database_is_tested(probes: BaasProbes) -> None:
    result = cards(scan(RTDB, probes=probes))

    assert set(result) == {"tested"}
    assert result["tested"].severity is Severity.INFO
    assert HOST in result["tested"].evidence


def test_the_tested_card_says_yours_read_only_and_points_to_results() -> None:
    fix = CATALOG["baas.backends_tested"].fix

    assert "yours" in fix.what_it_means
    assert "read-only" in fix.what_it_means
    assert '"Checked:"' in fix.how_to_fix
    assert "hasn't tested" not in fix.what_it_means


def test_tested_storage_bucket() -> None:
    result = cards(scan(STORAGE, probes=BaasProbes(storage=(StorageProbe(BUCKET, False),))))

    assert set(result) == {"tested"}


@pytest.mark.parametrize("access", [TableAccess.READABLE, TableAccess.NO_ROWS, TableAccess.REFUSED])
def test_supabase_with_a_real_table_answer_is_tested(access: TableAccess) -> None:
    probes = BaasProbes(supabase=(SupabaseProbe(REF, (TableProbe("todos", access),)),))

    assert set(cards(scan(SUPABASE, probes=probes))) == {"tested"}


def test_one_real_table_answer_is_enough() -> None:
    tables = (TableProbe("a", TableAccess.UNKNOWN), TableProbe("b", TableAccess.REFUSED))
    probes = BaasProbes(supabase=(SupabaseProbe(REF, tables),))

    assert set(cards(scan(SUPABASE, probes=probes))) == {"tested"}


@pytest.mark.parametrize(
    ("backend", "probes"),
    [
        (RTDB, BaasProbes(rtdb=(RtdbProbe(HOST, None),))),
        (STORAGE, BaasProbes(storage=(StorageProbe(BUCKET, None),))),
        (SUPABASE, BaasProbes(supabase=(SupabaseProbe(REF, has_key=False),))),
        (SUPABASE, BaasProbes(supabase=(SupabaseProbe(REF),))),
        (
            SUPABASE,
            BaasProbes(supabase=(SupabaseProbe(REF, (TableProbe("x", TableAccess.UNKNOWN),)),)),
        ),
        (
            SUPABASE,
            BaasProbes(supabase=(SupabaseProbe(REF, (TableProbe("x", TableAccess.NOT_FOUND),)),)),
        ),
    ],
)
def test_confirmed_without_a_real_answer_is_never_called_tested(
    backend: DiscoveredBackend, probes: BaasProbes
) -> None:
    result = cards(scan(backend, probes=probes))

    assert set(result) == {"unanswered"}
    assert "confirmed" in result["unanswered"].fix.what_it_means


def test_each_backend_appears_on_exactly_one_card() -> None:
    probes = BaasProbes(rtdb=(RtdbProbe(HOST, False),), storage=(StorageProbe(BUCKET, None),))

    result = cards(scan(RTDB, STORAGE, SUPABASE, probes=probes))

    assert set(result) == {"found", "tested", "unanswered"}
    assert HOST in result["tested"].evidence
    assert HOST not in result["found"].evidence
    assert BUCKET in result["unanswered"].evidence
    assert BUCKET not in result["tested"].evidence
    assert REF in result["found"].evidence
    assert REF not in result["tested"].evidence


def test_no_backends_means_no_cards() -> None:
    assert cards(scan(probes=BaasProbes())) == {}


def test_every_card_reports_script_coverage() -> None:
    result = cards(scan(RTDB, probes=BaasProbes(rtdb=(RtdbProbe(HOST, False),))))

    assert "Read 2 of 2 scripts." in result["tested"].evidence


def test_all_three_cards_have_their_own_text() -> None:
    ids = ("baas.backends_found", "baas.backends_tested", "baas.backends_unanswered")

    assert len({CATALOG[item].title for item in ids}) == 3
    assert len({CATALOG[item].fix.what_it_means for item in ids}) == 3

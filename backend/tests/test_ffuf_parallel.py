"""Tests for the bounded parallel FFUF scheduler."""

from app.providers.ffuf_provider import FfufProvider


def test_ffuf_defaults():
    opts = FfufProvider.normalize_ffuf_options({})
    assert opts["enabled"] is True
    assert opts["concurrency"] == 1
    assert opts["rate_strategy"] == "split"


def test_ffuf_options_clamped_and_validated():
    opts = FfufProvider.normalize_ffuf_options({
        "concurrency": 999,
        "rate_strategy": "nonsense",
    })
    assert opts["concurrency"] == 10
    assert opts["rate_strategy"] == "split"

    opts = FfufProvider.normalize_ffuf_options({"concurrency": 0})
    assert opts["concurrency"] == 1


def test_split_rate_keeps_aggregate_budget():
    workers, per_worker, aggregate = FfufProvider.plan_ffuf_rate(10, 3, "split", 11)
    assert workers == 3
    assert per_worker == 3
    assert aggregate == 9
    assert aggregate <= 10


def test_per_worker_rate_multiplies_aggregate():
    workers, per_worker, aggregate = FfufProvider.plan_ffuf_rate(10, 3, "per_worker", 11)
    assert workers == 3
    assert per_worker == 10
    assert aggregate == 30


def test_worker_count_cannot_exceed_targets():
    workers, per_worker, aggregate = FfufProvider.plan_ffuf_rate(10, 5, "split", 2)
    assert workers == 2
    assert per_worker == 5
    assert aggregate == 10


def test_split_rate_never_zero():
    workers, per_worker, aggregate = FfufProvider.plan_ffuf_rate(2, 5, "split", 10)
    assert workers == 5
    assert per_worker == 1
    assert aggregate == 5

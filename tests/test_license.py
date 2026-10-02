"""Tests for the trial license seam (v0.1: notice only, no enforcement)."""

import io
import json
from datetime import datetime, timedelta, timezone

import pytest

from aegisforge.core.license import (
    LicenseExpiredError,
    TrialStatus,
    print_trial_notice,
    trial_status,
    validate_license_key,
)


def _now():
    return datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)


def test_first_run_records_timestamp_and_starts_trial(tmp_path):
    status = trial_status(directory=tmp_path, now=_now())
    assert status.days_remaining == 7
    assert status.licensed is False
    assert status.expired is False
    record = json.loads((tmp_path / "trial.json").read_text(encoding="utf-8"))
    assert record["first_run"].endswith("Z")


def test_second_run_same_trial(tmp_path):
    first = trial_status(directory=tmp_path, now=_now())
    second = trial_status(directory=tmp_path, now=_now() + timedelta(hours=3))
    assert second.days_remaining == 7
    assert second.first_run == first.first_run


def test_days_remaining_counts_down(tmp_path):
    trial_status(directory=tmp_path, now=_now())
    status = trial_status(directory=tmp_path, now=_now() + timedelta(days=3, hours=1))
    assert status.days_remaining == 4
    assert status.expired is False


def test_expiry_path_sets_expired_without_raising(tmp_path):
    trial_status(directory=tmp_path, now=_now())
    status = trial_status(directory=tmp_path, now=_now() + timedelta(days=8))
    assert status.expired is True
    assert status.days_remaining == 0
    assert "commercial license" in status.message
    # v0.1: no exception is raised by trial_status itself.


def test_exactly_seven_days_is_expired(tmp_path):
    trial_status(directory=tmp_path, now=_now())
    status = trial_status(directory=tmp_path, now=_now() + timedelta(days=7))
    assert status.expired is True


def test_license_key_file_counts_as_licensed(tmp_path):
    trial_status(directory=tmp_path, now=_now())
    (tmp_path / "license.key").write_text("purchased-key", encoding="utf-8")
    status = trial_status(directory=tmp_path, now=_now() + timedelta(days=30))
    assert status.licensed is True
    assert status.expired is False


def test_corrupt_trial_file_restarts_trial(tmp_path):
    (tmp_path / "trial.json").write_text("{broken", encoding="utf-8")
    status = trial_status(directory=tmp_path, now=_now())
    assert status.days_remaining == 7
    assert status.expired is False


def test_bypass_env(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGISFORGE_NO_TRIAL_CHECK", "1")
    status = trial_status(directory=tmp_path, now=_now())
    assert status.days_remaining == 7
    assert "bypassed" in status.message


def test_print_trial_notice_remaining_days():
    buf = io.StringIO()
    print_trial_notice(TrialStatus(5, False, False, None, "x"), stream=buf)
    assert "5 day(s)" in buf.getvalue()


def test_print_trial_notice_expired():
    buf = io.StringIO()
    print_trial_notice(TrialStatus(0, False, True, None, "x"), stream=buf)
    assert "ended" in buf.getvalue()


def test_print_trial_notice_silent_when_licensed():
    buf = io.StringIO()
    print_trial_notice(TrialStatus(7, True, False, None, "x"), stream=buf)
    assert buf.getvalue() == ""


def test_print_trial_notice_never_raises():
    class BadStream:
        def write(self, _):
            raise OSError("nope")

        def flush(self):
            pass

    print_trial_notice(TrialStatus(3, False, False, None, "x"), stream=BadStream())


def test_validate_license_key_is_dormant_stub():
    with pytest.raises(NotImplementedError, match="not active in v0.1"):
        validate_license_key("anything")


def test_license_expired_error_exists_for_future_use():
    assert issubclass(LicenseExpiredError, Exception)

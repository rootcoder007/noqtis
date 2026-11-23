# SPDX-License-Identifier: LGPL-3.0-or-later
"""The known-answer self-test and the errors it and signing add."""
import noqtis


def test_selftest():
    assert noqtis.selftest() is None


def test_errors():
    assert noqtis.SelfTestError(0).code == -12
    assert noqtis.StopError(0).code == -13
    assert noqtis.FaultError(0).code == -11
    assert issubclass(noqtis.SelfTestError, noqtis.NoqtisError)
    assert "selftest" in noqtis.__all__

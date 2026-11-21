# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""The notice of a newer release: no test asks the network."""

from noqtis import _upd


def test_the_version_in_the_answer():
    assert _upd.parse("https://github.com/a/noqtis/releases/tag/v1.20.3") == "1.20.3"
    assert _upd.parse("https://github.com/a/noqtis/releases/tag/v1.2;rm") is None
    assert _upd.parse("https://github.com/a/noqtis/releases") is None
    assert _upd.parse(None) is None
    assert _upd.key("0.10.0") > _upd.key("0.9.9")
    assert _upd.key("1.0") < _upd.key("1.0.1")


def test_off_in_a_script_and_by_the_variable(monkeypatch):
    monkeypatch.delenv("NOQTIS_NO_UPDATE_CHECK", raising=False)
    monkeypatch.delenv("NOQTIS_UPDATE_CHECK", raising=False)
    # nothing is asked unless it is asked for
    assert _upd.off(False)
    assert _upd.off(True)
    monkeypatch.setenv("NOQTIS_UPDATE_CHECK", "1")
    assert not _upd.off(True)
    assert _upd.off(False)
    monkeypatch.setenv("NOQTIS_NO_UPDATE_CHECK", "1")
    assert _upd.off(True)


def test_the_kept_answer_and_the_day(tmp_path):
    f = str(tmp_path / "sub" / "update")
    asked = []
    ask = lambda: asked.append(1)  # noqa: E731
    # nothing kept: asked, and no notice yet
    assert _upd.message("0.1.9", f, 1000000.0, ask) is None
    assert len(asked) == 1
    _upd.write(f, 1000000.0, "0.2.0")
    with open(f) as h:
        assert h.read() == "1000000 0.2.0\n"
    m = _upd.message("0.1.9", f, 1000000.0 + 86399, ask)
    assert m.startswith("noqtis 0.2.0 is available (this is 0.1.9): https://github.com/")
    assert m.endswith("NOQTIS_NO_UPDATE_CHECK=1 stops this notice.")
    assert len(asked) == 1
    # the same or a later installed version: nothing
    assert _upd.message("0.2.0", f, 1000500.0, ask) is None
    assert _upd.message("0.10.0", f, 1000500.0, ask) is None
    # after a day, and with a clock set back, it is asked again
    assert _upd.message("0.1.9", f, 1000000.0 + 86400, ask) == m
    assert _upd.message("0.1.9", f, 5.0, ask) == m
    assert len(asked) == 3
    # no answer is kept as none; anything else in the file is never shown
    _upd.write(f, 3000000.0, None)
    assert _upd.read(f) == (3000000.0, None)
    with open(f, "w") as h:
        h.write("3000000 9;import os\n")
    assert _upd.message("0.1.9", f, 3000001.0, ask) is None
    with open(f, "w") as h:
        h.write("junk\n")
    assert _upd.read(f) == (0.0, None)
    # a place that cannot be written is left alone
    _upd.write(str(tmp_path / "sub" / "update" / "under-a-file"), 1.0, "1.0")


def test_import_in_a_script_says_nothing(capsys, monkeypatch):
    def never(timeout=2.0):
        raise AssertionError("asked")

    monkeypatch.setattr(_upd, "latest", never)
    _upd.notify("0.0.1")
    assert capsys.readouterr().err == ""

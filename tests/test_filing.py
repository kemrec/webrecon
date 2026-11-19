import os
from webrecon import utils


def test_target_slug():
    assert utils.target_slug("http://10.0.0.5:8080/app") == "10.0.0.5_8080"
    assert utils.target_slug("https://example.com/a/b?x=1") == "example.com"
    assert utils.target_slug("10.0.0.0/24") == "10.0.0.0_24"
    assert utils.target_slug("scanme.nmap.org") == "scanme.nmap.org"
    assert utils.target_slug("") == "scan"


def test_run_dir_layout(tmp_path):
    base = str(tmp_path / "out")
    d1 = utils.run_dir(base, "http://10.0.0.5/")
    assert os.path.isdir(d1)
    # <base>/10.0.0.5/<timestamp>
    assert os.path.basename(os.path.dirname(d1)) == "10.0.0.5"
    link = os.path.join(base, "10.0.0.5", "latest")
    assert os.path.islink(link)
    assert os.path.realpath(link) == os.path.realpath(d1)


def test_run_dir_never_overwrites(tmp_path):
    base = str(tmp_path / "out")
    a = utils.run_dir(base, "10.0.0.5")
    b = utils.run_dir(base, "10.0.0.5")
    assert a != b                      # second run gets its own directory
    # latest points at the most recent
    link = os.path.join(base, "10.0.0.5", "latest")
    assert os.path.realpath(link) == os.path.realpath(b)


def test_run_dir_flat(tmp_path):
    base = str(tmp_path / "flat")
    d = utils.run_dir(base, "10.0.0.5", flat=True)
    assert d == base
    assert os.path.isdir(base)

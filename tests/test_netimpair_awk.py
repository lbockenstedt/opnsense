"""The Network Impairment plugin's awk adds latency/loss to dnctl pipe lines."""
import pathlib
import shutil
import subprocess

import pytest

AWK = pathlib.Path(__file__).parent.parent / "plugin/netimpair/src/opnsense/scripts/OPNsense/NetImpair/impair.awk"

RULES = """\
# define dummynet pipes
pipe 10000 config bw 100Mbit/s delay 20  type  wf2q+
pipe 10001 config bw 50Mbit/s type  fq_codel  noecn
pipe 10002 config bw 10Mbit/s type  wf2q+
queue 10000 config pipe 10000 weight 100
"""


@pytest.mark.skipif(not shutil.which("awk"), reason="needs awk")
def test_adds_delay_and_loss_only_to_listed_pipes(tmp_path):
    conf = tmp_path / "netimpair.conf"
    conf.write_text("10000 150 0.0250\n10001 - 0.1000\n")
    rules = tmp_path / "dnctl.conf"
    rules.write_text(RULES)

    out = subprocess.run(["awk", "-f", str(AWK), str(conf), str(rules)],
                         capture_output=True, text=True, check=True).stdout.splitlines()

    # pipe delay replaced (not duplicated), loss added
    assert out[1].split() == "pipe 10000 config bw 100Mbit/s type wf2q+ delay 150 plr 0.0250".split()
    # "-" keeps the pipe's own delay
    assert out[2].split() == "pipe 10001 config bw 50Mbit/s type fq_codel noecn plr 0.1000".split()
    # pipes and queues not listed are untouched
    assert out[3] == "pipe 10002 config bw 10Mbit/s type  wf2q+"
    assert out[4] == "queue 10000 config pipe 10000 weight 100"

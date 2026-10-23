import unittest
import importlib.util, os

# Load the main file by path (its name contains a dot, so a normal import won't work)
_spec = importlib.util.spec_from_file_location(
    "ssh_analyzer", os.path.join(os.path.dirname(os.path.abspath(__file__)), "Adith.O_SSHLogAnalyzer.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
parse_log, analyze = _mod.parse_log, _mod.analyze

BRUTE = [
    f"Oct 22 03:14:{s:02d} srv sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2"
    for s in range(0, 12, 2)
]
SUCCESS = ["Oct 22 03:14:20 srv sshd[1]: Accepted password for root from 203.0.113.5 port 1 ssh2"]


def run(lines, **kw):
    return analyze(parse_log(lines, year=2026), **kw)


class TestAnalyzer(unittest.TestCase):
    def test_detects_brute_force(self):
        f = run(BRUTE, threshold=5, window=300)
        self.assertEqual(len(f["brute_force"]), 1)
        self.assertEqual(f["brute_force"][0]["ip"], "203.0.113.5")

    def test_below_threshold_not_flagged(self):
        f = run(BRUTE[:3], threshold=5)
        self.assertEqual(f["brute_force"], [])

    def test_slow_attempts_outside_window_not_flagged(self):
        slow = [
            f"Oct 22 {h:02d}:00:00 srv sshd[1]: Failed password for bob from 192.0.2.1 port 1 ssh2"
            for h in range(1, 8)
        ]
        self.assertEqual(run(slow, threshold=5, window=300)["brute_force"], [])

    def test_compromise_after_failures(self):
        f = run(BRUTE + SUCCESS)
        self.assertEqual(len(f["possible_compromise"]), 1)
        self.assertEqual(f["possible_compromise"][0]["severity"], "CRITICAL")

    def test_normal_login_not_flagged(self):
        f = run(SUCCESS)
        self.assertEqual(f["possible_compromise"], [])

    def test_user_enumeration(self):
        lines = [
            f"Oct 22 03:00:0{i} srv sshd[1]: Invalid user u{i} from 192.0.2.9 port 1"
            for i in range(4)
        ]
        self.assertEqual(len(run(lines)["user_enumeration"]), 1)

    def test_ignores_garbage_lines(self):
        self.assertEqual(list(parse_log(["not a log line", ""], year=2026)), [])


if __name__ == "__main__":
    unittest.main()

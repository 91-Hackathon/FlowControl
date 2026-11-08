"""Session budget and lifetime (threat model category 6).

Run with: python3 -m unittest discover -t . -s tests
"""
import time
import unittest

from gateway.session import Session


class BudgetTests(unittest.TestCase):
    def test_exactly_max_requests_are_served(self):
        s = Session()
        served = 0
        for _ in range(10):
            if s.over_budget(4, 0):  # checked before counting, as the server does
                break
            s.count_model_request()
            served += 1
        self.assertEqual(served, 4)
        self.assertEqual(s.over_budget(4, 0)[0], "budget")

    def test_zero_means_no_limit(self):
        s = Session()
        for _ in range(50):
            s.count_model_request()
        self.assertIsNone(s.over_budget(0, 0))

    def test_lifetime(self):
        s = Session()
        self.assertIsNone(s.over_budget(0, 60))
        s.started_at = time.monotonic() - 61
        self.assertEqual(s.over_budget(0, 60)[0], "ttl")


if __name__ == "__main__":
    unittest.main()

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from pricing import total_with_fee  # noqa: E402


class PricingTests(unittest.TestCase):
    def test_fee(self):
        self.assertAlmostEqual(total_with_fee([10, 10], 0.05), 21.0)


if __name__ == "__main__":
    unittest.main()

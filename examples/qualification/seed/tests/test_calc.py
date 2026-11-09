"""Unit tests for calculator product fixture."""
import unittest
from src.calc import add, multiply


class CalcTest(unittest.TestCase):
    def test_add(self) -> None:
        self.assertEqual(add(2, 3), 5)

    def test_multiply(self) -> None:
        self.assertEqual(multiply(3, 4), 12)


if __name__ == "__main__":
    unittest.main()

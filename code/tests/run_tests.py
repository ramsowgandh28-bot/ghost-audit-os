"""Unified test runner for Stage 1 and Stage 2 automated tests."""

import os
import sys
import unittest

sys.stdout.reconfigure(encoding='utf-8')

test_dir = os.path.dirname(os.path.abspath(__file__))
code_dir = os.path.dirname(test_dir)
sys.path.insert(0, code_dir)

loader = unittest.TestLoader()
suite = loader.discover(start_dir=test_dir, pattern="test_*.py")

print("=" * 70)
print("HACKERRANK ORCHESTRATE — GHOST DATA STILL EXISTS")
print("AUTOMATED TEST SUITE (STAGE 1 & STAGE 2)")
print("=" * 70)

runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)

print("\n" + "=" * 70)
print(f"Tests run: {result.testsRun}")
print(f"Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
print(f"Failures: {len(result.failures)}")
print(f"Errors: {len(result.errors)}")
print("=" * 70)

sys.exit(0 if result.wasSuccessful() else 1)

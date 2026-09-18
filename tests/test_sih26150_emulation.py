from __future__ import annotations

import unittest

from tools.sih26150_emulation import run


class SIH26150EmulationTests(unittest.TestCase):
    def test_controlled_recorder_image_runs_the_full_preservation_pipeline(self):
        result = run()
        self.assertEqual(result["vendor"], "dahua")
        self.assertEqual(result["normal_segments"], 3)
        self.assertGreater(result["payload_bytes"], 20)
        self.assertIn(result["analytics_object_status"], {"not_configured", "unsupported"})
        self.assertTrue(result["chain_valid"])
        self.assertGreaterEqual(result["chain_events"], 10)


if __name__ == "__main__":
    unittest.main()

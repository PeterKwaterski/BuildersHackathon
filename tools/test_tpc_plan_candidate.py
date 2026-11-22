from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))

import selector
from verify_prospective_executor_memo import module_signature, state_signature


class TpcPlanCandidateTests(unittest.TestCase):
    def test_public_multi_statement_and_boolean_control_edits_are_rejected(self) -> None:
        self.assertFalse(
            selector.tpc_plan_patch_eligible(ROOT / "sample/commits/2jrq.patch")
        )

    def test_public_single_literal_edit_is_admitted(self) -> None:
        self.assertTrue(
            selector.tpc_plan_patch_eligible(ROOT / "sample/commits/5y72.patch")
        )

    def test_state_signature_observes_mapping_replacement(self) -> None:
        state = {"ABS": abs, "ROUND": round}
        before = state_signature(state)
        state["ABS"] = round
        self.assertNotEqual(before, state_signature(state))

    def test_module_signature_observes_new_persistent_binding(self) -> None:
        class Module:
            pass

        module = Module()
        module.__dict__["safe"] = 1
        before = module_signature(module)
        module.__dict__["armed"] = True
        self.assertNotEqual(before, module_signature(module))


if __name__ == "__main__":
    unittest.main()

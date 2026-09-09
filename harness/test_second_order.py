"""Tests for second-order confirmation (V22 SQLi, V17 IDOR) + the chaining
composition rules that identify the plant->trigger (A,B) candidate pairs."""
import asyncio
import unittest

import second_order
import chaining


# --- V22: second-order SQLi boolean differential -----------------------------

class SecondOrderSqliTests(unittest.TestCase):
    def test_confirms_when_read_depends_on_planted_boolean(self):
        """A vulnerable B: the stored value is concatenated into a query, so the
        TRUE marker returns rows and the FALSE marker returns nothing."""
        stored = {"v": ""}

        async def plant(val):
            stored["v"] = val

        async def trigger():
            # simulate: B builds  SELECT ... WHERE note='<stored>'
            # TRUE marker -> the OR makes the whole set match -> many rows;
            # FALSE marker -> nothing matches -> empty.
            if stored["v"].endswith("'1'='1"):
                return "row1 alice\nrow2 bob\nrow3 carol\nrow4 dave"
            return ""

        res = asyncio.run(second_order.confirm_second_order_sqli(plant=plant, trigger=trigger))
        self.assertTrue(res.confirmed, res.evidence)

    def test_not_confirmed_when_read_is_inert(self):
        """A safe B: the stored value is parameterised, so B's response is
        identical regardless of the planted boolean."""
        stored = {"v": ""}

        async def plant(val):
            stored["v"] = val

        async def trigger():
            return "static content, same every time"

        res = asyncio.run(second_order.confirm_second_order_sqli(plant=plant, trigger=trigger))
        self.assertFalse(res.confirmed, res.evidence)

    def test_reset_called_between_plants(self):
        calls = {"reset": 0, "plant": 0}

        async def plant(val):
            calls["plant"] += 1

        async def trigger():
            return "same"

        async def reset():
            calls["reset"] += 1

        asyncio.run(second_order.confirm_second_order_sqli(plant=plant, trigger=trigger, reset=reset))
        self.assertEqual(calls["plant"], 2)
        self.assertEqual(calls["reset"], 2)


# --- V17: second-order IDOR (plant as id1, read as id2) ----------------------

class SecondOrderIdorTests(unittest.TestCase):
    def test_confirms_cross_identity_read_of_planted_object(self):
        store = {"obj": ""}

        async def plant(marker):
            store["obj"] = marker  # identity 1 stores it

        async def read_as_other():
            return f"here is the object: {store['obj']}"  # identity 2 sees it -> IDOR

        res = asyncio.run(second_order.confirm_second_order_idor(
            plant=plant, read_as_other=read_as_other))
        self.assertTrue(res.confirmed, res.evidence)

    def test_not_confirmed_when_scoped(self):
        store = {"obj": ""}

        async def plant(marker):
            store["obj"] = marker

        async def read_as_other():
            return "403 forbidden -- not your object"  # properly scoped

        res = asyncio.run(second_order.confirm_second_order_idor(
            plant=plant, read_as_other=read_as_other))
        self.assertFalse(res.confirmed, res.evidence)


# --- composition rules that surface the (A,B) candidate --------------------

class CompositionRuleTests(unittest.TestCase):
    def _detect(self, findings):
        return {f.vulnerability_class for f in chaining.detect(findings)}

    def test_second_order_sqli_chain_composed(self):
        findings = [
            {"url": "https://t.test/api/profile", "vulnerability_class": "mass_assignment",
             "severity": "medium", "confidence": 0.6, "summary": "stored input persists"},
            {"url": "https://t.test/api/search", "vulnerability_class": "sqli",
             "severity": "high", "confidence": 0.6, "summary": "sqli suspected"},
        ]
        sigs = self._detect(findings)
        self.assertIn("potential-attack-chain:second_order_sqli", sigs)

    def test_second_order_idor_chain_composed(self):
        findings = [
            {"url": "https://t.test/api/comments", "vulnerability_class": "stored xss",
             "severity": "medium", "confidence": 0.6, "summary": "stored comment"},
            {"url": "https://t.test/api/tickets/1", "vulnerability_class": "idor",
             "severity": "high", "confidence": 0.6, "summary": "object reachable cross-identity"},
        ]
        sigs = self._detect(findings)
        self.assertIn("potential-attack-chain:second_order_idor", sigs)

    def test_no_second_order_chain_without_a_write(self):
        findings = [
            {"url": "https://t.test/api/search", "vulnerability_class": "sqli",
             "severity": "high", "confidence": 0.6, "summary": "sqli"},
        ]
        sigs = self._detect(findings)
        self.assertNotIn("potential-attack-chain:second_order_sqli", sigs)


if __name__ == "__main__":
    unittest.main()

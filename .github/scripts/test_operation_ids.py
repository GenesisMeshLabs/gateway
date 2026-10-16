"""The operation ID check's own cases: python3 .github/scripts/test_operation_ids.py"""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from operation_ids import allowed, incompatibilities  # noqa: E402

OP = {"id": "grants-get-grant", "group": "evidence_store", "method": "GET", "admin": False,
      "parameters": ["grant_id"], "query": ["include"]}


def catalog(*ops):
    return {op["id"]: op for op in ops}


def changed(**fields):
    op = copy.deepcopy(OP)
    op.update(fields)
    return op


class OperationIds(unittest.TestCase):
    def check(self, head, base=None):
        released = catalog(OP)
        return incompatibilities(released, base if base is not None else released, head)

    def test_unchanged_and_additions_pass(self):
        self.assertEqual(self.check(catalog(OP)), [])
        extra = changed(id="grants-list-grants", parameters=[])
        self.assertEqual(self.check(catalog(OP, extra)), [])
        self.assertEqual(self.check(catalog(changed(query=["include", "limit"]))), [])
        self.assertEqual(self.check(catalog(changed(description="new words"))), [])

    def test_removal_and_rename_fail(self):
        self.assertEqual(self.check({}), ["grants-get-grant: removed"])
        renamed = changed(id="grants-read-grant")
        self.assertEqual(self.check(catalog(renamed)), ["grants-get-grant: removed"])

    def test_incompatible_changes_fail(self):
        self.assertEqual(self.check(catalog(changed(method="POST"))),
                         ["grants-get-grant: method GET -> POST"])
        self.assertEqual(self.check(catalog(changed(group="administration"))),
                         ["grants-get-grant: service group evidence_store -> administration"])
        self.assertEqual(self.check(catalog(changed(admin=True))),
                         ["grants-get-grant: now an operator (admin) operation"])
        self.assertEqual(self.check(catalog(changed(query=[]))),
                         ["grants-get-grant: no longer accepts include"])
        self.assertEqual(self.check(catalog(changed(parameters=["grant_id", "holder"]))),
                         ["grants-get-grant: now requires holder"])

    def test_a_query_parameter_becoming_a_path_parameter_requires_it(self):
        self.assertEqual(self.check(catalog(changed(parameters=["grant_id", "include"], query=[]))),
                         ["grants-get-grant: now requires include"])

    def test_breaks_already_on_the_base_are_not_counted_again(self):
        base = catalog(changed(method="POST"))
        self.assertEqual(self.check(catalog(changed(method="POST")), base), [])
        self.assertEqual(self.check({}, base), ["grants-get-grant: removed"])
        self.assertEqual(self.check({}, {}), [])

    def test_unreleased_operations_may_change(self):
        draft = changed(id="grants-draft")
        self.assertEqual(incompatibilities(catalog(OP), catalog(OP, draft), catalog(OP)), [])

    def test_label_and_upgrading_section_are_both_required(self):
        body = "Text\n\n### Upgrading\n\nCall grants-read-grant instead.\n"
        self.assertTrue(allowed({"breaking"}, body))
        self.assertFalse(allowed({"breaking"}, "no section"))
        self.assertFalse(allowed({"breaking"}, "#### Upgrading"))
        self.assertFalse(allowed(set(), body))
        self.assertFalse(allowed({"not-breaking"}, body))
        self.assertFalse(allowed({"breaking"}, None))


if __name__ == "__main__":
    unittest.main()

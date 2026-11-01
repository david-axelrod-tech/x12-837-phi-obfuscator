"""Tests for obfuscate_837.py, run against the synthetic sample in samples/.

Every name, ID and address in the sample is fictional.
"""
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import obfuscate_837 as ob  # noqa: E402

SAMPLE = os.path.join(ROOT, "samples", "sample_837p.x12")

REAL_PATIENT_TOKENS = ["DOE", "JANE", "ROE", "RICHARD", "ROBIN", "ZZ12345A", "ZZ67890B",
                       "123 MAPLE ST", "456 OAK AVE", "MRN0004471", "MRN0004472"]
# Things that must survive every mode untouched
KEEP_ALWAYS = ["1999999992", "1888888886",        # NPIs
               "RIVERTON HOME CARE LLC", "SAMPLE STATE MEDICAID", "SMITH*MARY",
               "T1019", "99213", "ABK:I10", "ABF:E119", "480.00", "360.00", "95.00",
               "900 COMMERCE PARK DR", "ALBANY*NY*122050001"]


def load():
    with open(SAMPLE, "rb") as fh:
        return fh.read().decode("latin-1")


def run(text, mode="basic", seed="unit-test", **kw):
    opts = ob.Options(mode=mode, seed=seed, **kw)
    policy = ob.Policy(opts)
    scr = ob.Scrambler(seed, policy)
    out, problems = ob.FileObfuscator(scr, policy).run(text)
    return out, problems


def segments(text):
    return [s.strip() for s in text.split("~") if s.strip()]


def tags(text):
    return [s.split("*")[0] for s in segments(text)]


def elements(text, tag):
    return [s.split("*") for s in segments(text) if s.startswith(tag + "*")]


class StructureTests(unittest.TestCase):
    def setUp(self):
        self.src = load()

    def test_segment_structure_preserved_in_every_mode(self):
        for mode in ("basic", "expert", "safe-harbor"):
            out, _ = run(self.src, mode)
            self.assertEqual(tags(out), tags(self.src), mode)
            self.assertEqual(len(out.splitlines()), len(self.src.splitlines()), mode)
            # SE count and envelope control numbers untouched
            self.assertEqual(elements(out, "SE"), elements(self.src, "SE"), mode)
            self.assertEqual(elements(out, "IEA"), elements(self.src, "IEA"), mode)

    def test_non_phi_untouched_in_every_mode(self):
        for mode in ("basic", "expert", "safe-harbor"):
            out, _ = run(self.src, mode)
            for keep in KEEP_ALWAYS:
                self.assertIn(keep, out, f"{keep!r} lost in {mode}")

    def test_replacements_keep_shape(self):
        out, _ = run(self.src, "basic")
        for a, b in zip(elements(self.src, "NM1"), elements(out, "NM1")):
            if a[1] in ("IL", "QC") and len(a) > 9 and a[9]:
                self.assertEqual(len(a[9]), len(b[9]))
                for x, y in zip(a[9], b[9]):
                    self.assertEqual(x.isdigit(), y.isdigit())
                    self.assertEqual(x.isalpha(), y.isalpha())

    def test_leak_check_is_clean(self):
        for mode in ("basic", "expert", "safe-harbor"):
            _, problems = run(self.src, mode)
            self.assertEqual(problems, [], mode)


class BasicModeTests(unittest.TestCase):
    def setUp(self):
        self.src = load()
        self.out, _ = run(self.src, "basic")

    def test_patient_identity_removed(self):
        for tok in REAL_PATIENT_TOKENS:
            self.assertIsNone(re.search(r"\b" + re.escape(tok) + r"\b", self.out), tok)

    def test_relative_in_note_renamed_and_phone_scrambled(self):
        nte = elements(self.out, "NTE")[0][2]
        self.assertNotIn("JOHN DOE", nte)
        self.assertNotIn("6075550123", nte)
        self.assertIn("REL: SPOUSE", nte)                 # structure of the note kept
        self.assertRegex(nte, r"NAME: [A-Z]+ [A-Z]+ REL: SPOUSE CONTACT \d{10}")

    def test_claim_data_untouched_in_basic(self):
        self.assertEqual(elements(self.out, "CLM"), elements(self.src, "CLM"))
        self.assertEqual(elements(self.out, "DTP"), elements(self.src, "DTP"))
        self.assertEqual(elements(self.out, "HI"), elements(self.src, "HI"))
        # ZIPs kept, cities faked
        n4 = elements(self.out, "N4")
        self.assertEqual([e[3] for e in n4], [e[3] for e in elements(self.src, "N4")])
        self.assertNotEqual(n4[1][1], "SPRINGDALE")

    def test_dob_shifted_not_removed(self):
        src_dob = [e[2] for e in elements(self.src, "DMG")]
        out_dob = [e[2] for e in elements(self.out, "DMG")]
        for a, b in zip(src_dob, out_dob):
            self.assertNotEqual(a, b)
            self.assertRegex(b, r"^\d{8}$")
            self.assertLessEqual(abs(int(a[:4]) - int(b[:4])), 3)

    def test_same_person_same_fake_across_loops(self):
        # Richard Roe (subscriber) and dependent Robin Roe share a surname and address;
        # the fake surname and fake street must be consistent within the file.
        nm1 = [e for e in elements(self.out, "NM1") if e[1] in ("IL", "QC")]
        self.assertEqual(nm1[1][3], nm1[2][3])             # same fake last name
        n3 = elements(self.out, "N3")
        self.assertEqual(n3[2], n3[3])                     # same fake street


class DeterminismTests(unittest.TestCase):
    def test_same_seed_same_output(self):
        src = load()
        a, _ = run(src, "expert", seed="alpha")
        b, _ = run(src, "expert", seed="alpha")
        self.assertEqual(a, b)

    def test_different_seed_different_output(self):
        src = load()
        a, _ = run(src, "expert", seed="alpha")
        b, _ = run(src, "expert", seed="beta")
        self.assertNotEqual(a, b)

    def test_safe_harbor_is_not_seed_derived(self):
        src = load()
        a, _ = run(src, "safe-harbor", seed="alpha")
        b, _ = run(src, "safe-harbor", seed="alpha")
        self.assertNotEqual(elements(a, "NM1"), elements(b, "NM1"))


class ExpertModeTests(unittest.TestCase):
    def setUp(self):
        self.src = load()
        self.out, _ = run(self.src, "expert")

    def test_service_dates_shifted_consistently(self):
        src_dtp = elements(self.src, "DTP")
        out_dtp = elements(self.out, "DTP")
        self.assertNotEqual(src_dtp, out_dtp)
        # claim 1: statement span (434) and both line dates (472) move by the same offset
        def d(v):
            from datetime import datetime
            return datetime.strptime(v[:8], "%Y%m%d")
        offsets = {(d(a[3]) - d(b[3])).days for a, b in zip(src_dtp[:3], out_dtp[:3])}
        self.assertEqual(len(offsets), 1)
        self.assertTrue(1 <= offsets.pop() <= 60)

    def test_claim_ids_keep_office_prefix(self):
        clm = [e[1] for e in elements(self.out, "CLM")]
        self.assertTrue(all(c.startswith("37-") for c in clm))
        self.assertNotIn("37-104625", clm)

    def test_patient_zip_reduced_to_zip3(self):
        n4 = elements(self.out, "N4")
        self.assertEqual(n4[0][3], "122050001")            # billing provider: untouched
        self.assertEqual({e[3] for e in n4[1:]}, {"12300"})

    def test_provider_without_npi_renamed_but_npi_provider_kept(self):
        nm1 = {e[1]: e for e in elements(self.out, "NM1")}
        self.assertNotEqual(nm1["DQ"][3:5], ["BROWN", "ALICE"])
        self.assertEqual(nm1["82"][3:5], ["SMITH", "MARY"])


class SafeHarborTests(unittest.TestCase):
    def setUp(self):
        self.src = load()
        self.out, _ = run(self.src, "safe-harbor")

    def test_all_dates_year_only(self):
        for e in elements(self.out, "DTP"):
            for part in e[3].split("-"):
                self.assertTrue(part.endswith("0101"), e)
        for e in elements(self.out, "DMG"):
            self.assertTrue(e[2].endswith("0101"), e)
        isa = elements(self.out, "ISA")[0]
        self.assertTrue(isa[9].endswith("0101"))
        self.assertEqual(isa[10], "0000")

    def test_free_text_redacted(self):
        self.assertEqual(elements(self.out, "NTE")[0][2], "REDACTED")

    def test_group_number_replaced(self):
        self.assertNotEqual(elements(self.out, "SBR")[0][3], "GRP1001")

    def test_patient_identity_removed(self):
        for tok in REAL_PATIENT_TOKENS:
            self.assertIsNone(re.search(r"\b" + re.escape(tok) + r"\b", self.out), tok)


class MappingTests(unittest.TestCase):
    def test_mapping_round_trip_reproduces_safe_harbor_output(self):
        import csv
        import tempfile
        src = load()
        with tempfile.TemporaryDirectory() as tmp:
            map_path = os.path.join(tmp, "map.csv")
            logs = []
            first = ob.Options(inputs=[SAMPLE], out=os.path.join(tmp, "a"),
                               mode="safe-harbor", map=map_path)
            ob.run_job(first, lambda m, lvl="info": logs.append(m))
            second = ob.Options(inputs=[SAMPLE], out=os.path.join(tmp, "b"),
                                mode="safe-harbor", map_in=map_path)
            ob.run_job(second, lambda m, lvl="info": logs.append(m))
            with open(os.path.join(tmp, "a", "sample_837p.x12"), "rb") as fh:
                a = fh.read()
            with open(os.path.join(tmp, "b", "sample_837p.x12"), "rb") as fh:
                b = fh.read()
            with open(map_path, newline="") as fh:
                rows = list(csv.DictReader(fh))
        self.assertEqual(a, b)
        self.assertTrue(rows)
        self.assertEqual(set(rows[0]), {"category", "real", "fake"})


if __name__ == "__main__":
    unittest.main()

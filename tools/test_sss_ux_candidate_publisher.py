"""Owned memory-only candidate protocol tests. Never call a real socket/API."""
import base64
import copy
import io
import json
import socket
import unittest
from unittest.mock import patch
import urllib.error
import sss_ux_candidate_publisher as p

COMMIT = "a" * 40
NAMES = ("owned-auto.exe", "owned-auto.zip", "owned-readme.txt", "owned-sums.txt", "owned-catalog.json",
         "owned-win7.exe", "owned-win7.zip", "owned-modern.exe", "owned-modern.zip")
KINDS = ("exe", "zip", "readme", "checksums", "catalog", "exe", "zip", "exe", "zip")
VARIANTS = (("Auto", (NAMES[0], NAMES[1])), ("Win7", (NAMES[5], NAMES[6])), ("Win10-11", (NAMES[7], NAMES[8])))
MARKERS = ("開發候選", "正式信任")
CONTENTS = {NAMES[0]: b"MZ-memory-fixture-not-executable", NAMES[1]: b"PK\x03\x04-memory-not-archive",
            NAMES[2]: "開發候選；不代表正式信任。\n".encode("utf-8")}
for i in (5, 6, 7, 8):
    CONTENTS[NAMES[i]] = (b"MZ" if KINDS[i] == "exe" else b"PK\x03\x04") + b"memory-only-" + str(i).encode("ascii")
CATALOG = {"Schema": 1, "Product": "Solar System Shield", "Version": "0.4.5 UX", "Stage": "Development candidate",
           "Recommended": NAMES[0], "Selection": "Installer reads actual Windows, native architecture, client type, .NET and package identity; compatible child files are verified before launch",
           "MinimumNetFrameworkRelease": 528040, "Targets": [
               {"Variant": "Win7", "OS": "Windows 7 SP1", "Architecture": "x64", "MinimumBuild": 7601, "MinimumServicePack": 1, "ActualWin7Accepted": False},
               {"Variant": "Win10-11", "OS": "Windows 10 or Windows 11", "Architecture": "x64", "MinimumBuild": 19041, "ActualOrdinaryWindows11Installed": True}],
           "NativeProtectionEnabled": False, "ProductionReady": False, "SssAssistedSslRecoveryImplemented": False,
           "Assets": [{"Name": NAMES[i], "Bytes": len(CONTENTS[NAMES[i]]), "SHA256": p.sha(CONTENTS[NAMES[i]]).upper()}
                      for i, variant in ((0, "Auto"), (1, "Auto"), (5, "Win7"), (6, "Win7"), (7, "Win10-11"), (8, "Win10-11"))],
           "AdditionalFees": 0, "PaidCredits": 0, "ExactTaskTokens": None,
           "PackagingRevision": "Corrected portable desktop installer and public four-file Win7 package"}
CONTENTS[NAMES[4]] = json.dumps(CATALOG, separators=(",", ":")).encode("utf-8")
CONTENTS[NAMES[3]] = "".join(p.sha(CONTENTS[r["Name"]]).upper() + "  " + r["Name"] + "\r\n" for r in CATALOG["Assets"]).encode("ascii")
PINS = tuple((n, len(CONTENTS[n]), p.sha(CONTENTS[n]), k) for n, k in zip(NAMES, KINDS))


def request():
    return {"schema": 1, "tag": p.TAG, "classification": p.CLASSIFICATION, "files": [
        {"name": n, "encoding": "raw", "size": len(CONTENTS[n]), "sha256": p.sha(CONTENTS[n])} for n in NAMES]}


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def bundle():
    return p.validate_inputs(encoded(request()), lambda n, _: CONTENTS[n])


def release(draft=False, immutable=False):
    return {"id": 71, "tag_name": p.TAG, "name": p.TITLE, "body": p.BODY, "target_commitish": COMMIT,
            "draft": draft, "prerelease": True, "immutable": immutable}


class FakeGitHub:
    def __init__(self, initial=None, contents=None):
        self.current = copy.deepcopy(initial)
        self.repo = {"full_name": p.REPOSITORY, "private": False, "visibility": "public", "archived": False}
        self.data, self.items, self.mutations, self.public_reads = {}, {}, [], []
        self.next_id = 100
        self.bad_public = self.upload_unknown = self.publish_unknown = False
        for n, b in (contents or {}).items():
            self.add(n, b)

    def add(self, name, data):
        self.next_id += 1
        value = {"id": self.next_id, "name": name, "size": len(data), "state": "uploaded", "digest": "sha256:" + p.sha(data)}
        self.items[name], self.data[self.next_id] = value, data
        return copy.deepcopy(value)

    def repository(self): return copy.deepcopy(self.repo)
    def find_release(self): return copy.deepcopy(self.current)
    def get_release(self, rid):
        assert rid == 71
        return copy.deepcopy(self.current)
    def assets(self, rid):
        assert rid == 71
        return copy.deepcopy(list(self.items.values()))
    def create_draft(self, commit):
        assert self.current is None and commit == COMMIT
        self.mutations.append(("create", p.TAG)); self.current = release(True)
        return copy.deepcopy(self.current)
    def upload(self, rid, name, data):
        assert rid == 71 and name not in self.items and self.current["draft"] and not self.current["immutable"]
        self.mutations.append(("upload", name))
        value = self.add(name, data)
        if self.upload_unknown: value["id"] += 1
        return value
    def asset_bytes(self, aid, size): return self.data[aid]
    def publish_draft(self, rid):
        assert rid == 71 and set(self.items) == set(NAMES)
        self.mutations.append(("publish", p.TAG))
        if self.publish_unknown: raise p.PublishError("owned-publication-unknown")
        self.current["draft"] = False
        return copy.deepcopy(self.current)
    def public_bytes(self, name, size):
        assert not self.current["draft"]
        self.public_reads.append(name)
        return b"wrong" if self.bad_public == name else self.data[self.items[name]["id"]]


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.stack = []
        for target, name, value in ((p, "FROZEN_ASSETS", PINS), (p, "FROZEN_README_MARKERS", MARKERS), (p, "FROZEN_VARIANTS", VARIANTS),
                                    (socket, "socket", lambda *_a, **_k: self.fail("real socket forbidden")),
                                    (socket, "create_connection", lambda *_a, **_k: self.fail("real connection forbidden"))):
            item = patch.object(target, name, value); item.start(); self.stack.append(item)
    def tearDown(self):
        for item in reversed(self.stack): item.stop()
    def rejected(self, value, payload=None):
        with self.assertRaises(p.PublishError):
            p.validate_inputs(encoded(value), lambda n, _: (CONTENTS if payload is None else payload)[n])

    def test_01_unfrozen_main_refuses_before_token_file_or_network(self):
        with patch.object(p, "FROZEN_ASSETS", ()), patch.object(p, "Http", side_effect=AssertionError("network constructed")), \
             patch.object(p, "load_inputs", side_effect=AssertionError("file read")), patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(p.main(), 1)
        self.assertEqual(json.loads(output.getvalue())["code"], "candidate-final-tuple-not-frozen")

    def test_02_exact_raw_and_base64_same_frozen_bytes(self):
        value = request()
        for row in value["files"]: row["encoding"] = "base64"
        data = {n + ".b64": base64.b64encode(b) for n, b in CONTENTS.items()}
        self.assertEqual(p.validate_inputs(encoded(value), lambda n, _: data[n])["contents"], bundle()["contents"])

    def test_03_purpose_unknown_and_bool_schema_refused(self):
        for k, v in (("schema", True), ("classification", "stable"), ("tag", "sss-stable"), ("tag", "ssl-stable"), ("extra", 1)):
            r = request(); r[k] = v; self.rejected(r)

    def test_04_inventory_order_traversal_case_and_extras_refused(self):
        for change in (lambda r: r.pop(), lambda r: r.append(dict(r[0])), lambda r: r.reverse(),
                       lambda r: r[0].update(name="../outside.exe"), lambda r: r[0].update(name=NAMES[0].upper()),
                       lambda r: r[0].update(path="outside")):
            r = request(); change(r["files"]); self.rejected(r)

    def test_05_request_cannot_replace_frozen_size_or_digest(self):
        for k, v in (("size", True), ("size", 1.0), ("size", 0), ("size", p.MAX_FILE + 1),
                     ("sha256", "A" * 64), ("sha256", "0" * 64)):
            r = request(); r["files"][0][k] = v; self.rejected(r)
        data = dict(CONTENTS); data[NAMES[0]] = b"Z" + data[NAMES[0]][1:]; self.rejected(request(), data)

    def test_06_duplicate_json_constants_bom_and_capacity_refused(self):
        for raw in (b'{"schema":1,"schema":1}', b'\xef\xbb\xbf{}', b'{"schema":NaN}', b'x' * (p.MAX_REQUEST + 1)):
            with self.assertRaises(p.PublishError): p.validate_inputs(raw, lambda *_: self.fail("reader reached"))

    def test_07_base64_canonical_and_encoded_bound_refused(self):
        r = request()
        for row in r["files"]: row["encoding"] = "base64"
        for bad in (b"!!!!", b"TV===", base64.b64encode(CONTENTS[NAMES[0]]) + b"\n"):
            data = {n + ".b64": base64.b64encode(b) for n, b in CONTENTS.items()}; data[NAMES[0] + ".b64"] = bad
            self.rejected(r, data)

    def test_08_frozen_tuple_bounds_suffix_duplicate_and_notice_guard(self):
        for pins in ((), PINS + (PINS[0],), (("../bad", 1, "a" * 64, "exe"),) + PINS[1:],
                     (("bad.txt", 1, "a" * 64, "exe"),) + PINS[1:],
                     ((NAMES[0], p.MAX_FILE + 1, "a" * 64, "exe"),) + PINS[1:]):
            with patch.object(p, "FROZEN_ASSETS", pins), self.assertRaises(p.PublishError): p.frozen()
        with patch.object(p, "FROZEN_README_MARKERS", ()), self.assertRaises(p.PublishError): p.frozen()
        huge = tuple((n, p.MAX_FILE, "a" * 64, k) for n, k in zip(NAMES, KINDS))
        with patch.object(p, "FROZEN_ASSETS", huge), self.assertRaises(p.PublishError): p.frozen()

    def test_09_marker_notice_and_checksum_semantics_even_with_matching_pins(self):
        for idx, data in ((0, b"NO-executable-marker"), (1, b"NO-zip-marker"), (2, b"missing notice"), (3, b"incomplete\n")):
            contents = dict(CONTENTS); contents[NAMES[idx]] = data
            pins = tuple((n, len(contents[n]), p.sha(contents[n]), PINS[i][3]) for i, n in enumerate(NAMES))
            r = request(); r["files"][idx].update(size=len(data), sha256=p.sha(data))
            with patch.object(p, "FROZEN_ASSETS", pins): self.rejected(r, contents)
        for change in (lambda c: c.update(NativeProtectionEnabled=True), lambda c: c.update(ProductionReady=True),
                       lambda c: c.update(SssAssistedSslRecoveryImplemented=True), lambda c: c.update(internalPath="forbidden"),
                       lambda c: c["Targets"][0].update(ActualWin7Accepted=True), lambda c: c["Targets"][0].update(MinimumServicePack=True),
                       lambda c: c.update(Recommended=NAMES[5]), lambda c: c["Assets"].append(dict(c["Assets"][0])),
                       lambda c: c["Assets"][0].update(Variant="Win7"), lambda c: c["Assets"][0].update(SHA256="A" * 64)):
            c = copy.deepcopy(CATALOG); change(c)
            with self.assertRaises(p.PublishError): p.validate_catalog(encoded(c), p.frozen())

    def test_10_create_upload_publish_and_all_public_readbacks(self):
        client = FakeGitHub(); result = p.publish(client, bundle(), COMMIT)
        self.assertEqual(result["status"], "public-readback-verified")
        self.assertEqual(client.mutations, [("create", p.TAG)] + [("upload", n) for n in NAMES] + [("publish", p.TAG)])
        self.assertEqual(client.public_reads, list(NAMES))

    def test_11_published_exact_bytes_is_idempotent_even_immutable(self):
        for immutable in (False, True):
            client = FakeGitHub(release(immutable=immutable), CONTENTS)
            self.assertFalse(p.publish(client, bundle(), COMMIT)["created"]); self.assertEqual(client.mutations, [])

    def test_12_owned_partial_draft_adds_only_missing_asset(self):
        client = FakeGitHub(release(True), {n: CONTENTS[n] for n in NAMES[:-1]}); p.publish(client, bundle(), COMMIT)
        self.assertEqual(client.mutations, [("upload", NAMES[-1]), ("publish", p.TAG)])

    def test_13_any_existing_size_digest_or_byte_conflict_no_mutation(self):
        for mode in range(3):
            client = FakeGitHub(release(True), CONTENTS); item = client.items[NAMES[0]]
            if mode == 0: item["size"] += 1
            elif mode == 1: item["digest"] = "sha256:" + "0" * 64
            else: client.data[item["id"]] = b"Z" + CONTENTS[NAMES[0]][1:]
            with self.assertRaises(p.PublishError): p.publish(client, bundle(), COMMIT)
            self.assertEqual(client.mutations, [])

    def test_14_body_tag_prerelease_target_repo_and_commit_guard(self):
        for k, v in (("tag_name", "sss-stable"), ("body", "not-owned"), ("prerelease", False), ("target_commitish", "main"), ("draft", 1)):
            client = FakeGitHub(release(True), CONTENTS); client.current[k] = v
            with self.assertRaises(p.PublishError): p.publish(client, bundle(), COMMIT)
            self.assertEqual(client.mutations, [])
        for k, v in (("private", True), ("archived", True), ("visibility", "private"), ("full_name", "other/repo")):
            client = FakeGitHub(); client.repo[k] = v
            with self.assertRaises(p.PublishError): p.publish(client, bundle(), COMMIT)
            self.assertEqual(client.mutations, [])
        with self.assertRaises(p.PublishError): p.publish(FakeGitHub(), bundle(), "main")

    def test_15_unknown_duplicate_unuploaded_and_published_missing_assets_refused(self):
        for variant in range(5):
            client = FakeGitHub(release(), CONTENTS)
            if variant == 0: client.add("unknown.exe", b"x")
            elif variant == 1:
                original = client.assets; client.assets = lambda rid: [original(rid)[0]] * 2
            elif variant == 2: client.items[NAMES[0]]["state"] = "starter"
            elif variant == 3: del client.items[NAMES[0]]
            else: client.items[NAMES[1]]["id"] = client.items[NAMES[0]]["id"]
            with self.assertRaises(p.PublishError): p.publish(client, bundle(), COMMIT)
            self.assertEqual(client.mutations, [])

    def test_16_immutable_draft_and_forged_bundle_no_mutation(self):
        client = FakeGitHub(release(True, True))
        with self.assertRaises(p.PublishError): p.publish(client, bundle(), COMMIT)
        self.assertEqual(client.mutations, [])
        value = bundle(); value["contents"][NAMES[0]] = b"MZ-other"
        client = FakeGitHub()
        with self.assertRaises(p.PublishError): p.publish(client, value, COMMIT)
        self.assertEqual(client.mutations, [])

    def test_17_unknown_upload_or_publish_state_is_not_retried(self):
        for field in ("upload_unknown", "publish_unknown"):
            client = FakeGitHub(); setattr(client, field, True)
            with self.assertRaises(p.PublishError): p.publish(client, bundle(), COMMIT)
            self.assertEqual(sum(v[0] == "create" for v in client.mutations), 1)
            self.assertLessEqual(sum(v[0] == "publish" for v in client.mutations), 1)
            self.assertEqual(sum(v[0] == "upload" for v in client.mutations), 1 if field == "upload_unknown" else len(NAMES))

    def test_18_public_readback_mismatch_is_failure_not_success(self):
        client = FakeGitHub(); client.bad_public = NAMES[1]
        with self.assertRaisesRegex(p.PublishError, "public-readback-conflict"): p.publish(client, bundle(), COMMIT)

    def test_19_redirect_origin_token_drop_and_bounded_response(self):
        class Response:
            def __init__(self, b): self.stream = io.BytesIO(b)
            def __enter__(self): return self
            def __exit__(self, *_): self.stream.close()
            def read(self, count): return self.stream.read(count)
        class Opener:
            def __init__(self, rows): self.rows = list(rows); self.calls = []
            def open(self, req, timeout):
                self.calls.append(req); row = self.rows.pop(0)
                if isinstance(row, Exception): raise row
                return Response(row)
        redirect = urllib.error.HTTPError(p.API, 302, "owned", {"Location": "https://release-assets.githubusercontent.com/owned"}, io.BytesIO())
        opener = Opener([redirect, b"abc"])
        with patch.object(p.urllib.request, "build_opener", return_value=opener): http = p.Http("owned-not-credential")
        self.assertEqual(http.fetch(p.API + "/releases/assets/1", 3, authenticated=True, binary=True, redirects=True), b"abc")
        self.assertIsNotNone(opener.calls[0].get_header("Authorization")); self.assertIsNone(opener.calls[1].get_header("Authorization"))
        for location in ("https://evil.invalid/data", "http://release-assets.githubusercontent.com/owned"):
            opener = Opener([urllib.error.HTTPError(p.API, 302, "owned", {"Location": location}, io.BytesIO())])
            with patch.object(p.urllib.request, "build_opener", return_value=opener): http = p.Http("owned-not-credential")
            with self.assertRaises(p.PublishError): http.fetch(p.API, 3, authenticated=True, redirects=True)
            self.assertEqual(len(opener.calls), 1)
        opener = Opener([b"abcd"])
        with patch.object(p.urllib.request, "build_opener", return_value=opener): http = p.Http("owned-not-credential")
        with self.assertRaisesRegex(p.PublishError, "network-response-size"): http.fetch(p.API, 3)

    def test_20_real_adapter_refuses_other_tag_delete_patch_and_bad_draft_target(self):
        class Capture:
            def __init__(self): self.calls = []
            def fetch(self, *args, **kw): self.calls.append((args, kw)); return b"{}"
        capture = Capture(); github = p.GitHub(capture); github.create_draft(COMMIT)
        posted = json.loads(capture.calls[0][0][3]); self.assertTrue(posted["draft"] and posted["prerelease"])
        self.assertEqual(posted["target_commitish"], COMMIT); self.assertEqual(posted["make_latest"], "false")
        for suffix, method, body in (("/releases/tags/sss-stable", "GET", None), ("/releases/1", "DELETE", None),
                                     ("/releases/1/assets/2", "PATCH", {"name": "overwrite"}),
                                     ("/releases", "POST", dict(posted, target_commitish="main"))):
            before = len(capture.calls)
            with self.assertRaises(p.PublishError): github.api(suffix, method, body)
            self.assertEqual(len(capture.calls), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)

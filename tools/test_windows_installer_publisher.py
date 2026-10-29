"""Owned memory-only tests: no real HTTP, installer, repository or filesystem IO."""
import base64
import copy
import io
import json
import os
import socket
import sys
import unittest
from unittest.mock import patch
import urllib.error

import windows_installer_publisher as p

COMMIT = "a" * 40


def fixture(encoding="raw", readme_bom=False):
    readme = "0.7.1-r1 Windows x64 整合開發候選；不是完整 SSS。操作需有效授權，已保存的 standing grant 仍需逐次 bound RSA 驗證。無人值守與 POS 實機持續操作尚未完成驗收。\n".encode("utf-8")
    if readme_bom:
        readme = b"\xef\xbb\xbf" + readme
    contents = {p.NAMES[0]: b"MZ-owned-fixture-not-an-executable", p.NAMES[1]: b"PK\x03\x04-owned-fixture-not-a-zip", p.NAMES[2]: readme}
    contents[p.NAMES[3]] = "".join(p.sha(contents[n]) + "  " + n + "\n" for n in p.NAMES[:3]).encode("ascii")
    request = {"schema": 1, "tag": p.TAG, "classification": p.CLASSIFICATION, "files": [
        {"name": n, "encoding": encoding, "size": len(contents[n]), "sha256": p.sha(contents[n])} for n in p.NAMES]}
    payload = {n + (".b64" if encoding == "base64" else ""): base64.b64encode(contents[n]) if encoding == "base64" else contents[n] for n in p.NAMES}
    return request, payload, contents


def encoded(request):
    return json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def bundle(encoding="raw", readme_bom=False):
    request, payload, _ = fixture(encoding, readme_bom)
    return p.validate_inputs(encoded(request), lambda name, maximum: payload[name])


def release(draft=False, immutable=False):
    return {"id": 71, "tag_name": p.TAG, "name": p.TITLE, "body": p.BODY,
            "draft": draft, "prerelease": True, "immutable": immutable}


class FakeGitHub:
    """API protocol model. Mutation calls are explicit and never touch a network."""
    def __init__(self, initial=None, contents=None):
        self.current = copy.deepcopy(initial)
        self.repo = {"full_name": p.REPOSITORY, "visibility": "public", "private": False, "archived": False}
        self.data, self.items, self.mutations, self.public_reads = {}, {}, [], []
        self.next_id = 100
        self.bad_public = None
        self.publish_unknown = False
        self.upload_unknown = False
        if contents:
            for name, data in contents.items():
                self.add(name, data)

    def add(self, name, data):
        self.next_id += 1
        item = {"id": self.next_id, "name": name, "size": len(data), "state": "uploaded", "digest": "sha256:" + p.sha(data)}
        self.items[name], self.data[item["id"]] = item, data
        return copy.deepcopy(item)

    def repository(self):
        return copy.deepcopy(self.repo)

    def find_release(self):
        return copy.deepcopy(self.current)

    def get_release(self, release_id):
        if release_id != 71:
            raise AssertionError("wrong release id")
        return copy.deepcopy(self.current)

    def assets(self, release_id):
        if release_id != 71:
            raise AssertionError("wrong release id")
        return copy.deepcopy(list(self.items.values()))

    def create_draft(self, commit):
        if self.current is not None or commit != COMMIT:
            raise AssertionError("unexpected draft create")
        self.mutations.append(("create", p.TAG))
        self.current = release(draft=True)
        return copy.deepcopy(self.current)

    def upload(self, release_id, name, data):
        if release_id != 71 or name in self.items or not self.current["draft"] or self.current["immutable"]:
            raise AssertionError("overwrite or invalid upload")
        self.mutations.append(("upload", name))
        value = self.add(name, data)
        if self.upload_unknown:
            value["id"] += 1
        return value

    def asset_bytes(self, asset_id, maximum):
        return self.data[asset_id]

    def publish_draft(self, release_id):
        if release_id != 71 or set(self.items) != set(p.NAMES):
            raise AssertionError("incomplete publish")
        self.mutations.append(("publish", p.TAG))
        if self.publish_unknown:
            raise p.PublishError("owned-unknown-after-publish")
        self.current["draft"] = False
        return copy.deepcopy(self.current)

    def public_bytes(self, name, maximum):
        self.public_reads.append(name)
        if self.current["draft"]:
            raise AssertionError("public read before publish")
        return b"wrong" if self.bad_public == name else self.data[self.items[name]["id"]]


class InputTests(unittest.TestCase):
    def refused(self, request, payload):
        with self.assertRaises(p.PublishError):
            p.validate_inputs(encoded(request), lambda name, maximum: payload[name])

    def test_raw_and_canonical_base64_bom_are_same_bytes(self):
        for bom in (False, True):
            self.assertEqual(bundle("raw", bom)["contents"], bundle("base64", bom)["contents"])

    def test_purpose_schema_and_unknown_fields_refused(self):
        self.assertEqual(p.TAG, "ssl-windows-v0.7.1-r1")
        self.assertEqual(p.NAMES[:2], ("SolarSystemLink-Windows-x64-Setup-0.7.1-r1.exe",
                                      "SolarSystemLink-Windows-x64-Setup-0.7.1-r1.zip"))
        self.assertEqual(p.CLASSIFICATION, "development-sss-preconnect-update-candidate")
        for key, value in (("schema", True), ("tag", "ssl-stable"), ("tag", "ssl-v0.6.7.0"),
                           ("classification", "unattended"), ("unknown", 1)):
            request, payload, _ = fixture()
            request[key] = value
            self.refused(request, payload)

    def test_exact_order_names_inventory_and_traversal_refused(self):
        for operation in (lambda rows: rows.pop(), lambda rows: rows.append(dict(rows[0])),
                          lambda rows: rows.reverse(), lambda rows: rows[0].update(name="../other.exe"),
                          lambda rows: rows[0].update(name=p.NAMES[0].lower()),
                          lambda rows: rows[0].update(path="outside")):
            request, payload, _ = fixture()
            operation(request["files"])
            self.refused(request, payload)

    def test_per_file_size_bool_float_zero_and_total_bound(self):
        for value in (True, 1.0, 0, -1, p.MAX_FILE + 1):
            request, payload, _ = fixture()
            request["files"][0]["size"] = value
            self.refused(request, payload)
        request, payload, _ = fixture()
        request["files"][0]["size"] = p.MAX_FILE
        payload[p.NAMES[0]] = b"MZ" + b"x" * (p.MAX_FILE - 2)
        request["files"][0]["sha256"] = p.sha(payload[p.NAMES[0]])
        request["files"][1]["size"] = p.MAX_TOTAL - p.MAX_FILE + 1
        self.refused(request, payload)

    def test_digest_length_case_and_actual_byte_mismatch(self):
        for digest in ("a" * 63, "A" * 64, "g" * 64, "0" * 64):
            request, payload, _ = fixture()
            request["files"][0]["sha256"] = digest
            self.refused(request, payload)
        request, payload, _ = fixture()
        payload[p.NAMES[0]] += b"x"
        self.refused(request, payload)

    def test_duplicate_json_bom_constants_and_request_capacity(self):
        for data in (b'{"schema":1,"schema":1}', b"\xef\xbb\xbf{}", b'{"schema":NaN}', b"x" * (p.MAX_REQUEST + 1)):
            with self.assertRaises(p.PublishError):
                p.validate_inputs(data, lambda *_: self.fail("reader must not be reached"))

    def test_base64_whitespace_bad_padding_and_wrong_encoding(self):
        request, payload, _ = fixture("base64")
        for value in (payload[p.NAMES[0] + ".b64"] + b"\n", b"!!!!", b"TV==="):
            changed = dict(payload)
            changed[p.NAMES[0] + ".b64"] = value
            self.refused(request, changed)
        request["files"][0]["encoding"] = "zip"
        self.refused(request, payload)

    def test_readme_semantic_markers_and_checksum_inventory(self):
        for marker in p.README_MARKERS:
            request, payload, _ = fixture()
            payload[p.NAMES[2]] = payload[p.NAMES[2]].replace(marker.encode("utf-8"), b"omitted")
            request["files"][2].update(size=len(payload[p.NAMES[2]]), sha256=p.sha(payload[p.NAMES[2]]))
            self.refused(request, payload)
        request, payload, _ = fixture()
        payload[p.NAMES[3]] = b"incomplete\n"
        request["files"][3].update(size=len(payload[p.NAMES[3]]), sha256=p.sha(payload[p.NAMES[3]]))
        self.refused(request, payload)


class PublicationTests(unittest.TestCase):
    def test_new_draft_upload_all_publish_and_four_public_readbacks(self):
        client = FakeGitHub()
        result = p.publish(client, bundle(), COMMIT)
        self.assertEqual(result["status"], "public-readback-verified")
        self.assertTrue(result["created"])
        self.assertEqual(client.mutations, [("create", p.TAG)] + [("upload", n) for n in p.NAMES] + [("publish", p.TAG)])
        self.assertEqual(client.public_reads, list(p.NAMES))
        self.assertTrue(all(row["url"].startswith(p.PUBLIC) for row in result["files"]))

    def test_published_same_bytes_idempotent_including_immutable(self):
        for immutable in (False, True):
            client = FakeGitHub(release(immutable=immutable), bundle()["contents"])
            self.assertFalse(p.publish(client, bundle(), COMMIT)["created"])
            self.assertEqual(client.mutations, [])
            self.assertEqual(client.public_reads, list(p.NAMES))

    def test_owned_partial_draft_only_adds_missing_asset(self):
        contents = bundle()["contents"]
        client = FakeGitHub(release(draft=True), {n: contents[n] for n in p.NAMES[:3]})
        p.publish(client, bundle(), COMMIT)
        self.assertEqual(client.mutations, [("upload", p.NAMES[3]), ("publish", p.TAG)])

    def test_conflict_size_digest_or_same_metadata_different_bytes_never_overwrites(self):
        for variant in range(3):
            client = FakeGitHub(release(draft=True), bundle()["contents"])
            item = client.items[p.NAMES[0]]
            if variant == 0:
                item["size"] += 1
            elif variant == 1:
                item["digest"] = "sha256:" + "0" * 64
            else:
                old = client.data[item["id"]]
                client.data[item["id"]] = b"X" + old[1:]
            with self.assertRaises(p.PublishError):
                p.publish(client, bundle(), COMMIT)
            self.assertEqual(client.mutations, [])

    def test_other_tag_body_public_or_commit_refused_before_mutation(self):
        for variant in range(6):
            client = FakeGitHub(release(), bundle()["contents"])
            commit = COMMIT
            if variant == 0:
                client.current["tag_name"] = "ssl-stable"
            elif variant == 1:
                client.current["tag_name"] = "ssl-v0.6.7.0"
            elif variant == 2:
                client.current["body"] = "not owned"
            elif variant == 3:
                client.repo["private"] = True
            elif variant == 4:
                client.repo["archived"] = True
            else:
                commit = "main"
            with self.assertRaises(p.PublishError):
                p.publish(client, bundle(), commit)
            self.assertEqual(client.mutations, [])

    def test_unknown_duplicate_unuploaded_or_published_missing_assets_refused(self):
        contents = bundle()["contents"]
        for variant in range(4):
            client = FakeGitHub(release(), contents)
            if variant == 0:
                client.add("unknown.exe", b"x")
            elif variant == 1:
                original = client.assets
                client.assets = lambda rid: [original(rid)[0], original(rid)[0]]
            elif variant == 2:
                client.items[p.NAMES[0]]["state"] = "starter"
            else:
                del client.items[p.NAMES[0]]
            with self.assertRaises(p.PublishError):
                p.publish(client, bundle(), COMMIT)
            self.assertEqual(client.mutations, [])

    def test_immutable_partial_draft_cannot_upload(self):
        client = FakeGitHub(release(draft=True, immutable=True))
        with self.assertRaises(p.PublishError):
            p.publish(client, bundle(), COMMIT)
        self.assertEqual(client.mutations, [])

    def test_unknown_upload_identity_and_publication_are_not_retried(self):
        for variant in ("upload_unknown", "publish_unknown"):
            client = FakeGitHub()
            setattr(client, variant, True)
            with self.assertRaises(p.PublishError):
                p.publish(client, bundle(), COMMIT)
            self.assertEqual(sum(c[0] == "create" for c in client.mutations), 1)
            self.assertLessEqual(sum(c[0] == "publish" for c in client.mutations), 1)
            self.assertEqual(sum(c[0] == "upload" for c in client.mutations), 1 if variant == "upload_unknown" else 4)

    def test_api_success_without_exact_public_readback_is_failure(self):
        client = FakeGitHub()
        client.bad_public = p.NAMES[1]
        with self.assertRaisesRegex(p.PublishError, "public-readback-conflict"):
            p.publish(client, bundle(), COMMIT)
        self.assertEqual(sum(c[0] == "publish" for c in client.mutations), 1)


class Response:
    def __init__(self, data):
        self.stream = io.BytesIO(data)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.stream.close()

    def read(self, count):
        return self.stream.read(count)


class Opener:
    def __init__(self, responses):
        self.responses, self.requests = list(responses), []

    def open(self, request, timeout):
        self.requests.append(request)
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return Response(item)


class TransportTests(unittest.TestCase):
    def http(self, responses):
        opener = Opener(responses)
        with patch.object(p.urllib.request, "build_opener", return_value=opener):
            client = p.Http("owned-dummy-token-not-a-credential")
        return client, opener

    def test_authenticated_download_redirect_drops_token_on_cdn(self):
        redirect = urllib.error.HTTPError(p.API, 302, "owned", {"Location": "https://release-assets.githubusercontent.com/owned?fixture=yes"}, io.BytesIO())
        http, opener = self.http([redirect, b"abc"])
        self.assertEqual(http.fetch(p.API + "/releases/assets/1", 3, authenticated=True, binary=True, redirects=True), b"abc")
        self.assertIsNotNone(opener.requests[0].get_header("Authorization"))
        self.assertIsNone(opener.requests[1].get_header("Authorization"))

    def test_redirect_origin_nonget_and_response_capacity_refuse(self):
        for method, location in (("GET", "https://evil.invalid/data"), ("POST", "https://release-assets.githubusercontent.com/owned")):
            redirect = urllib.error.HTTPError(p.API, 302, "owned", {"Location": location}, io.BytesIO())
            http, opener = self.http([redirect])
            with self.assertRaises(p.PublishError):
                http.fetch(p.API, 3, method, b"x" if method == "POST" else None, True, True, True)
            self.assertEqual(len(opener.requests), 1)
            if method == "POST":
                self.assertEqual(opener.requests[0].get_header("Accept"), "application/vnd.github+json")
                self.assertEqual(opener.requests[0].get_header("Content-type"), "application/octet-stream")
        http, _ = self.http([b"abcd"])
        with self.assertRaisesRegex(p.PublishError, "network-response-size"):
            http.fetch(p.PUBLIC + p.NAMES[0], 3, binary=True)

    def test_actual_api_adapter_fixed_tag_and_no_delete_patch_asset(self):
        class Capture:
            def __init__(self):
                self.calls = []

            def fetch(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                return b"{}"
        capture = Capture()
        github = p.GitHub(capture)
        github.create_draft(COMMIT)
        args, _ = capture.calls[0]
        body = json.loads(args[3])
        self.assertEqual(body["tag_name"], p.TAG)
        self.assertTrue(body["draft"] and body["prerelease"])
        self.assertEqual(body["make_latest"], "false")
        for suffix, method, payload in (("/releases/tags/ssl-stable", "GET", None),
                                        ("/releases/1/assets/2", "PATCH", {"name": "overwrite"}),
                                        ("/releases/1", "DELETE", None),
                                        ("/releases", "POST", {"tag_name": "ssl-v0.6.7.0", "draft": True})):
            with self.assertRaises(p.PublishError):
                github.api(suffix, method, payload)
        self.assertEqual(len(capture.calls), 1)


if __name__ == "__main__":
    # A real network attempt is a test failure. No temporary files or cache are used.
    with patch.object(socket, "create_connection", side_effect=AssertionError("real network forbidden")):
        suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps({"schema": 1, "pid": os.getpid(), "testsRun": result.testsRun,
                      "failures": len(result.failures), "errors": len(result.errors),
                      "realNetwork": False, "realRepositoryMutated": False,
                      "installerExecuted": False, "newFees": 0, "paidCredits": 0}))
    sys.exit(0 if result.wasSuccessful() else 1)

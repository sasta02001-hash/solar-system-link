#!/usr/bin/env python3
"""Create-once SSS wrapper prerelease. Never sign, build, load or execute assets.
Only the new fixed push workflow may publish; existing tag/release always refuses.
This source has no stable/feed/old-release mutation route or automatic retry.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = "sasta02001-hash/solar-system-link"
TAG = "sss-installer-v0.5.0-r1"
CLASSIFICATION = "development-single-file-installer-candidate"
NAMES = ("SSS-Setup-050-r1.exe", "SSS-Setup-050-r1.manifest.json", "README-SSS-SETUP.txt", "SHA256SUMS.txt")
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 3 * 1024 * 1024
MAX_REQUEST = 16384
MAX_JSON = 1024 * 1024
API = "https://api.github.com/repos/" + REPOSITORY
UPLOADS = "https://uploads.github.com/repos/" + REPOSITORY
PUBLIC = "https://github.com/" + REPOSITORY + "/releases/download/" + TAG + "/"
TITLE = "SSS 單檔安裝器 0.5.0-r1（開發測試版）"
BODY = "SSS-SINGLE-INSTALLER-V1\n\n新增單檔安裝器交付，內嵌既有 SSS 0.5.0.0 / sequence7，舊目錄與資產不變。\n需已安裝.NET Framework4.8；未加Authenticode。既有<0.4.9.0或reply11移轉入口未閉，OS/POS/普通安裝與SSL重啟重連尚未驗收。\n"
FIXED_FILES = {'SSS-Setup-050-r1.exe': {'size': 1015808, 'sha256': '03023035a7acd5594fbbc7eb22952f1caa0133f58dc1869aa5a49ab02edee040'}, 'SSS-Setup-050-r1.manifest.json': {'size': 4046, 'sha256': 'b8b9cf2507163745f60a31e7be7f0ccd70b09c575b11d5304f2431fe842de7da'}, 'README-SSS-SETUP.txt': {'size': 1846, 'sha256': 'fa1e9b4bb974e683338e49838cbceee85d28815f9ae6aefb2360ca7d48b72b30'}, 'SHA256SUMS.txt': {'size': 271, 'sha256': '2b370bd5358f72aff51f3b2ed40d7be7aa5423c910f3486d2b0bd82a281655b1'}}
EXPECTED_RUNTIME = {'version': '0.5.0.0', 'sequence': 7, 'embeddedInitialZip': {'name': 'SSS-0.5.0.0-Background-Initial-Setup.zip', 'bytes': 866724, 'sha256': 'cc6882d6b61fb0218ca2318a35454d2826de078a85d10814393579b952235781', 'url': 'https://github.com/sasta02001-hash/solar-system-link/releases/download/sss-ui-v0.5.0.0/SSS-0.5.0.0-Background-Initial-Setup.zip'}, 'signedCatalogSha256': '9b99ea951150efe8b36e02d46c9a2a7d46b4ae82955fd454586630140bed147a'}
EXPECTED_SOURCE_EVIDENCE = {'delivery-manifest-r1': {'bytes': 14349, 'sha256': '0f2acb837abd92182d89c71d44cd8c567c44bd8e89d066ba62efb910a8f93fc1'}, 'independent-source-peer-r1': {'bytes': 9322, 'sha256': '7a8437d88c0638336224c845cb20a6ca085da43f2d5ecf69380e440a47af74c8'}, 'candidate-build-receipt-r1': {'bytes': 24711, 'sha256': '586f9d829bb330278be27d91e1690e74015a8f22219159abb934d270c88214cb'}, 'source-preflight-r3': {'bytes': 13183, 'sha256': '41441f189e0b01bb605f00fe4c2903b5fd05e3994330f0d7794cd0dc1468be30'}}


class PublishError(Exception):
    pass


def fail(code):
    raise PublishError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def exact(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        fail("unexpected-fields")


def positive(value, maximum):
    if type(value) is not int or not 1 <= value <= maximum:
        fail("integer-bound")
    return value


def pairs(items):
    result = {}
    for name, value in items:
        if name in result:
            fail("duplicate-json-field")
        result[name] = value
    return result


def parse_json(data, maximum):
    if type(data) is not bytes or not 1 <= len(data) <= maximum:
        fail("json-size")
    try:
        return json.loads(data.decode("utf-8", "strict"), object_pairs_hook=pairs,
                          parse_constant=lambda _: fail("json-constant"))
    except (ValueError, UnicodeError, RecursionError):
        fail("json-format")


def read_local(path, maximum):
    """Read bounded ordinary bytes, never extract or execute a payload."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 1 <= before.st_size <= maximum:
                fail("local-file-type-links-size")
            data = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
            if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or len(data) != before.st_size):
                fail("local-file-changed")
            return data
    except OSError:
        fail("local-file-read")


def validate_inputs(request_bytes, payload_reader):
    request = parse_json(request_bytes, MAX_REQUEST)
    exact(request, ("schema", "product", "tag", "classification", "runtime", "sourceEvidenceDigests", "files"))
    if (type(request["schema"]) is not int or request["schema"] != 1 or request["product"] != "SSS" or
            request["tag"] != TAG or request["classification"] != CLASSIFICATION or
            request["runtime"] != EXPECTED_RUNTIME or request["sourceEvidenceDigests"] != EXPECTED_SOURCE_EVIDENCE):
        fail("request-purpose-or-runtime-source")
    if type(request["files"]) is not list or len(request["files"]) != 4:
        fail("request-inventory")
    contents, total = {}, 0
    for name, row in zip(NAMES, request["files"]):
        exact(row, ("name", "encoding", "size", "sha256"))
        fixed = FIXED_FILES[name]
        if (row["name"] != name or row["encoding"] != "raw" or type(row["size"]) is not int or
                row["size"] != fixed["size"] or row["sha256"] != fixed["sha256"]):
            fail("request-fixed-file-tuple")
        positive(row["size"], MAX_FILE)
        total += row["size"]
        if total > MAX_TOTAL:
            fail("payload-total")
        data = payload_reader(name, row["size"])
        if type(data) is not bytes or len(data) != row["size"] or sha(data) != row["sha256"]:
            fail("payload-size-or-hash")
        contents[name] = data
    if not contents[NAMES[0]].startswith(b"MZ"):
        fail("installer-file-marker")
    public_manifest = parse_json(contents[NAMES[1]], MAX_REQUEST)
    if (public_manifest.get("purpose") != "SSS.SingleFileInstaller.PublicDeliveryManifest.v1" or
            public_manifest.get("runtime") != EXPECTED_RUNTIME or public_manifest.get("releaseTag") != TAG):
        fail("public-manifest-purpose")
    try:
        readme = contents[NAMES[2]].decode("utf-8", "strict")
    except UnicodeError:
        fail("readme-utf8")
    if any(text not in readme for text in ("開發測試版", "0.5.0.0", "sequence 7", ".NET Framework 4.8", "Authenticode", "0.4.9.0", "回覆 11", "尚未完成驗收")):
        fail("readme-limits")
    sums = "".join(sha(contents[name]) + "  " + name + "\n" for name in NAMES[:3]).encode("ascii")
    if contents[NAMES[3]] != sums:
        fail("checksums-inventory")
    return {"request": request, "contents": contents}


def load_inputs(root):
    folder = root / "updates" / "sss-installer"
    payload = folder / "payload"
    for directory in (root, root / "updates", folder, payload):
        if directory.is_symlink() or not directory.is_dir():
            fail("checkout-directory-type")
    return validate_inputs(read_local(folder / "publish-request.json", MAX_REQUEST),
                           lambda name, bound: read_local(payload / name, bound))


def release(value, expected_id=None, expected_commit=None):
    if type(value) is not dict:
        fail("release-shape")
    positive(value.get("id"), 2**63 - 1)
    if (value.get("tag_name") != TAG or value.get("name") != TITLE or value.get("body") != BODY or
            value.get("prerelease") is not True or type(value.get("draft")) is not bool or
            type(value.get("immutable")) is not bool or
            (expected_id is not None and value["id"] != expected_id) or
            (expected_commit is not None and value.get("target_commitish") != expected_commit)):
        fail("release-identity-or-ownership")
    return value


def catalog(values):
    if type(values) is not list or len(values) > len(NAMES):
        fail("asset-inventory")
    result = {}
    for item in values:
        if type(item) is not dict or item.get("name") not in NAMES or item["name"] in result:
            fail("asset-name-or-duplicate")
        positive(item.get("id"), 2**63 - 1)
        positive(item.get("size"), MAX_FILE)
        if item.get("state") != "uploaded":
            fail("asset-state")
        result[item["name"]] = item
    return result


def verify_asset(client, item, expected):
    if item["size"] != len(expected):
        fail("existing-asset-size-conflict")
    digest = item.get("digest")
    if digest is not None and digest != "sha256:" + sha(expected):
        fail("existing-asset-digest-conflict")
    if client.asset_bytes(item["id"], len(expected)) != expected:
        fail("existing-asset-bytes-conflict")


def publish(client, bundle, commit):
    if type(commit) is not str or not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail("commit-format")
    repository = client.repository()
    if (type(repository) is not dict or repository.get("full_name") != REPOSITORY or
            repository.get("private") is not False or repository.get("visibility") != "public" or
            repository.get("archived") is not False):
        fail("public-active-repository-required")
    # Revalidate all exact data before any external mutation, even for a caller-created bundle.
    checked = validate_inputs(json.dumps(bundle["request"], ensure_ascii=False).encode("utf-8"),
                              lambda name, maximum: bundle["contents"][name])
    contents = checked["contents"]
    if client.find_tag() is not None:
        fail("existing-tag-refused-no-replay")
    if client.find_release() is not None:
        fail("existing-release-refused-no-replay")
    current = release(client.create_draft(commit), expected_commit=commit)
    release_id = current["id"]
    if current["draft"] is not True or current["immutable"] or catalog(client.assets(release_id)):
        fail("new-empty-mutable-draft-required")
    for index, name in enumerate(NAMES):
        current = release(client.get_release(release_id), release_id, commit)
        if current["draft"] is not True or current["immutable"]:
            fail("owned-draft-state-changed")
        before = catalog(client.assets(release_id))
        if set(before) != set(NAMES[:index]):
            fail("owned-draft-inventory-changed")
        uploaded = client.upload(release_id, name, contents[name])
        after = catalog(client.assets(release_id))
        if (set(after) != set(NAMES[:index + 1]) or type(uploaded) is not dict or
                uploaded.get("id") != after[name]["id"]):
            fail("upload-identity-unknown")
        for prior in NAMES[:index + 1]:
            verify_asset(client, after[prior], contents[prior])
    current = release(client.get_release(release_id), release_id, commit)
    assets = catalog(client.assets(release_id))
    if current["draft"] is not True or current["immutable"] or set(assets) != set(NAMES):
        fail("complete-owned-draft-required")
    for name in NAMES:
        verify_asset(client, assets[name], contents[name])
    # Draft tags may be deferred by GitHub; any already-visible ref must match.
    ref = client.find_tag()
    if ref is not None:
        verify_tag(ref, commit)
    current = release(client.publish_draft(release_id), release_id, commit)
    if current["draft"]:
        fail("publication-not-confirmed")
    current = release(client.get_release(release_id), release_id, commit)
    if current["draft"]:
        fail("publication-state-changed")
    verify_tag(client.find_tag(), commit)
    assets = catalog(client.assets(release_id))
    if set(assets) != set(NAMES):
        fail("published-inventory-changed")
    rows = []
    for name in NAMES:
        verify_asset(client, assets[name], contents[name])
        if client.public_bytes(name, len(contents[name])) != contents[name]:
            fail("public-readback-conflict")
        rows.append({"name": name, "size": len(contents[name]), "sha256": sha(contents[name]),
                     "url": PUBLIC + urllib.parse.quote(name, safe="")})
    return {"schema": 1, "status": "public-readback-verified", "repository": REPOSITORY,
            "commit": commit, "tag": TAG, "created": True, "releaseId": release_id,
            "files": rows, "classification": CLASSIFICATION, "runtimeVersion": "0.5.0.0",
            "runtimeSequence": 7, "authenticodeSigned": False, "installationOrOsPosAccepted": False}


def verify_tag(value, commit):
    if (type(value) is not dict or value.get("ref") != "refs/tags/" + TAG or
            type(value.get("object")) is not dict or value["object"].get("type") != "commit" or
            value["object"].get("sha") != commit):
        fail("published-tag-commit-unconfirmed")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


class Http:
    def __init__(self, token):
        if not token or any(c.isspace() for c in token):
            fail("ephemeral-workflow-token-required")
        self.token = token
        self.deadline = time.monotonic() + 480
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def fetch(self, url, maximum, method="GET", data=None, authenticated=False, binary=False, redirects=False):
        for hop in range(4):
            parsed = urllib.parse.urlsplit(url)
            if (parsed.scheme != "https" or parsed.port not in (None, 443) or parsed.username or parsed.password or
                    parsed.fragment or parsed.hostname not in ("api.github.com", "uploads.github.com", "github.com",
                                                               "release-assets.githubusercontent.com", "objects.githubusercontent.com")):
                fail("network-origin")
            use_token = authenticated and hop == 0
            if use_token and parsed.hostname not in ("api.github.com", "uploads.github.com"):
                fail("credential-origin")
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                fail("network-deadline")
            headers = {"User-Agent": "SSS-Single-Installer-Publisher-v1", "X-GitHub-Api-Version": "2022-11-28",
                       "Accept": "application/octet-stream" if binary and method == "GET" else "application/vnd.github+json"}
            if use_token:
                headers["Authorization"] = "Bearer " + self.token
            if data is not None:
                headers["Content-Type"] = "application/octet-stream" if binary else "application/json"
            request = urllib.request.Request(url, data=data, method=method, headers=headers)
            try:
                with self.opener.open(request, timeout=min(30, remaining)) as response:
                    value = bytearray()
                    while True:
                        if time.monotonic() >= self.deadline:
                            fail("network-deadline")
                        part = response.read(min(65536, maximum + 1 - len(value)))
                        if time.monotonic() >= self.deadline:
                            fail("network-deadline")
                        if not part:
                            return bytes(value)
                        value.extend(part)
                        if len(value) > maximum:
                            fail("network-response-size")
            except urllib.error.HTTPError as error:
                status = error.code
                location = error.headers.get("Location")
                error.close()
                if status in (301, 302, 303, 307, 308) and redirects and method == "GET" and hop < 3 and location:
                    next_url = urllib.parse.urljoin(url, location)
                    target = urllib.parse.urlsplit(next_url)
                    if target.hostname not in ("release-assets.githubusercontent.com", "objects.githubusercontent.com"):
                        fail("redirect-origin")
                    url = next_url
                    continue
                fail("http-status-" + str(status))
            except (OSError, ValueError):
                fail("network-unavailable")
        fail("redirect-limit")


class GitHub:
    def __init__(self, http):
        self.http = http
        self.create_attempted = False
        self.created_release_id = None
        self.upload_attempts = []
        self.publish_attempted = False

    def api(self, suffix="", method="GET", body=None):
        get_route = suffix == "" or suffix == "/releases/tags/" + TAG or suffix == "/git/ref/tags/" + TAG or re.fullmatch(r"/releases/[1-9][0-9]*(/assets\?per_page=100)?", suffix)
        valid = ((method == "GET" and get_route and body is None) or
                 (method == "POST" and suffix == "/releases" and type(body) is dict and
                  body.get("tag_name") == TAG and body.get("draft") is True) or
                 (method == "PATCH" and re.fullmatch(r"/releases/[1-9][0-9]*", suffix) and
                  body == {"draft": False, "make_latest": "false"}))
        if not valid:
            fail("api-method")
        raw = None if body is None else json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return parse_json(self.http.fetch(API + suffix, MAX_JSON, method, raw, True), MAX_JSON)

    def repository(self):
        return self.api()

    def find_release(self):
        try:
            return self.api("/releases/tags/" + TAG)
        except PublishError as error:
            if str(error) == "http-status-404":
                return None
            raise

    def get_release(self, release_id):
        positive(release_id, 2**63 - 1)
        return self.api("/releases/" + str(release_id))

    def assets(self, release_id):
        positive(release_id, 2**63 - 1)
        # Four expected assets; >=100 or any unknown entry is refused by catalog.
        return self.api("/releases/" + str(release_id) + "/assets?per_page=100")

    def create_draft(self, commit):
        if self.create_attempted:
            fail("create-attempt-already-consumed")
        self.create_attempted = True
        value = self.api("/releases", "POST", {"tag_name": TAG, "target_commitish": commit, "name": TITLE,
                          "body": BODY, "draft": True, "prerelease": True, "make_latest": "false"})
        self.created_release_id = positive(value.get("id"), 2**63 - 1)
        return value

    def owned(self, release_id):
        if type(release_id) is not int or release_id != self.created_release_id:
            fail("only-newly-created-release-may-mutate")

    def find_tag(self):
        try:
            return self.api("/git/ref/tags/" + TAG)
        except PublishError as error:
            if str(error) == "http-status-404":
                return None
            raise

    def upload(self, release_id, name, data):
        self.owned(release_id)
        if name in self.upload_attempts:
            fail("upload-attempt-already-consumed")
        self.upload_attempts.append(name)
        if name not in NAMES or type(data) is not bytes or not 1 <= len(data) <= MAX_FILE:
            fail("upload-input")
        url = UPLOADS + "/releases/" + str(release_id) + "/assets?name=" + urllib.parse.quote(name, safe="")
        return parse_json(self.http.fetch(url, MAX_JSON, "POST", data, True, True), MAX_JSON)

    def asset_bytes(self, asset_id, size):
        positive(asset_id, 2**63 - 1)
        positive(size, MAX_FILE)
        return self.http.fetch(API + "/releases/assets/" + str(asset_id), size, authenticated=True, binary=True, redirects=True)

    def publish_draft(self, release_id):
        self.owned(release_id)
        if self.publish_attempted:
            fail("publish-attempt-already-consumed")
        self.publish_attempted = True
        return self.api("/releases/" + str(release_id), "PATCH", {"draft": False, "make_latest": "false"})

    def public_bytes(self, name, size):
        if name not in NAMES:
            fail("public-name")
        positive(size, MAX_FILE)
        return self.http.fetch(PUBLIC + urllib.parse.quote(name, safe=""), size, binary=True, redirects=True)


def main():
    result = {"schema": 1, "repository": REPOSITORY, "tag": TAG, "status": "not-started"}
    client = None
    try:
        if (len(sys.argv) != 1 or os.environ.get("GITHUB_ACTIONS") != "true" or
                os.environ.get("GITHUB_EVENT_NAME") != "push" or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY or
                os.environ.get("GITHUB_REF") != "refs/heads/main" or
                os.environ.get("GITHUB_RUN_ATTEMPT") != "1" or
                os.environ.get("GITHUB_WORKFLOW_REF") != REPOSITORY + "/.github/workflows/publish-sss-installer.yml@refs/heads/main"):
            fail("fixed-public-push-workflow-required")
        script = Path(__file__).resolve(strict=True)
        root = Path(os.environ.get("GITHUB_WORKSPACE", "")).resolve(strict=True)
        if script != root / "tools" / "sss_installer_publisher.py":
            fail("fixed-checkout-layout")
        bundle = load_inputs(root)
        client = GitHub(Http(os.environ.get("GITHUB_TOKEN", "")))
        result = publish(client, bundle, os.environ.get("GITHUB_SHA", ""))
    except PublishError as error:
        result.update({"status": "failed-or-external-state-unknown", "code": str(error)})
    except Exception as error:
        # Never expose HTTP error text, headers, credentials or signed CDN URLs.
        result.update({"status": "failed-or-external-state-unknown", "code": "unexpected-" + type(error).__name__})
    if result["status"] != "public-readback-verified":
        result["automaticRetryPermitted"] = False
        if client is not None:
            result.update({"createAttempted": client.create_attempted, "knownCreatedReleaseId": client.created_release_id,
                           "uploadAttempts": client.upload_attempts, "publishAttempted": client.publish_attempted})
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0 if result["status"] == "public-readback-verified" else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Fixed public POS development-installer delivery; never build, sign or execute.

This publisher cannot change the SSL update channel or its signed six-file
inventory. Repository authorization is delivery permission, not a signing key.
Only main's fixed push workflow may run main; tests inject a memory-only client.
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
TAG = "ssl-pos-v0.6.8-r1"
CLASSIFICATION = "development-manual-share"
NAMES = (
    "SolarSystemLink-POS-Setup-0.6.8-r1.exe",
    "SolarSystemLink-POS-Setup-0.6.8-r1.zip",
    "README-SETUP.txt",
    "SHA256SUMS.txt",
)
MAX_FILE = 5 * 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024
MAX_REQUEST = 16384
MAX_JSON = 1024 * 1024
API = "https://api.github.com/repos/" + REPOSITORY
UPLOADS = "https://uploads.github.com/repos/" + REPOSITORY
PUBLIC = "https://github.com/" + REPOSITORY + "/releases/download/" + TAG + "/"
TITLE = "Solar System Link POS 0.6.8-r1（手動分享開發測試版）"
NOTICE = (
    "POS 手動分享開發測試版",
    "不含 SSS",
    "不是無人值守",
    "尚未完成 POS 實機驗收",
)
README_MARKERS = ("每次連線仍須", "不是完整 SSS", "無人值守", "實機", "0.6.8")
BODY = "SSL-POS-INSTALLER-V1\n\n" + "\n".join(NOTICE) + "\n"


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
    """Pure validation. Reader receives a derived basename and an encoded bound."""
    request = parse_json(request_bytes, MAX_REQUEST)
    exact(request, ("schema", "tag", "classification", "files"))
    if type(request["schema"]) is not int or request["schema"] != 1 or request["tag"] != TAG or request["classification"] != CLASSIFICATION:
        fail("request-purpose")
    rows = request["files"]
    if type(rows) is not list or len(rows) != len(NAMES):
        fail("request-inventory")
    contents, total = {}, 0
    for expected, row in zip(NAMES, rows):
        exact(row, ("name", "encoding", "size", "sha256"))
        if row["name"] != expected or row["encoding"] not in ("raw", "base64"):
            fail("request-name-or-encoding")
        size = positive(row["size"], MAX_FILE)
        total += size
        if total > MAX_TOTAL:
            fail("request-total-size")
        if type(row["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"]):
            fail("request-digest")
        encoded = row["encoding"] == "base64"
        bound = 4 * ((MAX_FILE + 2) // 3) if encoded else MAX_FILE
        data = payload_reader(expected + (".b64" if encoded else ""), bound)
        if type(data) is not bytes or not 1 <= len(data) <= bound:
            fail("payload-encoded-size")
        if encoded:
            try:
                decoded = base64.b64decode(data, validate=True)
            except ValueError:
                fail("payload-base64")
            if base64.b64encode(decoded) != data:
                fail("payload-base64-canonical")
            data = decoded
        if len(data) != size or sha(data) != row["sha256"]:
            fail("payload-size-or-hash")
        contents[expected] = data
    if not contents[NAMES[0]].startswith(b"MZ") or not contents[NAMES[1]].startswith(b"PK\x03\x04"):
        fail("payload-file-marker")
    try:
        readme = contents[NAMES[2]].decode("utf-8-sig", "strict")
    except UnicodeError:
        fail("readme-utf8")
    if readme.startswith("\ufeff") or any(note not in readme for note in README_MARKERS):
        fail("readme-development-notice")
    checksums = "".join(sha(contents[name]) + "  " + name + "\n" for name in NAMES[:3]).encode("ascii")
    if contents[NAMES[3]] != checksums:
        fail("checksums-inventory")
    return {"request": request, "contents": contents}


def load_inputs(root):
    folder = root / "updates" / "ssl-pos"
    payload = folder / "payload"
    for directory in (root, root / "updates", folder, payload):
        if directory.is_symlink() or not directory.is_dir():
            fail("checkout-directory-type")
    return validate_inputs(read_local(folder / "publish-request.json", MAX_REQUEST),
                           lambda name, bound: read_local(payload / name, bound))


def release(value, expected_id=None):
    if type(value) is not dict:
        fail("release-shape")
    positive(value.get("id"), 2**63 - 1)
    if (value.get("tag_name") != TAG or value.get("name") != TITLE or value.get("body") != BODY or
            value.get("prerelease") is not True or type(value.get("draft")) is not bool or
            type(value.get("immutable")) is not bool or
            (expected_id is not None and value["id"] != expected_id)):
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
    repo = client.repository()
    if (type(repo) is not dict or repo.get("full_name") != REPOSITORY or repo.get("private") is not False or
            repo.get("visibility") != "public" or repo.get("archived") is not False):
        fail("public-active-repository-required")
    contents = bundle["contents"]
    if set(contents) != set(NAMES):
        fail("validated-bundle-required")
    found = client.find_release()
    created = found is None
    current = release(client.create_draft(commit) if created else found)
    release_id = current["id"]
    assets = catalog(client.assets(release_id))
    if not current["draft"] and set(assets) != set(NAMES):
        fail("published-release-incomplete")
    # Verify EVERY existing byte before any upload or release-state mutation.
    for name, item in assets.items():
        verify_asset(client, item, contents[name])
    for name in NAMES:
        if name in assets:
            continue
        current = release(client.get_release(release_id), release_id)
        if not current["draft"] or current["immutable"]:
            fail("mutable-owned-draft-required")
        uploaded = client.upload(release_id, name, contents[name])
        after = catalog(client.assets(release_id))
        if name not in after or type(uploaded) is not dict or uploaded.get("id") != after[name]["id"]:
            fail("upload-identity-unknown")
        assets = after
        verify_asset(client, assets[name], contents[name])
    current = release(client.get_release(release_id), release_id)
    assets = catalog(client.assets(release_id))
    if set(assets) != set(NAMES):
        fail("complete-four-assets-required")
    for name in NAMES:
        verify_asset(client, assets[name], contents[name])
    if current["draft"]:
        if current["immutable"]:
            fail("immutable-draft-refused")
        current = release(client.publish_draft(release_id), release_id)
    if current["draft"]:
        fail("publication-not-confirmed")
    # Final current state AND full public download, not API success alone.
    current = release(client.get_release(release_id), release_id)
    if current["draft"]:
        fail("publication-state-changed")
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
            "commit": commit, "tag": TAG, "created": created,
            "releaseId": release_id, "files": rows, "classification": CLASSIFICATION,
            "sssIncludedOrUnattendedOrPosAcceptanceClaimed": False}


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
            headers = {"User-Agent": "SSL-POS-Installer-Publisher-v1", "X-GitHub-Api-Version": "2022-11-28",
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

    def api(self, suffix="", method="GET", body=None):
        get_route = suffix == "" or suffix == "/releases/tags/" + TAG or re.fullmatch(r"/releases/[1-9][0-9]*(/assets\?per_page=100)?", suffix)
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
        return self.api("/releases", "POST", {"tag_name": TAG, "target_commitish": commit, "name": TITLE,
                        "body": BODY, "draft": True, "prerelease": True, "make_latest": "false"})

    def upload(self, release_id, name, data):
        positive(release_id, 2**63 - 1)
        if name not in NAMES or type(data) is not bytes or not 1 <= len(data) <= MAX_FILE:
            fail("upload-input")
        url = UPLOADS + "/releases/" + str(release_id) + "/assets?name=" + urllib.parse.quote(name, safe="")
        return parse_json(self.http.fetch(url, MAX_JSON, "POST", data, True, True), MAX_JSON)

    def asset_bytes(self, asset_id, size):
        positive(asset_id, 2**63 - 1)
        positive(size, MAX_FILE)
        return self.http.fetch(API + "/releases/assets/" + str(asset_id), size, authenticated=True, binary=True, redirects=True)

    def publish_draft(self, release_id):
        positive(release_id, 2**63 - 1)
        return self.api("/releases/" + str(release_id), "PATCH", {"draft": False, "make_latest": "false"})

    def public_bytes(self, name, size):
        if name not in NAMES:
            fail("public-name")
        positive(size, MAX_FILE)
        return self.http.fetch(PUBLIC + urllib.parse.quote(name, safe=""), size, binary=True, redirects=True)


def main():
    result = {"schema": 1, "repository": REPOSITORY, "tag": TAG, "status": "not-started"}
    try:
        if (len(sys.argv) != 1 or os.environ.get("GITHUB_ACTIONS") != "true" or
                os.environ.get("GITHUB_EVENT_NAME") != "push" or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY or
                os.environ.get("GITHUB_REF") != "refs/heads/main"):
            fail("fixed-public-push-workflow-required")
        script = Path(__file__).resolve(strict=True)
        root = Path(os.environ.get("GITHUB_WORKSPACE", "")).resolve(strict=True)
        if script != root / "tools" / "pos_installer_publisher.py":
            fail("fixed-checkout-layout")
        bundle = load_inputs(root)
        result = publish(GitHub(Http(os.environ.get("GITHUB_TOKEN", ""))), bundle, os.environ.get("GITHUB_SHA", ""))
    except PublishError as error:
        result.update({"status": "failed-or-external-state-unknown", "code": str(error)})
    except Exception as error:
        # Never expose HTTP error text, headers, credentials or signed CDN URLs.
        result.update({"status": "failed-or-external-state-unknown", "code": "unexpected-" + type(error).__name__})
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0 if result["status"] == "public-readback-verified" else 1


if __name__ == "__main__":
    sys.exit(main())

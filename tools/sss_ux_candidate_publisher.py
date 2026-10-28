#!/usr/bin/env python3
"""Frozen nine-asset SSS UX candidate delivery; never build/sign/execute.

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
TAG = "sss-ux-0.4.5-r2"
CLASSIFICATION = "development-ux-candidate"
# Exact Root-authorized PublicAssets only. Repository permission is delivery,
# never SSS maintenance/trust or evidence that native protection is enabled.
# kind: exe | zip | readme | checksums | catalog.
FROZEN_ASSETS = (
    ("download-catalog.json", 2136, "b72dfbbdf8a72157ba0fcab762e48a6e6fdfe9abba7bcff695665c73fd9a3497", "catalog"),
    ("README-DOWNLOADS.zh-TW.md", 1828, "f80bcb4b8e8cd2b2f53cfffe3103962386344318edc8efb59ab0613ec5d3be88", "readme"),
    ("sha256.txt", 596, "025e3f4156a65900cec05eed1508b8a43f4a2933a018d33f254b48e5061cc929", "checksums"),
    ("SSS-0.4.5-UX-Auto-Setup-r3.exe", 1448428, "5ebed1f9df2f7e6904a9cb28c81b68bc72ed237fab4b07fe84c2e19c08e72ee6", "exe"),
    ("SSS-0.4.5-UX-Auto-Setup-r3.zip", 2686368, "b40ea3c7db26aefd91cb4eed56c61383da98f283fd96a04ff49a70ab8f2a97ab", "zip"),
    ("SSS-0.4.5-UX-Win10-11-Setup-r2.exe", 936327, "8ef3a31c7e18190103a9345f9f8ee5b8dd4c046a97f56adb74e62c0d9d95cd16", "exe"),
    ("SSS-0.4.5-UX-Win10-11-Setup-r2.zip", 1164728, "9cc645f2673befbe023f75307f98ea80ee8113f56a425070f712f102c857af85", "zip"),
    ("SSS-0.4.5-UX-Win7-Setup-r2.exe", 934235, "c56847eb33b95254ad49214a73892f8cba42f253da9108b49ce684198ba674d6", "exe"),
    ("SSS-0.4.5-UX-Win7-Setup-r2.zip", 1162591, "f3798ee5a95f2df5c518ea5491da1eb9cac7bcfba4203d8ddceb1244e671137c", "zip"),
)
FROZEN_README_MARKERS = ("SSS 0.4.5 UX 開發候選版", "Windows 7 POS 實機驗收尚未完成", "正式 Ready 尚未啟用", "SSS 協助 SSL 更新後重啟及重連", "未包含於此版")
FROZEN_VARIANTS = (
    ("Auto", ("SSS-0.4.5-UX-Auto-Setup-r3.exe", "SSS-0.4.5-UX-Auto-Setup-r3.zip")),
    ("Win7", ("SSS-0.4.5-UX-Win7-Setup-r2.exe", "SSS-0.4.5-UX-Win7-Setup-r2.zip")),
    ("Win10-11", ("SSS-0.4.5-UX-Win10-11-Setup-r2.exe", "SSS-0.4.5-UX-Win10-11-Setup-r2.zip")),
)
# Reviewed public main-branch companion, deliberately not a tenth release asset.
SUPPORT_PROFILE = ("runtime-profile.json", 3095, "3b9072688b23570813c55a4047b4ec92f995f526bec24a5e6131beba7d6fcb83")
MAX_FILE = 5 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_REQUEST = 16384
MAX_JSON = 1024 * 1024
API = "https://api.github.com/repos/" + REPOSITORY
UPLOADS = "https://uploads.github.com/repos/" + REPOSITORY
PUBLIC = "https://github.com/" + REPOSITORY + "/releases/download/" + TAG + "/"
TITLE = "SSS 0.4.5 UX r2（開發候選版）"
NOTICE = (
    "SSS 自動偵測與分系統安裝介面開發候選版",
    "不是 SSS 正式安全發行或正式信任授權",
    "不變更 SSL 更新頻道、SSS 維修金鑰或正式信任",
    "尚未完成 POS 實機與持續操作驗收",
)
BODY = "SSS-UX-CANDIDATE-V1\n\n" + "\n".join(NOTICE) + "\n"


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


def frozen():
    """Validate source-owned pins before any payload read or network operation."""
    if type(FROZEN_ASSETS) is not tuple or not 4 <= len(FROZEN_ASSETS) <= 9:
        fail("candidate-final-tuple-not-frozen")
    result, total, folded = {}, 0, set()
    for row in FROZEN_ASSETS:
        if type(row) is not tuple or len(row) != 4:
            fail("frozen-row")
        name, size, digest, kind = row
        if (type(name) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}", name) or
                name.casefold() in folded or kind not in ("exe", "zip", "readme", "checksums", "catalog")):
            fail("frozen-name-kind")
        positive(size, MAX_FILE)
        if type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest):
            fail("frozen-digest")
        if (kind == "exe" and not name.endswith(".exe")) or (kind == "zip" and not name.endswith(".zip")):
            fail("frozen-extension")
        total += size
        result[name] = row
        folded.add(name.casefold())
    kinds = [r[3] for r in result.values()]
    if total > MAX_TOTAL or kinds.count("readme") != 1 or kinds.count("checksums") != 1 or kinds.count("catalog") != 1 or "exe" not in kinds or "zip" not in kinds:
        fail("frozen-inventory")
    if (type(FROZEN_README_MARKERS) is not tuple or not FROZEN_README_MARKERS or
            any(type(m) is not str or not 1 <= len(m) <= 120 for m in FROZEN_README_MARKERS)):
        fail("frozen-notice-markers")
    if (type(FROZEN_VARIANTS) is not tuple or tuple(r[0] for r in FROZEN_VARIANTS) != ("Auto", "Win7", "Win10-11") or
            any(type(r) is not tuple or len(r) != 2 or type(r[1]) is not tuple or len(r[1]) != 2 for r in FROZEN_VARIANTS)):
        fail("frozen-variants")
    variant_names = [n for _, pair in FROZEN_VARIANTS for n in pair]
    if len(set(variant_names)) != 6 or set(variant_names) != {n for n, r in result.items() if r[3] in ("exe", "zip")}:
        fail("frozen-variant-inventory")
    if any(tuple(result[n][3] for n in pair) != ("exe", "zip") for _, pair in FROZEN_VARIANTS):
        fail("frozen-variant-kinds")
    return result


def names():
    return tuple(frozen())


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


def validate_catalog(data, pins):
    """Closed public catalog; local test evidence is not native/POS acceptance."""
    value = parse_json(data, MAX_REQUEST)
    exact(value, ("Schema", "Product", "Version", "Stage", "Recommended", "Selection",
                  "MinimumNetFrameworkRelease", "Targets", "NativeProtectionEnabled", "ProductionReady",
                  "SssAssistedSslRecoveryImplemented", "Assets", "AdditionalFees", "PaidCredits", "ExactTaskTokens", "PackagingRevision"))
    if (type(value["Schema"]) is not int or value["Schema"] != 1 or value["Product"] != "Solar System Shield" or
            value["Version"] != "0.4.5 UX" or value["Stage"] != "Development candidate" or
            value["Selection"] != "Installer reads actual Windows, native architecture, client type, .NET and package identity; compatible child files are verified before launch" or
            type(value["MinimumNetFrameworkRelease"]) is not int or value["MinimumNetFrameworkRelease"] != 528040 or
            any(value[k] is not False for k in ("NativeProtectionEnabled", "ProductionReady", "SssAssistedSslRecoveryImplemented")) or
            any(type(value[k]) is not int or value[k] != 0 for k in ("AdditionalFees", "PaidCredits")) or value["ExactTaskTokens"] is not None or
            value["PackagingRevision"] != "Corrected portable desktop installer and public four-file Win7 package"):
        fail("catalog-development-purpose")
    targets = [{"Variant": "Win7", "OS": "Windows 7 SP1", "Architecture": "x64", "MinimumBuild": 7601,
                "MinimumServicePack": 1, "ActualWin7Accepted": False},
               {"Variant": "Win10-11", "OS": "Windows 10 or Windows 11", "Architecture": "x64", "MinimumBuild": 19041,
                "ActualOrdinaryWindows11Installed": True}]
    # Canonical JSON comparison keeps booleans distinct from Python integers.
    if json.dumps(value["Targets"], sort_keys=True) != json.dumps(targets, sort_keys=True):
        fail("catalog-targets")
    expected = {n for n, r in pins.items() if r[3] in ("exe", "zip")}
    assets = value["Assets"]
    if type(assets) is not list or len(assets) != len(expected):
        fail("catalog-inventory")
    seen = set()
    source_variants = {n: role for role, pair in FROZEN_VARIANTS for n in pair}
    ordered = []
    for row in assets:
        exact(row, ("Name", "Bytes", "SHA256"))
        name = row["Name"]
        if type(name) is not str or name not in expected or name in seen:
            fail("catalog-asset-name-or-variant")
        positive(row["Bytes"], MAX_FILE)
        if (row["Bytes"] != pins[name][1] or type(row["SHA256"]) is not str or
                not re.fullmatch(r"[0-9A-F]{64}", row["SHA256"]) or row["SHA256"].lower() != pins[name][2]):
            fail("catalog-asset-pin")
        seen.add(name)
        ordered.append(name)
    if seen != expected:
        fail("catalog-variant-pairs")
    recommended = value["Recommended"]
    if type(recommended) is not str or recommended not in expected or pins[recommended][3] != "exe":
        fail("catalog-recommended")
    if source_variants[recommended] != "Auto":
        fail("catalog-recommended-variant")
    return ordered


def validate_inputs(request_bytes, payload_reader):
    """Pure validation. Reader receives a derived basename and an encoded bound."""
    pins = frozen()
    request = parse_json(request_bytes, MAX_REQUEST)
    exact(request, ("schema", "tag", "classification", "files"))
    if type(request["schema"]) is not int or request["schema"] != 1 or request["tag"] != TAG or request["classification"] != CLASSIFICATION:
        fail("request-purpose")
    rows = request["files"]
    if type(rows) is not list or len(rows) != len(pins):
        fail("request-inventory")
    contents, total = {}, 0
    for expected, row in zip(pins, rows):
        exact(row, ("name", "encoding", "size", "sha256"))
        if row["name"] != expected or row["encoding"] not in ("raw", "base64"):
            fail("request-name-or-encoding")
        size = positive(row["size"], MAX_FILE)
        total += size
        if total > MAX_TOTAL:
            fail("request-total-size")
        if (row["size"], row["sha256"]) != pins[expected][1:3]:
            fail("request-digest")
        encoded = row["encoding"] == "base64"
        bound = 4 * ((size + 2) // 3) if encoded else size
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
    readme_name = next(n for n, r in pins.items() if r[3] == "readme")
    checksum_name = next(n for n, r in pins.items() if r[3] == "checksums")
    for name, (_, _, _, kind) in pins.items():
        if (kind == "exe" and not contents[name].startswith(b"MZ")) or (kind == "zip" and not contents[name].startswith(b"PK\x03\x04")):
            fail("payload-file-marker")
    try:
        readme = contents[readme_name].decode("utf-8-sig", "strict")
    except UnicodeError:
        fail("readme-utf8")
    if readme.startswith("\ufeff") or any(note not in readme for note in FROZEN_README_MARKERS):
        fail("readme-development-notice")
    catalog_name = next(n for n, r in pins.items() if r[3] == "catalog")
    ordered = validate_catalog(contents[catalog_name], pins)
    checksums = "".join(sha(contents[name]).upper() + "  " + name + "\r\n" for name in ordered).encode("ascii")
    if contents[checksum_name] != checksums:
        fail("checksums-inventory")
    return {"request": request, "contents": contents}


def load_inputs(root):
    folder = root / "updates" / "sss-ux"
    payload = folder / "payload"
    for directory in (root, root / "updates", folder, payload):
        if directory.is_symlink() or not directory.is_dir():
            fail("checkout-directory-type")
    seen = set()
    def reader(name, bound):
        seen.add(name)
        return read_local(payload / name, bound)
    bundle = validate_inputs(read_local(folder / "publish-request.json", MAX_REQUEST), reader)
    profile = read_local(folder / SUPPORT_PROFILE[0], SUPPORT_PROFILE[1])
    if len(profile) != SUPPORT_PROFILE[1] or sha(profile) != SUPPORT_PROFILE[2]:
        fail("support-profile-pin")
    if set(p.name for p in payload.iterdir()) != seen or set(p.name for p in folder.iterdir()) != {"publish-request.json", "payload", SUPPORT_PROFILE[0]}:
        fail("checkout-extra-files")
    return bundle


def release(value, commit, expected_id=None):
    if type(value) is not dict:
        fail("release-shape")
    positive(value.get("id"), 2**63 - 1)
    if (value.get("tag_name") != TAG or value.get("name") != TITLE or value.get("body") != BODY or value.get("target_commitish") != commit or
            value.get("prerelease") is not True or type(value.get("draft")) is not bool or
            type(value.get("immutable")) is not bool or
            (expected_id is not None and value["id"] != expected_id)):
        fail("release-identity-or-ownership")
    return value


def catalog(values):
    expected = names()
    if type(values) is not list or len(values) > len(expected):
        fail("asset-inventory")
    result, ids = {}, set()
    for item in values:
        if type(item) is not dict or item.get("name") not in expected or item["name"] in result:
            fail("asset-name-or-duplicate")
        positive(item.get("id"), 2**63 - 1)
        if item["id"] in ids:
            fail("asset-duplicate-id")
        ids.add(item["id"])
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
    pins = frozen()
    if type(commit) is not str or not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail("commit-format")
    exact(bundle, ("request", "contents"))
    # Revalidate all bytes and source pins. A forged in-memory "bundle" cannot
    # skip the exact request/signature-independent delivery allowlist.
    contents = bundle["contents"]
    if type(contents) is not dict or set(contents) != set(pins) or any(type(b) is not bytes for b in contents.values()):
        fail("validated-bundle-required")
    raw_payload = {n: b for n, b in contents.items()}
    raw_payload.update({n + ".b64": base64.b64encode(b) for n, b in contents.items()})
    checked = validate_inputs(json.dumps(bundle["request"], ensure_ascii=False, separators=(",", ":")).encode("utf-8"), lambda n, _: raw_payload[n])
    if checked["contents"] != contents:
        fail("validated-bundle-required")
    repo = client.repository()
    if (type(repo) is not dict or repo.get("full_name") != REPOSITORY or repo.get("private") is not False or
            repo.get("visibility") != "public" or repo.get("archived") is not False):
        fail("public-active-repository-required")
    contents = bundle["contents"]
    if set(contents) != set(pins):
        fail("validated-bundle-required")
    found = client.find_release()
    created = found is None
    current = release(client.create_draft(commit) if created else found, commit)
    release_id = current["id"]
    assets = catalog(client.assets(release_id))
    if not current["draft"] and set(assets) != set(pins):
        fail("published-release-incomplete")
    # Verify EVERY existing byte before any upload or release-state mutation.
    for name, item in assets.items():
        verify_asset(client, item, contents[name])
    for name in pins:
        if name in assets:
            continue
        current = release(client.get_release(release_id), commit, release_id)
        if not current["draft"] or current["immutable"]:
            fail("mutable-owned-draft-required")
        uploaded = client.upload(release_id, name, contents[name])
        after = catalog(client.assets(release_id))
        if name not in after or type(uploaded) is not dict or uploaded.get("id") != after[name]["id"]:
            fail("upload-identity-unknown")
        assets = after
        verify_asset(client, assets[name], contents[name])
    current = release(client.get_release(release_id), commit, release_id)
    assets = catalog(client.assets(release_id))
    if set(assets) != set(pins):
        fail("complete-frozen-assets-required")
    for name in pins:
        verify_asset(client, assets[name], contents[name])
    if current["draft"]:
        if current["immutable"]:
            fail("immutable-draft-refused")
        current = release(client.publish_draft(release_id), commit, release_id)
    if current["draft"]:
        fail("publication-not-confirmed")
    # Final current state AND full public download, not API success alone.
    current = release(client.get_release(release_id), commit, release_id)
    if current["draft"]:
        fail("publication-state-changed")
    assets = catalog(client.assets(release_id))
    if set(assets) != set(pins):
        fail("published-inventory-changed")
    rows = []
    for name in pins:
        verify_asset(client, assets[name], contents[name])
        if client.public_bytes(name, len(contents[name])) != contents[name]:
            fail("public-readback-conflict")
        rows.append({"name": name, "size": len(contents[name]), "sha256": sha(contents[name]),
                     "url": PUBLIC + urllib.parse.quote(name, safe="")})
    return {"schema": 1, "status": "public-readback-verified", "repository": REPOSITORY,
            "commit": commit, "tag": TAG, "created": created,
            "releaseId": release_id, "files": rows, "classification": CLASSIFICATION,
            "formalSssTrustOrNativeReadyOrPosAcceptanceClaimed": False}


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
            headers = {"User-Agent": "SSS-UX-Candidate-Publisher-v1", "X-GitHub-Api-Version": "2022-11-28",
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
        frozen()
        get_route = suffix == "" or suffix == "/releases/tags/" + TAG or re.fullmatch(r"/releases/[1-9][0-9]*(/assets\?per_page=100)?", suffix)
        valid = ((method == "GET" and get_route and body is None) or
                 (method == "POST" and suffix == "/releases" and type(body) is dict and
                  set(body) == {"tag_name", "target_commitish", "name", "body", "draft", "prerelease", "make_latest"} and
                  body.get("tag_name") == TAG and body.get("draft") is True and body.get("prerelease") is True and
                  body.get("name") == TITLE and body.get("body") == BODY and body.get("make_latest") == "false" and
                  type(body.get("target_commitish")) is str and re.fullmatch(r"[0-9a-f]{40}", body["target_commitish"])) or
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
        # At most nine exact assets; unknown/paginated inventories are refused.
        return self.api("/releases/" + str(release_id) + "/assets?per_page=100")

    def create_draft(self, commit):
        return self.api("/releases", "POST", {"tag_name": TAG, "target_commitish": commit, "name": TITLE,
                        "body": BODY, "draft": True, "prerelease": True, "make_latest": "false"})

    def upload(self, release_id, name, data):
        positive(release_id, 2**63 - 1)
        pins = frozen()
        if (name not in pins or type(data) is not bytes or len(data) != pins[name][1] or sha(data) != pins[name][2]):
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
        if name not in names():
            fail("public-name")
        positive(size, MAX_FILE)
        return self.http.fetch(PUBLIC + urllib.parse.quote(name, safe=""), size, binary=True, redirects=True)


def main():
    result = {"schema": 1, "repository": REPOSITORY, "tag": TAG, "status": "not-started"}
    try:
        # Source-owned nine-file pins, not request/env-selected assets.
        frozen()
        if (len(sys.argv) != 1 or os.environ.get("GITHUB_ACTIONS") != "true" or
                os.environ.get("GITHUB_EVENT_NAME") != "push" or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY or
                os.environ.get("GITHUB_REF") != "refs/heads/main"):
            fail("fixed-public-push-workflow-required")
        script = Path(__file__).resolve(strict=True)
        root = Path(os.environ.get("GITHUB_WORKSPACE", "")).resolve(strict=True)
        if script != root / "tools" / "sss_ux_candidate_publisher.py":
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

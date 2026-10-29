#!/usr/bin/env python3
"""Publish one reviewed SSL bundle. No signing, installation, or SSS operations.

This file is intended to live at tools/ssl_release_publisher.py in the one fixed
public repository. Network mutations occur only through main(), from the
fixed push workflow. A shell launch, upload, or API success is never a remote
control acceptance result. A mutable feed rotation has a possible 404 window.
"""

import base64
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request


REPOSITORY = "sasta02001-hash/solar-system-link"
API = "https://api.github.com"
UPLOADS = "https://uploads.github.com"
PUBLIC = "https://github.com/" + REPOSITORY + "/releases/download/"
API_VERSION = "2022-11-28"
STABLE_TAG = "ssl-stable"
ENVELOPE_NAME = "ssl-update-v1.json"
PUBLIC_KEY_ID = "70a8216d99566b51fec4cbd66ba5487c488f0d920fdf0cd817c580bea9002c7b"
PUBLIC_DER = base64.b64decode(
    "MIIBCgKCAQEApHgcxqkBJfRRPRmOyRP7KgDhrOEibieXswBCM90MAzwwaP1zkkJa7GiYDCjlTFhgBEksTLuKmO10GwXuJDpPxZfxjM4yb5QbnxkWKGla5ef7CKTbxGtF3yyvtE9F012dBWpCJOr1d2iD7xKBj6uAWHF/nlSNvQHnoVdyp67Qk/9pBQgtQJZw3083nfjeiepa4qAhNpvcV++N1bc5oAbMYr4euw8olr1KYceZpihoXYrfBn6jkpVV5m+m9uPSo5Noo8pz9dlVe9aE9vQXMqniB9TCDewP0BT5RExTMBgAl97BX5y5gXZqpB8ahx8qUO1wYccscq3oitH1yX0QP67d6QIDAQAB"
)
FILES = (
    "SSS.RemoteAuthorization.dll",
    "SSS.RemoteManagement.exe",
    "SSS.RemoteManagement.exe.config",
    "SolarSystemLink.Controller.exe",
    "SolarSystemLink.Controller.exe.config",
    "SolarSystemLink.Remote.dll",
)
MAX_FILE = 20 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_ENVELOPE = 65536
MAX_ARCHIVE = MAX_TOTAL + 1024 * 1024
MAX_TAR = MAX_ARCHIVE
MAX_JSON = 4 * 1024 * 1024
MAX_ASSETS = 1000
MARKER = "SSL-PUBLISHER-V1: signed update assets; no SSS release ownership."
RELEASE_BODY = (MARKER + "\n\n"
    "Solar System Link 維護發行\n\n"
    "本次維護範圍為已核准的品牌、動態視覺與更新入口回饋；保留既有裝置授權及綁定。\n\n"
    "SSS 正式 C1／Ready 與 Windows 7 POS 的持續鍵盤滑鼠操作仍待實機驗收。"
    "這次發行不代表上述驗收完成，也不代表軟體已達 100 分。\n\n"
    "更新器會沿用既有固定公鑰、套件驗證及回復機制。")
RELEASE_BODY_070 = (MARKER + "\n\n"
    "Solar System Link 0.7.0 維護發行\n\n"
    "主控開始連線前會先準備本機 SSS，核對公開最新版，必要時透過固定信任更新器更新並啟動背景程序。"
    "需要正常結束舊 SSS 或尚未完成驗證時會保持等待；取得新鮮有效證據後才開始連線。\n\n"
    "認證後的對端同樣須通過 SSS 最新版與背景狀態檢查。"
    "鍵盤滑鼠操作沿用既有裝置信任及有效操作授權；SSS 狀態檢查不會自行授予操作權限。\n\n"
    "加入已簽署線上更新、正常退出後重新開啟及有限重連。"
    "重新開啟或重連不會自行恢復鍵盤滑鼠操作允許。\n\n"
    "Windows 7 POS 的實際連線、鍵鼠及持續操作仍須實機驗收。"
    "本次發行不代表 Native C1／Ready 已驗收，也不宣稱軟體已達 100 分。\n\n"
    "保留既有裝置綁定、固定更新公鑰、完整套件驗證及回復機制。")


RELEASE_BODY_071 = (MARKER + "\n\n"
    "Solar System Link 0.7.1 維護修復發行\n\n"
    "修正 Windows 執行期的框架中繼資料，並整合 SSS 0.4.7 新版固定啟動元件與正常移轉流程。"
    "連線前仍先核對及準備本機 SSS，取得最新版本與真正背景程序的新鮮證據後才開始連線；"
    "認證後也核對對端 SSS。\n\n"
    "保留既有固定更新公鑰、完整簽章與套件驗證、裝置信任和有效操作授權。"
    "不強制結束舊 SSS，不因背景或版本檢查自行授予鍵盤滑鼠權限。\n\n"
    "Windows 7 POS 實際更新、連線、鍵鼠及持續操作仍待實機驗收；"
    "本次發行不代表 Native C1／Ready 或100分已完成。")


def version_body(tag):
    """Only reviewed version copy changes; stable and070 ownership stay exact."""
    if tag == "ssl-v0.7.1.0":
        return RELEASE_BODY_071
    return RELEASE_BODY_070 if tag == "ssl-v0.7.0.0" else RELEASE_BODY


HEX64 = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,4})(?:\.(?:0|[1-9][0-9]{0,4})){3}\Z")
POSITIVE = re.compile(r"[1-9][0-9]{0,17}\Z")


class PublishError(Exception):
    """A fixed diagnostic code; never include token, signed URL, or API body."""


def fail(code):
    raise PublishError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


def object_pairs(pairs):
    result = {}
    folded = set()
    for key, value in pairs:
        if not isinstance(key, str) or key.casefold() in folded:
            fail("json-duplicate-or-case-collision")
        folded.add(key.casefold())
        result[key] = value
    return result


def reject_scalar(_):
    fail("json-noninteger-scalar")


def parse_json(data, limit, canonical_required=False):
    if not isinstance(data, bytes) or not 1 <= len(data) <= limit:
        fail("json-size")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=object_pairs,
                           parse_float=reject_scalar, parse_constant=reject_scalar)
    except (UnicodeError, ValueError, RecursionError):
        fail("json-syntax")
    if canonical_required and canonical(value) != data:
        fail("json-noncanonical")
    return value


def exact(obj, names):
    if not isinstance(obj, dict) or tuple(obj) != tuple(names):
        fail("json-fields-or-order")


def text(value):
    if not isinstance(value, str):
        fail("text-type")
    return value


def digest(value):
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        fail("sha256-format")
    return value


def positive(value, maximum):
    if not isinstance(value, str) or not POSITIVE.fullmatch(value):
        fail("positive-format")
    number = int(value)
    if number > maximum:
        fail("positive-bound")
    return number


def version(value):
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        fail("version-format")
    parts = tuple(int(part) for part in value.split("."))
    if any(part > 65535 for part in parts):
        fail("version-bound")
    return parts


def b64(value, maximum):
    try:
        result = base64.b64decode(text(value), validate=True)
    except (ValueError, UnicodeError):
        fail("base64-format")
    if not result or len(result) > maximum or base64.b64encode(result).decode("ascii") != value:
        fail("base64-noncanonical-or-size")
    return result


def verify_envelope(data):
    """Verify the existing SSL format using only the fixed public RSA key."""
    if (len(PUBLIC_DER) != 270 or sha(PUBLIC_DER) != PUBLIC_KEY_ID or
            PUBLIC_DER[:9] != bytes.fromhex("3082010a0282010100") or
            PUBLIC_DER[-5:] != bytes.fromhex("0203010001")):
        fail("compiled-public-key-pin")
    envelope = parse_json(data, MAX_ENVELOPE, True)
    exact(envelope, ("schema", "keyId", "manifest", "signature"))
    if type(envelope["schema"]) is not int or envelope["schema"] != 1 or envelope["keyId"] != PUBLIC_KEY_ID:
        fail("envelope-schema-or-key")
    payload = b64(envelope["manifest"], 32768)
    signature = b64(envelope["signature"], 256)
    if len(signature) != 256:
        fail("signature-size")
    modulus = int.from_bytes(PUBLIC_DER[9:265], "big")
    signature_number = int.from_bytes(signature, "big")
    if signature_number >= modulus:
        fail("signature-range")
    decoded = pow(signature_number, 65537, modulus).to_bytes(256, "big")
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(payload).digest()
    expected = b"\x00\x01" + b"\xff" * (256 - len(digest_info) - 3) + b"\x00" + digest_info
    if decoded != expected:
        fail("signature-invalid")
    manifest = parse_json(payload, 32768, True)
    exact(manifest, ("schema", "product", "channel", "version", "sequence", "releaseTag", "files"))
    if (type(manifest["schema"]) is not int or manifest["schema"] != 1 or
            manifest["product"] != "SolarSystemLink" or manifest["channel"] != "stable"):
        fail("manifest-schema-or-product")
    version(manifest["version"])
    positive(manifest["sequence"], 999999999999999999)
    if manifest["releaseTag"] != "ssl-v" + manifest["version"]:
        fail("manifest-release-tag")
    entries = manifest["files"]
    if not isinstance(entries, list) or len(entries) != len(FILES):
        fail("manifest-file-count")
    total = 0
    for name, entry in zip(FILES, entries):
        exact(entry, ("name", "length", "sha256"))
        if entry["name"] != name:
            fail("manifest-file-whitelist-or-order")
        total += positive(entry["length"], MAX_FILE)
        digest(entry["sha256"])
    if total > MAX_TOTAL:
        fail("manifest-total-size")
    return manifest


def read_local(path, maximum):
    """One regular, single-link checkout file; no symlink or follow-on reopen."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 1 <= before.st_size <= maximum:
                fail("local-file-type-links-or-size")
            data = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
            if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or len(data) != before.st_size):
                fail("local-file-changed")
            return data
    except OSError:
        fail("local-file-open")


def load_bundle(repository_root):
    """Fixed request path, derived archive path; never extract archive members."""
    update_root = repository_root / "updates" / "ssl"
    for directory in (repository_root, repository_root / "updates", update_root, update_root / "bundles"):
        try:
            if directory.is_symlink() or not directory.is_dir():
                fail("checkout-directory-type")
        except OSError:
            fail("checkout-directory-open")
    request = parse_json(read_local(update_root / "publish-request.json", 4096), 4096, True)
    exact(request, ("schema", "version", "sequence", "archiveBytes", "archiveSha256",
                    "envelopeSha256", "expectedStableEnvelopeSha256"))
    if type(request["schema"]) is not int or request["schema"] != 1:
        fail("request-schema")
    version(request["version"])
    positive(request["sequence"], 999999999999999999)
    archive_size = positive(request["archiveBytes"], MAX_ARCHIVE)
    digest(request["archiveSha256"])
    digest(request["envelopeSha256"])
    if request["expectedStableEnvelopeSha256"] != "":
        digest(request["expectedStableEnvelopeSha256"])
    archive_name = request["version"] + "-" + request["sequence"] + ".tar.xz"
    archive = read_local(update_root / "bundles" / archive_name, MAX_ARCHIVE)
    if len(archive) != archive_size or sha(archive) != request["archiveSha256"]:
        fail("archive-pin")
    try:
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 * 1024 * 1024)
        uncompressed = decoder.decompress(archive, max_length=MAX_TAR + 1)
        if not decoder.eof or decoder.unused_data or len(uncompressed) > MAX_TAR:
            fail("archive-compression-capacity-or-trailing-data")
    except lzma.LZMAError:
        fail("archive-compression")
    members = {}
    tar_cursor = 0
    allowed = set(FILES) | {ENVELOPE_NAME, "publisher-public.der"}
    try:
        with tarfile.open(fileobj=io.BytesIO(uncompressed), mode="r:") as tar:
            for member in tar:
                if (len(members) >= 8 or member.name not in allowed or member.name in members or
                        member.offset != tar_cursor or member.offset_data != tar_cursor + 512 or
                        member.type != tarfile.REGTYPE or member.linkname or member.pax_headers or
                        member.sparse is not None or not 1 <= member.size <=
                        (MAX_ENVELOPE if member.name == ENVELOPE_NAME else MAX_FILE)):
                    fail("archive-member-type-name-or-size")
                stream = tar.extractfile(member)
                if stream is None:
                    fail("archive-member-read")
                with stream:
                    value = stream.read(member.size + 1)
                if len(value) != member.size:
                    fail("archive-member-truncated")
                members[member.name] = value
                tar_cursor = member.offset_data + ((member.size + 511) // 512) * 512
    except (tarfile.TarError, OSError, EOFError):
        fail("archive-tar")
    if (len(uncompressed) < tar_cursor + 1024 or len(uncompressed) % 512 != 0 or
            any(uncompressed[tar_cursor:])):
        fail("archive-hidden-or-trailing-members")
    if set(members) not in (set(FILES) | {ENVELOPE_NAME}, allowed):
        fail("archive-inventory")
    if "publisher-public.der" in members and members["publisher-public.der"] != PUBLIC_DER:
        fail("archive-public-key-pin")
    envelope = members[ENVELOPE_NAME]
    if sha(envelope) != request["envelopeSha256"]:
        fail("envelope-request-pin")
    manifest = verify_envelope(envelope)
    if manifest["version"] != request["version"] or manifest["sequence"] != request["sequence"]:
        fail("request-manifest-version-or-sequence")
    for entry in manifest["files"]:
        value = members[entry["name"]]
        if len(value) != int(entry["length"]) or sha(value) != entry["sha256"]:
            fail("payload-length-or-sha256")
    return request, manifest, members


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self, token, receipt):
        self.token = token
        self.receipt = receipt
        self.opener = urllib.request.build_opener(NoRedirect())

    def event(self, operation, **fields):
        value = dict(operation=operation, **fields)
        self.receipt["events"].append(value)
        # Preserve each known boundary in ordinary job logs even if a later
        # runner/job termination prevents the final aggregate receipt.
        print(json.dumps({"sslPublisherEvent": value}, ensure_ascii=True, separators=(",", ":")), flush=True)

    def fetch(self, url, limit, method="GET", body=None, authenticated=False,
              content_type=None, binary=False, public_redirect=False):
        """Token only on fixed API/uploads origins; never forward it on redirect."""
        for hop in range(6):
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme != "https" or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.fragment:
                fail("network-origin")
            if authenticated:
                if hop or parsed.netloc not in ("api.github.com", "uploads.github.com"):
                    fail("token-origin")
            elif parsed.hostname not in (("github.com", "release-assets.githubusercontent.com") if public_redirect else
                                           ("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com")):
                fail("public-origin")
            headers = {"User-Agent": "Solar-System-Link-release-publisher-v1",
                       "Accept": "application/octet-stream" if binary else "application/vnd.github+json"}
            if authenticated:
                headers.update({"Authorization": "Bearer " + self.token,
                                "X-GitHub-Api-Version": API_VERSION})
            if content_type:
                headers["Content-Type"] = content_type
            request = urllib.request.Request(url, data=body, headers=headers, method=method)
            started = time.monotonic()
            try:
                with self.opener.open(request, timeout=30) as response:
                    chunks = []
                    count = 0
                    while True:
                        if time.monotonic() - started > 60:
                            fail("network-read-deadline")
                        chunk = response.read(min(65536, limit - count + 1))
                        if not chunk:
                            break
                        count += len(chunk)
                        if count > limit:
                            fail("network-response-size")
                        chunks.append(chunk)
                    return b"".join(chunks)
            except urllib.error.HTTPError as error:
                status = error.code
                location = error.headers.get("Location")
                error.close()
                if method == "GET" and (public_redirect or binary) and status in (301, 302, 303, 307, 308) and location:
                    if hop == 5:
                        fail("network-redirect-limit")
                    url = urllib.parse.urljoin(url, location)
                    authenticated = False
                    continue
                fail("github-http-" + str(status))
            except (OSError, urllib.error.URLError, TimeoutError):
                fail("network-result-unknown")
        fail("network-redirect-limit")

    def api(self, path, method="GET", value=None):
        if path != "/repos/" + REPOSITORY and not path.startswith("/repos/" + REPOSITORY + "/"):
            fail("api-repository")
        raw = None if value is None else canonical(value)
        data = self.fetch(API + path, MAX_JSON, method, raw, True,
                          "application/json" if raw is not None else None)
        return parse_json(data, MAX_JSON)

    def release(self, release_id):
        value = self.api("/repos/" + REPOSITORY + "/releases/" + str(release_id))
        return self.validate_release(value)

    def validate_release(self, value):
        if (not isinstance(value, dict) or type(value.get("id")) is not int or value["id"] < 1 or
                type(value.get("draft")) is not bool or type(value.get("immutable")) is not bool or
                value.get("prerelease") is not False):
            fail("release-metadata-unknown")
        if value["immutable"]:
            fail("release-immutable-stop")
        return value

    def find_releases(self, tags):
        found = {}
        for page in range(1, 21):
            values = self.api("/repos/" + REPOSITORY + "/releases?per_page=100&page=" + str(page))
            if not isinstance(values, list) or len(values) > 100:
                fail("release-list-shape")
            for value in values:
                if isinstance(value, dict) and value.get("tag_name") in tags:
                    value = self.validate_release(value)
                    if value["tag_name"] in found:
                        fail("release-tag-duplicate")
                    found[value["tag_name"]] = value
            if len(values) < 100:
                return found
        fail("release-list-capacity")

    def assets(self, release):
        result = {}
        for page in range(1, MAX_ASSETS // 100 + 1):
            values = self.api("/repos/" + REPOSITORY + "/releases/" + str(release["id"]) +
                              "/assets?per_page=100&page=" + str(page))
            if not isinstance(values, list) or len(values) > 100:
                fail("asset-list-shape")
            for value in values:
                if (not isinstance(value, dict) or type(value.get("id")) is not int or value["id"] < 1 or
                        not isinstance(value.get("name"), str) or value["name"] in result or
                        type(value.get("size")) is not int or value["size"] < 1 or value.get("state") != "uploaded"):
                    fail("asset-metadata-unknown")
                result[value["name"]] = value
            if len(values) < 100:
                return result
        fail("asset-list-capacity")

    def asset_bytes(self, asset, limit):
        data = self.fetch(API + "/repos/" + REPOSITORY + "/releases/assets/" + str(asset["id"]),
                          limit, authenticated=True, binary=True)
        if len(data) != asset["size"]:
            fail("asset-metadata-length-mismatch")
        return data

    def asset_matches(self, asset, expected):
        if asset["size"] != len(expected) or self.asset_bytes(asset, len(expected)) != expected:
            fail("existing-asset-bytes-conflict")

    def public_check(self, tag, name, expected):
        url = PUBLIC + urllib.parse.quote(tag, safe="") + "/" + urllib.parse.quote(name, safe="")
        data = self.fetch(url, len(expected), binary=True, public_redirect=True)
        if data != expected:
            fail("public-get-bytes-mismatch")
        self.event("public-get-verified", url=url, bytes=len(data), sha256=sha(data))

    def create_draft(self, tag, commit):
        self.event("draft-create-submitted", tag=tag, commit=commit)
        value = self.api("/repos/" + REPOSITORY + "/releases", "POST",
                         {"tag_name": tag, "target_commitish": commit, "name": tag,
                          "body": version_body(tag), "draft": True, "prerelease": False,
                          "make_latest": "false"})
        release = self.validate_release(value)
        if release["tag_name"] != tag or release["draft"] is not True:
            fail("created-release-shape")
        self.event("draft-created", tag=tag, releaseId=release["id"])
        return release

    def publish_draft(self, release):
        current = self.release(release["id"])
        if current.get("tag_name") != release["tag_name"]:
            fail("release-tag-changed")
        if current["draft"]:
            if current.get("body") != version_body(current["tag_name"]):
                fail("draft-not-owned-by-publisher")
            self.event("release-publish-submitted", tag=current["tag_name"], releaseId=current["id"])
            result = self.api("/repos/" + REPOSITORY + "/releases/" + str(current["id"]),
                              "PATCH", {"draft": False, "make_latest": "false"})
            # If repository immutability became enabled, this can publish an
            # immutable release. Never disable it, retry around it, or pretend
            # no external change happened. The receipt records the boundary.
            self.event("release-publish-returned", tag=current["tag_name"],
                       releaseId=current["id"], immutable=result.get("immutable") if isinstance(result, dict) else None)
            current = self.validate_release(result)
        return current

    def ensure_asset(self, release, name, data):
        current = self.release(release["id"])
        if current.get("tag_name") != release["tag_name"]:
            fail("release-tag-changed")
        assets = self.assets(current)
        if name in assets:
            self.asset_matches(assets[name], data)
            self.event("asset-already-matches", name=name, assetId=assets[name]["id"], sha256=sha(data))
            return assets[name]
        if current.get("body") != version_body(current["tag_name"]):
            fail("draft-not-owned-by-publisher")
        url = UPLOADS + "/repos/" + REPOSITORY + "/releases/" + str(current["id"]) + "/assets?name=" + urllib.parse.quote(name, safe="")
        self.event("asset-upload-submitted", name=name, releaseId=current["id"], bytes=len(data), sha256=sha(data))
        result = parse_json(self.fetch(url, MAX_JSON, "POST", data, True, "application/octet-stream"), MAX_JSON)
        self.event("asset-upload-returned", name=name, releaseId=current["id"])
        after = self.assets(current).get(name)
        if not isinstance(result, dict) or after is None or result.get("id") != after["id"]:
            fail("uploaded-asset-identity-unknown")
        self.asset_matches(after, data)
        return after

    def rename(self, release, asset, before_name, after_name, expected):
        current = self.release(release["id"])
        if current.get("tag_name") != STABLE_TAG or current["draft"] or current.get("body") != RELEASE_BODY:
            fail("stable-release-state")
        assets = self.assets(current)
        before = assets.get(before_name)
        if before is None or before["id"] != asset["id"] or after_name in assets:
            fail("rename-precondition-conflict")
        self.asset_matches(before, expected)
        self.event("asset-rename-submitted", assetId=before["id"], before=before_name, after=after_name, sha256=sha(expected))
        result = self.api("/repos/" + REPOSITORY + "/releases/assets/" + str(before["id"]),
                          "PATCH", {"name": after_name})
        self.event("asset-rename-returned", assetId=before["id"], before=before_name, after=after_name)
        after_assets = self.assets(current)
        after = after_assets.get(after_name)
        if (not isinstance(result, dict) or result.get("id") != before["id"] or
                after is None or after["id"] != before["id"] or before_name in after_assets):
            fail("rename-result-unknown")
        self.asset_matches(after, expected)
        return after


def pending_name(manifest, envelope):
    return "ssl-update-pending-v" + manifest["version"] + "-s" + manifest["sequence"] + "-" + sha(envelope) + ".json"


def archived_name(manifest, envelope):
    return "ssl-update-archive-v" + manifest["version"] + "-s" + manifest["sequence"] + "-" + sha(envelope) + ".json"


def require_advance(new, old):
    if version(new["version"]) <= version(old["version"]) or int(new["sequence"]) <= int(old["sequence"]):
        fail("stable-version-and-sequence-must-advance")


def stable_preflight(github, stable, request, manifest, envelope):
    """Return exact old fixed/archive bytes, or None for first seed/new match."""
    expected_old = request["expectedStableEnvelopeSha256"]
    if stable is None:
        if expected_old:
            fail("expected-stable-release-missing")
        return None, None
    assets = github.assets(stable)
    fixed = assets.get(ENVELOPE_NAME)
    if fixed is not None:
        data = github.asset_bytes(fixed, MAX_ENVELOPE)
        old = verify_envelope(data)
        if data == envelope:
            return None, fixed
        if sha(data) != expected_old:
            fail("stable-old-request-pin")
        require_advance(manifest, old)
        if archived_name(old, data) in assets:
            fail("stable-old-archive-name-conflict")
        return (old, data, fixed, ENVELOPE_NAME), None
    if expected_old:
        # Resume only the exact request-bound old archive left by rotation.
        candidates = []
        for name, asset in assets.items():
            if name.startswith("ssl-update-archive-"):
                data = github.asset_bytes(asset, MAX_ENVELOPE)
                if sha(data) == expected_old:
                    old = verify_envelope(data)
                    if name != archived_name(old, data):
                        fail("old-archive-name-binding")
                    candidates.append((old, data, asset, name))
        if len(candidates) != 1 or pending_name(manifest, envelope) not in assets:
            fail("rotation-resume-state-unknown")
        require_advance(manifest, candidates[0][0])
        return candidates[0], None
    if any(name.startswith("ssl-update-archive-") for name in assets):
        fail("seed-with-existing-history")
    if any(name.startswith("ssl-update-pending-") and name != pending_name(manifest, envelope) for name in assets):
        fail("seed-with-other-pending-envelope")
    if not stable["draft"] and stable.get("body") != RELEASE_BODY:
        fail("empty-stable-release-not-owned")
    return None, None


def restore_old_if_safe(github, stable, old):
    if old is None:
        return
    manifest, data, asset, _ = old
    archive = archived_name(manifest, data)
    try:
        current = github.release(stable["id"])
        assets = github.assets(current)
        fixed = assets.get(ENVELOPE_NAME)
        if fixed is not None:
            github.event("restore-skipped-fixed-present", assetId=fixed["id"])
            return
        retained = assets.get(archive)
        if retained is None or retained["id"] != asset["id"]:
            github.event("restore-skipped-old-identity-unknown")
            return
        github.asset_matches(retained, data)
        github.rename(current, retained, archive, ENVELOPE_NAME, data)
        github.public_check(STABLE_TAG, ENVELOPE_NAME, data)
        github.event("old-feed-restored", assetId=retained["id"], sha256=sha(data))
    except PublishError as error:
        github.event("restore-not-confirmed", code=str(error))


def publish(github, request, manifest, members, commit):
    repository = github.api("/repos/" + REPOSITORY)
    if (not isinstance(repository, dict) or repository.get("full_name") != REPOSITORY or
            repository.get("private") is not False or repository.get("default_branch") != "main"):
        fail("fixed-public-repository-required")
    envelope = members[ENVELOPE_NAME]
    tag = manifest["releaseTag"]
    releases = github.find_releases({tag, STABLE_TAG})
    stable = releases.get(STABLE_TAG)
    old, already = stable_preflight(github, stable, request, manifest, envelope)
    release = releases.get(tag)
    if release is None:
        release = github.create_draft(tag, commit)
    elif release.get("body") != version_body(tag):
        fail("version-release-not-owned")
    if set(github.assets(release)) - set(FILES):
        fail("version-release-unexpected-assets")
    for name in FILES:
        github.ensure_asset(release, name, members[name])
    release = github.publish_draft(release)
    if set(github.assets(release)) != set(FILES):
        fail("version-release-inventory")
    for name in FILES:
        github.public_check(tag, name, members[name])
    github.event("version-six-complete", tag=tag, releaseId=release["id"])
    if already is not None:
        github.public_check(STABLE_TAG, ENVELOPE_NAME, envelope)
        github.event("stable-already-matches", assetId=already["id"], sha256=sha(envelope))
        return
    if stable is None:
        stable = github.create_draft(STABLE_TAG, commit)
    candidate_name = pending_name(manifest, envelope)
    pending = github.ensure_asset(stable, candidate_name, envelope)
    stable = github.publish_draft(stable)
    github.public_check(STABLE_TAG, candidate_name, envelope)
    # Re-read the exact fixed/archive state after the possibly slow six-file
    # publication. This detects an independently advanced feed before rename.
    old_now, already_now = stable_preflight(github, stable, request, manifest, envelope)
    if already_now is not None:
        github.public_check(STABLE_TAG, ENVELOPE_NAME, envelope)
        github.event("stable-concurrently-already-matches", assetId=already_now["id"])
        return
    old = old_now
    try:
        if old is not None and old[3] == ENVELOPE_NAME:
            github.rename(stable, old[2], ENVELOPE_NAME, archived_name(old[0], old[1]), old[1])
        github.rename(stable, pending, candidate_name, ENVELOPE_NAME, envelope)
        github.public_check(STABLE_TAG, ENVELOPE_NAME, envelope)
        github.event("stable-feed-verified", assetId=pending["id"], sha256=sha(envelope),
                     possibleTemporary404=True)
    except PublishError:
        # A mutation can have succeeded despite a lost response. Do not call it
        # success, delete any asset, overwrite an unknown fixed name, or retry
        # publication. Restore only the same previously pinned old ID/bytes.
        restore_old_if_safe(github, stable, old)
        raise


def emit_receipt(receipt):
    output = json.dumps(receipt, ensure_ascii=True, separators=(",", ":"))
    print(output, flush=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        # Runner-owned summary file, never an uploaded artifact/cache.
        try:
            with open(summary, "a", encoding="utf-8") as stream:
                stream.write("SSL release publication receipt\n\n```json\n" + output + "\n```\n")
        except OSError:
            print("SSL receipt summary write failed; stdout receipt retained.", file=sys.stderr)


def main():
    receipt = {"schema": 1, "repository": REPOSITORY, "status": "not-started",
               "events": [], "remoteControlAcceptance": "not-established",
               "paidServicesInvoked": False}
    try:
        if (os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_EVENT_NAME") not in ("push", "workflow_dispatch") or
                os.environ.get("GITHUB_REPOSITORY") != REPOSITORY or os.environ.get("GITHUB_REF") != "refs/heads/main"):
            fail("fixed-workflow-context-required")
        commit = os.environ.get("GITHUB_SHA", "")
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            fail("workflow-commit-format")
        token = os.environ.get("GITHUB_TOKEN", "")
        if not token or any(character.isspace() for character in token):
            fail("ephemeral-workflow-token-required")
        # The installed location is fixed; no command-line source/path/root.
        script = Path(__file__).resolve(strict=True)
        root = script.parents[1]
        workspace = Path(os.environ.get("GITHUB_WORKSPACE", "")).resolve(strict=True)
        if root != workspace or script != root / "tools" / "ssl_release_publisher.py":
            fail("fixed-checkout-layout")
        request, manifest, members = load_bundle(root)
        receipt.update({"commit": commit, "version": manifest["version"], "sequence": manifest["sequence"],
                        "archiveSha256": request["archiveSha256"], "envelopeSha256": request["envelopeSha256"],
                        "expectedStableEnvelopeSha256": request["expectedStableEnvelopeSha256"],
                        "signature": "verified-public-70a", "status": "verified-local-bundle"})
        publish(GitHub(token, receipt), request, manifest, members, commit)
        receipt["status"] = "public-get-verified"
        emit_receipt(receipt)
        return 0
    except PublishError as error:
        receipt["status"] = "failed-or-external-state-unknown"
        receipt["code"] = str(error)
    except Exception as error:
        # Do not print exception text/tracebacks: HTTP diagnostics can contain
        # signed redirect query strings. Unknown results require review.
        receipt["status"] = "failed-or-external-state-unknown"
        receipt["code"] = "unexpected-" + type(error).__name__
    emit_receipt(receipt)
    return 1


if __name__ == "__main__":
    sys.exit(main())

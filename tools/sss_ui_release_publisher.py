#!/usr/bin/env python3
"""Fixed signed SSS UI assets only; no install, signing, execution or grant.
Stable rotation retains pinned pending/archive bytes, with a possible short404.
"""
import hashlib
import io
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
import zipfile
import sss_ui_catalog as codec

REPOSITORY = "sasta02001-hash/solar-system-link"
API = "https://api.github.com"
UPLOADS = "https://uploads.github.com"
PUBLIC = "https://github.com/" + REPOSITORY + "/releases/download/"
API_VERSION = "2022-11-28"
VERSION = "0.4.6.0"
VERSION_TAG = "sss-ui-v" + VERSION
STABLE_TAG = "sss-ui-stable"
ENVELOPE_NAME = "sss-ui-update-v1.json"
PACKAGE_NAME = "SSS-" + VERSION + "-UI-x64.zip"
INITIAL_NAME = "SSS-0.4.6.0-Background-Initial-Setup.zip"
INITIAL_BYTES = 850627
INITIAL_SHA256 = "248bb18c9b37f7bdc46fde729a345aa2b62b499f9c5b11990c3dea9fc347f05f"
INITIAL_FILES = {
    "SSS.UiInitialSetup.exe": (66048,"4b70e0840710aa51df3fba397c1a463e843b60dbe760f000140e8ce26d0a1ef3"),
    "SSS.UiInitialSetup.exe.config": (138,"008d5c22af1b051c44f2fca2c8f0897cd5763ba687a55372cb480d2d7bc72337"),
    "Install-SSS-Background.vbs": (306,"d1a614d9926ee6ddb86ede0ec575010fec93d70dd3399bee426a957aada86963"),
    "initial-input/SSS.UiUpdateCoordinator.exe": (132608,"075a0bc57bc81eb56b9a9251ad76bee8c7164eb73b3d4f0c7366d315091dfe69"),
    "initial-input/SSS.UiUpdateCoordinator.exe.config": (138,"008d5c22af1b051c44f2fca2c8f0897cd5763ba687a55372cb480d2d7bc72337"),
    "initial-input/sss-ui-update-v1.json": (2921,"ff58613e4b1dbd1aa1b181cbf340646506fb1d239d75bc54e264f09f6a440f01"),
    "initial-input/SSS-0.4.6.0-UI-x64.zip": (760763,"9e4879305f790bdbeb67deb29319146550a95983f0e4b22df566d618b8afa2aa"),
}
MAX_FILE = 16777216
MAX_ENVELOPE = 8192
MAX_JSON = 1048576
MAX_ASSETS = 200
RELEASE_BODY = ("SSS-UI-PUBLISHER-V1: signed current-user UI assets only.\n\n"
                "SSS 0.4.6.0 CurrentUser UI 更新通道；不是 NativeReady/C1 或操作授權。"
                "Windows7 POS、無人值守與持續鍵鼠操作仍待實機驗收，非100分交付。\n\n"
                "既有0.4.5須先正常選一次『結束SSS』，再由新背景更新流程接續；不強殺舊程序。"
                "新Run登入啟動登錄已讀回，但下次真登入自啟尚未測試；不是Native全功能驗收。")

class PublishError(Exception):
    pass

def fail(code):
    raise PublishError(code)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def canonical(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")

def parse_json(data, limit):
    if type(data) is not bytes or not 1 <= len(data) <= limit:
        fail("json-size")
    try:
        return codec.decode(data)
    except (ValueError, UnicodeError, RecursionError):
        fail("json-format")

def exact(value, names):
    if type(value) is not dict or set(value) != set(names):
        fail("unexpected-fields")

def verify_envelope(data, current=True):
    try:
        return codec.verify_catalog(data, require_current=current)
    except (ValueError, UnicodeError, RecursionError, TypeError, OverflowError):
        fail("signed-catalog-invalid")

def read_local(path, maximum):
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

def verify_zip(data, catalog):
    if type(data) is not bytes or len(data) != catalog["packageBytes"] or sha(data) != catalog["packageSha256"]:
        fail("zip-package-binding")
    rows = {row["path"]: row for row in catalog["files"]}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) != 11 or {entry.filename for entry in entries} != set(rows):
                fail("zip-exact-eleven-files")
            seen, total = set(), 0
            for entry in entries:
                mode = entry.external_attr >> 16
                if (entry.filename in seen or entry.orig_filename != entry.filename or entry.is_dir() or
                        entry.flag_bits & 1 or entry.external_attr & 16 or
                        stat.S_IFMT(mode) not in (0, stat.S_IFREG) or
                        entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                    fail("zip-file-type-or-duplicate")
                seen.add(entry.filename)
                row = rows[entry.filename]
                if entry.file_size != row["bytes"] or not 1 <= entry.file_size <= 8388608:
                    fail("zip-member-size")
                total += entry.file_size
                if total > MAX_FILE:
                    fail("zip-total-size")
                with archive.open(entry) as member:
                    raw = member.read(row["bytes"] + 1)
                if len(raw) != row["bytes"] or sha(raw) != row["sha256"]:
                    fail("zip-member-hash")
    except (zipfile.BadZipFile, RuntimeError, OSError, ValueError, NotImplementedError):
        fail("zip-invalid")

def verify_initial(data):
    if type(data) is not bytes or len(data) != INITIAL_BYTES or sha(data) != INITIAL_SHA256:
        fail("initial-approved-package-binding")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries=archive.infolist()
            if len(entries)!=7 or {entry.filename for entry in entries}!=set(INITIAL_FILES):
                fail("initial-exact-seven-files")
            seen=set();total=0
            for entry in entries:
                size,digest=INITIAL_FILES[entry.filename]
                if (entry.filename in seen or entry.orig_filename!=entry.filename or entry.is_dir() or entry.flag_bits&1 or entry.external_attr&16 or
                        stat.S_IFMT(entry.external_attr>>16) not in (0,stat.S_IFREG) or entry.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED) or entry.file_size!=size):
                    fail("initial-member-type-or-size")
                seen.add(entry.filename);total+=size
                if total>MAX_FILE:fail("initial-total-size")
                with archive.open(entry) as stream:raw=stream.read(size+1)
                if len(raw)!=size or sha(raw)!=digest:fail("initial-member-hash")
    except (zipfile.BadZipFile,RuntimeError,OSError,ValueError,NotImplementedError):
        fail("initial-zip-invalid")

def validate_inputs(request_raw, package, envelope, initial):
    request = parse_json(request_raw, 4096)
    exact(request, ("schema", "version", "sequence", "packageBytes", "packageSha256", "envelopeSha256", "initialSetupBytes", "initialSetupSha256", "expectedStableEnvelopeSha256"))
    if (type(request["schema"]) is not int or request["schema"] != 1 or request["version"] != VERSION or
            type(request["sequence"]) is not int or not 1 <= request["sequence"] <= 2**63 - 1 or
            type(request["packageBytes"]) is not int or not 1 <= request["packageBytes"] <= MAX_FILE):
        fail("request-purpose")
    for field in ("packageSha256", "envelopeSha256"):
        if type(request[field]) is not str or not re.fullmatch(r"[0-9a-f]{64}", request[field]):
            fail("request-digest")
    old = request["expectedStableEnvelopeSha256"]
    if type(old) is not str or old and not re.fullmatch(r"[0-9a-f]{64}", old):
        fail("request-old-pin")
    catalog = verify_envelope(envelope)
    if (catalog["version"] != VERSION or catalog["sequence"] != request["sequence"] or
            len(envelope) > MAX_ENVELOPE or sha(envelope) != request["envelopeSha256"] or
            catalog["packageBytes"] != request["packageBytes"] or catalog["packageSha256"] != request["packageSha256"]):
        fail("request-catalog-binding")
    verify_zip(package, catalog)
    if type(request["initialSetupBytes"]) is not int or request["initialSetupBytes"]!=INITIAL_BYTES or request["initialSetupSha256"]!=INITIAL_SHA256:
        fail("initial-request-pin")
    verify_initial(initial)
    return request, catalog, {PACKAGE_NAME: package, ENVELOPE_NAME: envelope, INITIAL_NAME:initial}

def load_bundle(root):
    folder = root / "updates" / "sss-ui"
    for directory in (root, root / "updates", folder, folder / "payload"):
        if directory.is_symlink() or not directory.is_dir():
            fail("checkout-directory-type")
    return validate_inputs(read_local(folder / "publish-request.json", 4096),
                           read_local(folder / "payload" / PACKAGE_NAME, MAX_FILE),
                           read_local(folder / "payload" / ENVELOPE_NAME, MAX_ENVELOPE),
                           read_local(folder / "payload" / INITIAL_NAME, MAX_FILE))

# The following delivery transport is derived from the reviewed SSL publisher.

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self, token, receipt):
        if not token or any(c.isspace() for c in token):
            fail("ephemeral-workflow-token-required")
        self.token = token
        self.receipt = receipt
        self.deadline = time.monotonic() + 480
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def event(self, operation, **fields):
        value = dict(operation=operation, **fields)
        self.receipt["events"].append(value)
        # Preserve each known boundary in ordinary job logs even if a later
        # runner/job termination prevents the final aggregate receipt.
        print(json.dumps({"sssUiPublisherEvent": value}, ensure_ascii=True, separators=(",", ":")), flush=True)

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
            elif parsed.hostname not in ("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"):
                fail("public-origin")
            headers = {"User-Agent": "SSS-CurrentUser-UI-release-publisher-v1",
                       "Accept": "application/octet-stream" if binary else "application/vnd.github+json"}
            if authenticated:
                headers.update({"Authorization": "Bearer " + self.token,
                                "X-GitHub-Api-Version": API_VERSION})
            if content_type:
                headers["Content-Type"] = content_type
            request = urllib.request.Request(url, data=body, headers=headers, method=method)
            started = time.monotonic()
            if started >= self.deadline:
                fail("network-total-deadline")
            try:
                with self.opener.open(request, timeout=min(30, self.deadline-started)) as response:
                    chunks = []
                    count = 0
                    while True:
                        if time.monotonic() - started > 60 or time.monotonic() >= self.deadline:
                            fail("network-read-deadline")
                        chunk = response.read(min(65536, limit - count + 1))
                        if time.monotonic() >= self.deadline:
                            fail("network-total-deadline")
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
        suffix = path[len("/repos/"+REPOSITORY):]
        get_route = suffix == "" or suffix in ("/releases/tags/"+VERSION_TAG,"/releases/tags/"+STABLE_TAG) or re.fullmatch(r"/releases/[1-9][0-9]*(/assets\?per_page=100&page=[1-9][0-9]*)?",suffix)
        create = (method == "POST" and suffix == "/releases" and type(value) is dict and
                  set(value) == {"tag_name","target_commitish","name","body","draft","prerelease","make_latest"} and
                  value["tag_name"] in (VERSION_TAG,STABLE_TAG) and value["name"] == value["tag_name"] and
                  re.fullmatch(r"[0-9a-f]{40}",value["target_commitish"]) and value["body"] == RELEASE_BODY and
                  value["draft"] is True and value["prerelease"] is False and value["make_latest"] == "false")
        publish = method == "PATCH" and re.fullmatch(r"/releases/[1-9][0-9]*",suffix) and value == {"draft":False,"make_latest":"false"}
        rename = method == "PATCH" and re.fullmatch(r"/releases/assets/[1-9][0-9]*",suffix) and type(value) is dict and set(value) == {"name"} and allowed_feed_name(value["name"])
        if not ((method == "GET" and get_route and value is None) or create or publish or rename):
            fail("api-method-or-purpose")
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
                value.get("prerelease") is not False or value.get("tag_name") not in (VERSION_TAG,STABLE_TAG) or
                value.get("name") != value["tag_name"] or value.get("body") != RELEASE_BODY):
            fail("release-metadata-unknown")
        if value["immutable"] and value["tag_name"] == STABLE_TAG:
            fail("release-immutable-stop")
        return value

    def find_releases(self, tags):
        found = {}
        if set(tags) != {VERSION_TAG,STABLE_TAG}:
            fail("fixed-tags-required")
        for tag in (VERSION_TAG,STABLE_TAG):
            try:
                value=self.validate_release(self.api("/repos/"+REPOSITORY+"/releases/tags/"+tag))
                if value["tag_name"] != tag:
                    fail("release-tag-changed")
                found[tag]=value
            except PublishError as error:
                if str(error) != "github-http-404":
                    raise
        return found

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
                          "body": RELEASE_BODY, "draft": True, "prerelease": False,
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
            if current["immutable"]:
                fail("immutable-draft-refused")
            if current.get("body") != RELEASE_BODY:
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
        if ((current["tag_name"] == VERSION_TAG and name not in (PACKAGE_NAME,INITIAL_NAME)) or
                (current["tag_name"] == STABLE_TAG and not allowed_feed_name(name)) or
                type(data) is not bytes or not 1 <= len(data) <= (MAX_FILE if name in (PACKAGE_NAME,INITIAL_NAME) else MAX_ENVELOPE)):
            fail("upload-name-or-size")
        assets = self.assets(current)
        if name in assets:
            self.asset_matches(assets[name], data)
            self.event("asset-already-matches", name=name, assetId=assets[name]["id"], sha256=sha(data))
            return assets[name]
        if current.get("body") != RELEASE_BODY:
            fail("draft-not-owned-by-publisher")
        if current["immutable"] or current["tag_name"] == VERSION_TAG and not current["draft"]:
            fail("immutable-version-or-published-missing-asset")
        url = UPLOADS + "/repos/" + REPOSITORY + "/releases/" + str(current["id"]) + "/assets?name=" + urllib.parse.quote(name, safe="")
        self.event("asset-upload-submitted", name=name, releaseId=current["id"], bytes=len(data), sha256=sha(data))
        result = parse_json(self.fetch(url, MAX_JSON, "POST", data, True, "application/octet-stream"), MAX_JSON)
        self.event("asset-upload-returned", name=name, releaseId=current["id"])
        after = self.assets(current).get(name)
        if not isinstance(result, dict) or after is None or result.get("id") != after["id"]:
            fail("uploaded-asset-identity-unknown")
        self.asset_matches(after, data)
        return after

    def rename(self, release, asset, before_name, after_name, expected, admission_envelope=None):
        if not allowed_feed_name(before_name) or not allowed_feed_name(after_name):
            fail("rename-name-purpose")
        current = self.release(release["id"])
        if current.get("tag_name") != STABLE_TAG or current["draft"] or current.get("body") != RELEASE_BODY:
            fail("stable-release-state")
        assets = self.assets(current)
        before = assets.get(before_name)
        if before is None or before["id"] != asset["id"] or after_name in assets:
            fail("rename-precondition-conflict")
        self.asset_matches(before, expected)
        # All preceding identity/byte reads can take time.  The candidate must
        # still be current at the final local boundary before archive/promote.
        # Safe restoration passes no admission candidate and retains old bytes.
        if admission_envelope is not None:
            verify_envelope(admission_envelope)
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


def pending_name(catalog,envelope):
    return "sss-ui-update-pending-v"+catalog["version"]+"-s"+str(catalog["sequence"])+"-"+sha(envelope)+".json"

def archived_name(catalog,envelope):
    return "sss-ui-update-archive-v"+catalog["version"]+"-s"+str(catalog["sequence"])+"-"+sha(envelope)+".json"

def allowed_feed_name(name):
    return type(name) is str and (name == ENVELOPE_NAME or re.fullmatch(r"sss-ui-update-(pending|archive)-v(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){3}-s[1-9][0-9]*-[0-9a-f]{64}\.json",name) is not None)

def require_advance(new,old):
    old_version=tuple(map(int,old["version"].split(".")))
    new_version=tuple(map(int,new["version"].split(".")))
    if new_version < old_version or new["sequence"] <= old["sequence"]:
        fail("stable-rollback-or-no-advance")
    vector=lambda value: sorted((r["path"],r["bytes"],r["sha256"]) for r in value["files"])
    if new_version == old_version and (new["packageUrl"],new["packageBytes"],new["packageSha256"],vector(new)) != (old["packageUrl"],old["packageBytes"],old["packageSha256"],vector(old)):
        fail("same-version-bits-change")

def stable_preflight(github,stable,request,catalog,envelope):
    expected=request["expectedStableEnvelopeSha256"]
    if stable is None:
        if expected:
            fail("expected-stable-missing")
        return None,None
    assets=github.assets(stable)
    if any(not allowed_feed_name(name) for name in assets):
        fail("stable-unknown-asset")
    fixed=assets.get(ENVELOPE_NAME)
    if fixed is not None:
        raw=github.asset_bytes(fixed,MAX_ENVELOPE)
        old=verify_envelope(raw,current=False)
        if raw == envelope:
            return None,fixed
        if sha(raw) != expected:
            fail("stable-old-request-pin")
        require_advance(catalog,old)
        if archived_name(old,raw) in assets:
            fail("stable-archive-conflict")
        return (old,raw,fixed,ENVELOPE_NAME),None
    if expected:
        matches=[]
        for name,asset in assets.items():
            if name.startswith("sss-ui-update-archive-"):
                raw=github.asset_bytes(asset,MAX_ENVELOPE)
                if sha(raw) == expected:
                    old=verify_envelope(raw,current=False)
                    if name != archived_name(old,raw):
                        fail("old-archive-name-binding")
                    matches.append((old,raw,asset,name))
        if len(matches) != 1 or pending_name(catalog,envelope) not in assets:
            fail("rotation-resume-unknown")
        require_advance(catalog,matches[0][0])
        return matches[0],None
    if any(name.startswith("sss-ui-update-archive-") or name != pending_name(catalog,envelope) for name in assets):
        fail("seed-with-existing-history")
    return None,None

def restore_old_if_safe(github,stable,old):
    if old is None:
        return
    catalog,raw,asset,_=old
    try:
        current=github.release(stable["id"])
        assets=github.assets(current)
        if ENVELOPE_NAME in assets:
            github.event("restore-skipped-fixed-present")
            return
        retained=assets.get(archived_name(catalog,raw))
        if retained is None or retained["id"] != asset["id"]:
            github.event("restore-skipped-identity-unknown")
            return
        github.asset_matches(retained,raw)
        github.rename(current,retained,archived_name(catalog,raw),ENVELOPE_NAME,raw)
        github.public_check(STABLE_TAG,ENVELOPE_NAME,raw)
        github.event("old-feed-restored",sha256=sha(raw))
    except PublishError as error:
        github.event("restore-not-confirmed",code=str(error))

def publish(github,request,catalog,members,commit):
    if type(commit) is not str or re.fullmatch(r"[0-9a-f]{40}",commit) is None:
        fail("commit-format")
    if set(members) != {PACKAGE_NAME,ENVELOPE_NAME,INITIAL_NAME}:
        fail("fixed-three-payloads")
    # Revalidate signed bytes immediately before the first API call.
    request,actual,members=validate_inputs(canonical(request),members[PACKAGE_NAME],members[ENVELOPE_NAME],members[INITIAL_NAME])
    if actual != catalog:
        fail("catalog-object-not-verified-bytes")
    repo=github.api("/repos/"+REPOSITORY)
    if (type(repo) is not dict or repo.get("full_name") != REPOSITORY or repo.get("private") is not False or
            repo.get("default_branch") != "main" or repo.get("archived") is not False):
        fail("fixed-public-repository-required")
    envelope=members[ENVELOPE_NAME]
    releases=github.find_releases({VERSION_TAG,STABLE_TAG})
    stable=releases.get(STABLE_TAG)
    old,already=stable_preflight(github,stable,request,catalog,envelope)
    release=releases.get(VERSION_TAG)
    if release is None:
        release=github.create_draft(VERSION_TAG,commit)
    if set(github.assets(release))-{PACKAGE_NAME,INITIAL_NAME}:
        fail("version-unexpected-assets")
    github.ensure_asset(release,PACKAGE_NAME,members[PACKAGE_NAME])
    github.ensure_asset(release,INITIAL_NAME,members[INITIAL_NAME])
    release=github.publish_draft(release)
    if set(github.assets(release)) != {PACKAGE_NAME,INITIAL_NAME}:
        fail("version-inventory")
    github.public_check(VERSION_TAG,PACKAGE_NAME,members[PACKAGE_NAME])
    github.public_check(VERSION_TAG,INITIAL_NAME,members[INITIAL_NAME])
    if already is not None:
        github.public_check(STABLE_TAG,ENVELOPE_NAME,envelope)
        verify_envelope(envelope)
        return
    if stable is None:
        stable=github.create_draft(STABLE_TAG,commit)
    candidate=pending_name(catalog,envelope)
    pending=github.ensure_asset(stable,candidate,envelope)
    stable=github.publish_draft(stable)
    github.public_check(STABLE_TAG,candidate,envelope)
    verify_envelope(envelope)  # Never admit an expired candidate after a slow upload.
    old,already=stable_preflight(github,stable,request,catalog,envelope)
    if already is not None:
        github.public_check(STABLE_TAG,ENVELOPE_NAME,envelope)
        verify_envelope(envelope)
        return
    try:
        if old is not None and old[3] == ENVELOPE_NAME:
            verify_envelope(envelope)
            github.rename(stable,old[2],ENVELOPE_NAME,archived_name(old[0],old[1]),old[1],admission_envelope=envelope)
        verify_envelope(envelope)
        github.rename(stable,pending,candidate,ENVELOPE_NAME,envelope,admission_envelope=envelope)
        github.public_check(STABLE_TAG,ENVELOPE_NAME,envelope)
        verify_envelope(envelope)
        github.event("stable-feed-verified",sha256=sha(envelope),possibleTemporary404=True)
    except PublishError:
        restore_old_if_safe(github,stable,old)
        raise

def main():
    receipt={"schema":1,"repository":REPOSITORY,"tags":[VERSION_TAG,STABLE_TAG],"status":"not-started","events":[],"productExecuted":False,"nativeReady":False,"remoteInputGranted":False}
    try:
        if (len(sys.argv)!=1 or os.environ.get("GITHUB_ACTIONS")!="true" or os.environ.get("GITHUB_EVENT_NAME")!="push" or
                os.environ.get("GITHUB_REPOSITORY")!=REPOSITORY or os.environ.get("GITHUB_REF")!="refs/heads/main"):
            fail("fixed-public-main-push-required")
        root=Path(os.environ.get("GITHUB_WORKSPACE","")).resolve(strict=True)
        if Path(__file__).resolve(strict=True) != root/"tools"/"sss_ui_release_publisher.py":
            fail("fixed-checkout-layout")
        request,catalog,members=load_bundle(root)
        receipt.update({"version":catalog["version"],"sequence":catalog["sequence"],"envelopeSha256":sha(members[ENVELOPE_NAME]),"packageSha256":sha(members[PACKAGE_NAME])})
        publish(GitHub(os.environ.get("GITHUB_TOKEN",""),receipt),request,catalog,members,os.environ.get("GITHUB_SHA",""))
        verify_envelope(members[ENVELOPE_NAME])
        receipt["status"]="public-readback-verified"
    except PublishError as error:
        receipt.update({"status":"failed-or-external-state-unknown","code":str(error)})
    except Exception as error:
        receipt.update({"status":"failed-or-external-state-unknown","code":"unexpected-"+type(error).__name__})
    print(json.dumps(receipt,ensure_ascii=True,separators=(",",":")))
    return 0 if receipt["status"] == "public-readback-verified" else 1

if __name__ == "__main__":
    sys.exit(main())



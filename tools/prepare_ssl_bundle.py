#!/usr/bin/env python3
"""Local packager for an already signed bundle; never signs or publishes.

Operator-selected local input/output directories are packaging locations only.
The CI publisher has no path arguments and accepts only its fixed repo layout.
An existing destination is never overwritten. A failed partial output is kept.
"""

import argparse
import io
import json
import lzma
from pathlib import Path
import tarfile

import ssl_release_publisher as publisher


def prepare(source, output, expected_old):
    source = Path(source)
    if source.is_symlink():
        publisher.fail("packager-source-directory")
    source = source.resolve(strict=True)
    output = Path(output).resolve()
    if not source.is_dir() or source.is_symlink():
        publisher.fail("packager-source-directory")
    allowed = set(publisher.FILES) | {publisher.ENVELOPE_NAME}
    names = {path.name for path in source.iterdir()}
    if names not in (allowed, allowed | {"publisher-public.der"}):
        publisher.fail("packager-source-inventory")
    members = {}
    for name in publisher.FILES + (publisher.ENVELOPE_NAME,):
        members[name] = publisher.read_local(source / name,
                                            publisher.MAX_ENVELOPE if name == publisher.ENVELOPE_NAME else publisher.MAX_FILE)
    if "publisher-public.der" in names and publisher.read_local(source / "publisher-public.der", 270) != publisher.PUBLIC_DER:
        publisher.fail("packager-source-public-key")
    envelope = members[publisher.ENVELOPE_NAME]
    manifest = publisher.verify_envelope(envelope)
    for entry in manifest["files"]:
        value = members[entry["name"]]
        if len(value) != int(entry["length"]) or publisher.sha(value) != entry["sha256"]:
            publisher.fail("packager-payload-pin")
    if expected_old:
        publisher.digest(expected_old)
    members["publisher-public.der"] = publisher.PUBLIC_DER
    uncompressed = io.BytesIO()
    with tarfile.open(fileobj=uncompressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name in publisher.FILES + (publisher.ENVELOPE_NAME, "publisher-public.der"):
            item = tarfile.TarInfo(name)
            item.size = len(members[name])
            item.mode = 0o644
            item.uid = item.gid = item.mtime = 0
            item.uname = item.gname = ""
            item.type = tarfile.REGTYPE
            tar.addfile(item, io.BytesIO(members[name]))
    archive = lzma.compress(uncompressed.getvalue(), format=lzma.FORMAT_XZ,
                            check=lzma.CHECK_CRC64, preset=6)
    if not 1 <= len(archive) <= publisher.MAX_ARCHIVE:
        publisher.fail("packager-archive-size")
    request = {"schema": 1, "version": manifest["version"], "sequence": manifest["sequence"],
               "archiveBytes": str(len(archive)), "archiveSha256": publisher.sha(archive),
               "envelopeSha256": publisher.sha(envelope),
               "expectedStableEnvelopeSha256": expected_old}
    # A new staging root avoids accidentally replacing a prior reviewed input.
    output.mkdir(parents=True, exist_ok=False)
    bundles = output / "updates" / "ssl" / "bundles"
    bundles.mkdir(parents=True, exist_ok=False)
    archive_path = bundles / (manifest["version"] + "-" + manifest["sequence"] + ".tar.xz")
    with archive_path.open("xb") as stream:
        stream.write(archive)
    with (bundles.parent / "publish-request.json").open("xb") as stream:
        stream.write(publisher.canonical(request))
    # Re-read our own public data through the same bounded archive decoder.
    checked_request, checked_manifest, _ = publisher.load_bundle(output)
    if checked_request != request or checked_manifest != manifest:
        publisher.fail("packager-roundtrip")
    return {"schema": 1, "status": "local-public-data-packaged-only", "request": request,
            "output": str(output), "signedHere": False, "published": False,
            "remoteControlAcceptance": "not-established"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="Local directory containing exactly the already signed seven/eight files")
    parser.add_argument("--output", required=True, help="A new local staging directory; cannot already exist")
    parser.add_argument("--expected-stable-sha256", default="", help="Reviewed old envelope SHA256; empty only for initial feed seed")
    args = parser.parse_args()
    try:
        result = prepare(args.source, args.output, args.expected_stable_sha256)
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
        return 0
    except publisher.PublishError as error:
        print(json.dumps({"status": "packaging-failed", "code": str(error), "published": False}))
        return 1
    except Exception as error:
        print(json.dumps({"status": "packaging-failed", "code": type(error).__name__, "published": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

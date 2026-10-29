"""Three focused activation047 cases. No old19/7/14 or repair suite replay."""
import ast
import inspect
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import socket
import urllib.parse
import urllib.request
import zipfile
import sss_ui_release_publisher as p
def forbidden(*args,**kwargs):raise AssertionError("Real network forbidden")
socket.socket=forbidden
socket.create_connection=forbidden
urllib.request.urlopen=forbidden
urllib.request.OpenerDirector.open=forbidden
ROOT=Path(__file__).resolve().parent
STAGE=ROOT.parent if ROOT.name=="tools" else ROOT/"repository-staging"
DATA=STAGE/"updates/sss-ui/payload"
COMMIT="a"*40
def denied(action,code):
    try:action()
    except p.PublishError as error:assert str(error)==code,(str(error),code)
    else:raise AssertionError("Expected fail-closed result")
def funcs(tree):
    result={}
    for node in tree.body:
        if isinstance(node,ast.FunctionDef):result[node.name]=node
        elif isinstance(node,ast.ClassDef):
            for child in node.body:
                if isinstance(child,ast.FunctionDef):result[node.name+"."+child.name]=child
    return result
PROTECTED_AST_SHA256 = {'GitHub.rename': 'f60f0bd422ca1532ca7ef89e7bdd0d82e690b1852d41803c704d219fbc2921f8', 'stable_preflight': 'e1a759d2632ba0c02e79310673b0662abffbcdc1f8c1b69e17bb107c808f499d', 'restore_old_if_safe': '222c9d48f97d9ea24169d6dde1867bdb0f4f3cd097e4006b0ec3f84ee971c21d', 'require_advance': 'c37b8adf6e693e58203ddc51b1f55e5702bda9a8b8b1726b0f45de88d502c278', 'pending_name': '278dfa81a833108892ba5651333b41e4cc1035106082677ff84260cb902c754a', 'archived_name': 'f85ede3e41815ac7548b127a3cb0cf2898e9d2404267c94f642775c80db3f3f3', 'allowed_feed_name': '7f75e6dfafad81d7439a160ac5179a92087dbb4ae69c699a445cb9ccf9168fb6', 'GitHub.fetch': 'a8998d75d99d22777e9a8987d8121193c0eb2867dd6241561870a453b1cbb6af', 'GitHub.public_check': '209c3201a02bf3a343d23e970ecd70dab81ef310539b65709316a2ae93be1ad6', 'main': 'e9dc22904e2f350b0f8d382b41354298f33bf5e478e48a8a4900ca7c7965f5b4'}
PUBLISH_EXPIRY_CALLS_SHA256 = '91d84e7b15ac5e0186e91d33d219dc87895e346af67e2fd6540652d4a94c4da7'
OLD_ENV = base64.b64decode('eyJwYXlsb2FkQmFzZTY0IjoiZXlKelkyaGxiV0VpT2pFc0luQnliMlIxWTNRaU9pSlRiMnhoY2xONWMzUmxiVk5vYVdWc1pDSXNJbkIxY25CdmMyVWlPaUpUYjJ4aGNsTjVjM1JsYlZOb2FXVnNaQzVEZFhKeVpXNTBWWE5sY2xWcFZYQmtZWFJsTG5ZeElpd2ljSEp2Wm1sc1pTSTZJbU4xY25KbGJuUXRkWE5sY2kxMWFTMWpZVzVrYVdSaGRHVXRkakVpTENKamFHRnVibVZzSWpvaWMzUmhZbXhsSWl3aWEyVjVTV1FpT2lJeU5HTTFZMk0xWlRNMlpUa3lPR1ZoWlRRMk56ZGxZbUV4WkRaaU1qVTJZMk5qWVRrd05EQTVOalV5WXpObE5ETmlaalk1WkRjek5UZ3hZV1ZrTVdJeElpd2lkbVZ5YzJsdmJpSTZJakF1TkM0MkxqQWlMQ0p6WlhGMVpXNWpaU0k2TVN3aWNIVmliR2x6YUdWa1ZYUmpWR2xqYTNNaU9qWXpPVEk0T0RJM016QXdPREUyTWpJNE5Dd2laWGh3YVhKbGMxVjBZMVJwWTJ0eklqbzJNemt5T1RRek1qRXdNRGd4TmpJeU9EUXNJbkJoWTJ0aFoyVlZjbXdpT2lKb2RIUndjem92TDJkcGRHaDFZaTVqYjIwdmMyRnpkR0V3TWpBd01TMW9ZWE5vTDNOdmJHRnlMWE41YzNSbGJTMXNhVzVyTDNKbGJHVmhjMlZ6TDJSdmQyNXNiMkZrTDNOemN5MTFhUzEyTUM0MExqWXVNQzlUVTFNdE1DNDBMall1TUMxVlNTMTROalF1ZW1sd0lpd2ljR0ZqYTJGblpVSjVkR1Z6SWpvM05qQTNOak1zSW5CaFkydGhaMlZUYUdFeU5UWWlPaUk1WlRRNE56a3pNRFZtTnprd1ltUmlaV0kyTjJSbFlqSTVNekU1TVRRMk5UVXdZVGsxT1RnelpqQmxOR0l5TW1SbU5UWTJaRFl4T0dJNFlXWmhNbUZoSWl3aVptbHNaWE1pT2x0N0luQmhkR2dpT2lKVFUxTXVaWGhsSWl3aVlubDBaWE1pT2pjME56VXlNQ3dpYzJoaE1qVTJJam9pTlRkaU1qSm1ZbVV4T1dKaU16RXhOR0poWVRaaVl6VTBNekF4TVRJek9UQmxOVEF3WWpNNE16aGpaVEl5TkdSa05UYzJPV0ZpWm1ZeU1qbGlOR1UwT0NKOUxIc2ljR0YwYUNJNklsTlRVeTVEYjNKbExtUnNiQ0lzSW1KNWRHVnpJam8xT1RNNU1pd2ljMmhoTWpVMklqb2lNekV4TkRjM09UZzVZekU0WVdJNE9XWm1Oak5rWldReU56SXpaamxoTTJGbU9EWTBZVGMyTVRSa09EQmpOR0ZrWWpGbE5UVTFOamhqTVRjM01EVmxNU0o5TEhzaWNHRjBhQ0k2SWxOVFV5NUdkVzVqZEdsdmJtRnNMbVJzYkNJc0ltSjVkR1Z6SWpveE56azNNVElzSW5Ob1lUSTFOaUk2SW1WbE9UbGtaRGRtTm1ZNVpHRTNNRFU0TldJMU1UWTNOVFV3WlRjd09UbGtaalJpT1dNM01HVm1Zak0yTWpreU56QmpaVGMxWTJKa01tVXdZemhpWkRraWZTeDdJbkJoZEdnaU9pSlRVMU11VDNCbGNtRjBhVzl1Y3k1a2JHd2lMQ0ppZVhSbGN5STZNVEUwTVRjMkxDSnphR0V5TlRZaU9pSmpZamsxTkRrek1qRmpNbVZsWldVME1USm1aVFZqTm1FNU1Ea3hNREJsWlRoa1lXSTJaVGN3TTJJMU5tTmhOalk0WVRRNFlqQmtObU01TVdRNFlqTmhJbjBzZXlKd1lYUm9Jam9pVTFOVExsVndaR0YwWlhNdVpHeHNJaXdpWW5sMFpYTWlPalEyTURnd0xDSnphR0V5TlRZaU9pSmtaRE00Tm1Kak5XSXlaVFV3TmpZeU9XUXpNamszWVRrd05qaGlNRFV5WkRsbE5EZGlaREF6TUdZM1lqTmhNMkUzTlRrMlpqUTRaamhoWmpZek5ETXhJbjBzZXlKd1lYUm9Jam9pVTFOVExrOXdaWEpoZEdsdmJuTkliM04wTG1WNFpTSXNJbUo1ZEdWeklqbzBNRGsyTENKemFHRXlOVFlpT2lJd016QmhZVE5tTmpVNU1UVm1NV1ZtWkdOa05UQmtOams1WkdJeE5EWTFNems1WVRZMk5tVTBPVGs1TWpFek4yWTFOMlk1TWpaaE5qQmtPVEV6TkROa0luMHNleUp3WVhSb0lqb2lVMU5UTGs5d1pYSmhkR2x2Ym5OSWIzTjBMbVY0WlM1amIyNW1hV2NpTENKaWVYUmxjeUk2TWpVNExDSnphR0V5TlRZaU9pSXhZV1JoWmpNM09XWXhaR05pTjJZeFlUUTVNVFUyTkdGa1pqTm1OR0ZsTmpFNFpqZzVZVFEzWXpBek1UQXdNRFZoTm1KbE5UZzVaVGs1TlRNMU5XUTVJbjBzZXlKd1lYUm9Jam9pVTFOVExtVjRaUzVqYjI1bWFXY2lMQ0ppZVhSbGN5STZNekk1TENKemFHRXlOVFlpT2lJeVpXRTBZems1WlROak1HRXlaamRtWVRVd1pEZzBaR1EyTjJRME4yVmxNVFkxWm1Nek1qUXpZVEJsTlRJMllqZ3pOekkwWkRsaU1qa3hNRFkwTkRKaEluMHNleUp3WVhSb0lqb2lVMk55YVhCMGN5OVNaV0ZrVTNSaGRIVnpMbkJ6TVNJc0ltSjVkR1Z6SWpveE16QXhOeXdpYzJoaE1qVTJJam9pWXpNM09XSTFObVkwTnpBd05tUTRNbVppWVdNMk1HRmlNbUU0TTJFNE56ZzNNV1UyTkRGa05tUTRNbVZqTmpSaU9EZ3dPV05rTkRrM01XRTNNVEl3TUNKOUxIc2ljR0YwYUNJNklsTmpjbWx3ZEhNdlJtbHlaWGRoYkd4UGNHVnlZWFJwYjI0dWNITXhJaXdpWW5sMFpYTWlPakV4T1RJd0xDSnphR0V5TlRZaU9pSTFabVkwT1RFelpqUTRabUU1TVdGak0yUXpNRFF3TlRsbFptVXhZamM1TW1ZM05USTNZelV5TWpVMk1EWmtNbVJpTnpNMk56VTVOV1JpWldNMk5ESXlJbjBzZXlKd1lYUm9Jam9pVWtWQlJFMUZMbnBvTFZSWExuUjRkQ0lzSW1KNWRHVnpJam94TlRVNExDSnphR0V5TlRZaU9pSTNORGhsWkdObE5tTTJOMlE0TW1JNU0yUTFaR1l5WWpWbE9UUmhaV1EwTmpFM09UY3hOVEpoWmprMlpESTVORGc1WmpSbU1ETXdNekU0WTJaaU5XRXhJbjFkZlE9PSIsInNpZ25hdHVyZUJhc2U2NCI6ImJPM2kxRmtlcmI1dW1STWdRM01IQ2h2Y3lwcXdUeHFtbkFVUlRYV1pwWnBVQ0dGb1lEUWV1Z0hxamFPVjFBQzQyMGx6WCtjWVpiMWZ6Z2h1cUlLUDRleklJdWZMdVJ5bGsrSDJ4RUxvRHAzYVpyV2gzb0xuWDFaR09pM1Z3c1A1bTJ1SVh4VDNsMHdpbFVkVnYyNGhrdXYrV3A1RFA0M3Exb0pNQ1dlN090TzdEYmdzNXVEZXFSMk81eVB6bnEvWCtkR3d3cXJkeUptV3JWYWNockZvanpaUDB4VENEWHVTQk43YTAxTW5XSzcybDVFWFN5M2h6V3pBdVJKM0ZnZWxuTVpiaUNjZU5OQ256N3BzQmJJSVRqdmY1SDdrRmh6VVphaWJ4VFhvd0wzOWc0bVIrc1BVSHFEYW5QNTExODlSbmVlbU5DVjBVTWdJaEw2ZXFKam8xQT09In0=')
LEGACY_BODY = 'SSS-UI-PUBLISHER-V1: signed current-user UI assets only.\n\nSSS 0.4.6.0 CurrentUser UI 更新通道；不是 NativeReady/C1 或操作授權。Windows7 POS、無人值守與持續鍵鼠操作仍待實機驗收，非100分交付。\n\n既有0.4.5須先正常選一次『結束SSS』，再由新背景更新流程接續；不強殺舊程序。新Run登入啟動登錄已讀回，但下次真登入自啟尚未測試；不是Native全功能驗收。'

class MemoryGitHub(p.GitHub):
    """Actual GitHub adapter/state machine, replacing only its HTTP boundary."""
    def __init__(self):
        super().__init__("owned-dummy-not-a-credential",{"events":[]})
        self.releases={};self.data={};self.assets_by_release={};self.next=100
        self.calls=[];self.mutations=[];self.unknown_upload=False;self.unknown_rename=False;self.bad_public=False
    def event(self,operation,**fields):
        self.receipt["events"].append(dict(operation=operation,**fields))
    def fetch(self,url,limit,method="GET",body=None,authenticated=False,content_type=None,binary=False,public_redirect=False):
        self.calls.append((url,method))
        parsed=urllib.parse.urlsplit(url);path=parsed.path;value=None if body is None or content_type=="application/octet-stream" else json.loads(body)
        prefix="/repos/"+p.REPOSITORY
        def encoded(item):
            raw=p.canonical(item)
            if len(raw)>limit:raise p.PublishError("owned-response-bound")
            return raw
        def release_id():return int(path.split("/")[-1])
        def get_asset(asset_id):
            for rid,assets in self.assets_by_release.items():
                for name,item in assets.items():
                    if item["id"]==asset_id:return rid,name,item
            raise p.PublishError("github-http-404")
        if parsed.hostname=="github.com":
            tag,name=path.split("/releases/download/",1)[1].split("/",1);tag=urllib.parse.unquote(tag);name=urllib.parse.unquote(name)
            release=next(r for r in self.releases.values() if r["tag_name"]==tag)
            if release["draft"]:raise AssertionError("draft public read")
            item=self.assets_by_release[release["id"]][name]
            return b"bad" if self.bad_public else self.data[item["id"]]
        if method=="GET" and path==prefix:return encoded({"full_name":p.REPOSITORY,"private":False,"archived":False,"default_branch":"main"})
        if method=="GET" and "/releases/tags/" in path:
            tag=path.rsplit("/",1)[1]
            found=[r for r in self.releases.values() if r["tag_name"]==tag]
            if not found:raise p.PublishError("github-http-404")
            return encoded(found[0])
        if method=="POST" and path==prefix+"/releases":
            self.next+=1;rid=self.next
            item=dict(value,id=rid,immutable=False);self.releases[rid]=item;self.assets_by_release[rid]={}
            self.mutations.append(("create",value["tag_name"]))
            return encoded(item)
        if method=="GET" and "/releases/assets/" in path:
            return self.data[release_id()]
        if method=="GET" and path.endswith("/assets"):
            return encoded(list(self.assets_by_release[int(path.split("/")[-2])].values()))
        if method=="GET":return encoded(self.releases[release_id()])
        if parsed.hostname=="uploads.github.com":
            rid=int(path.split("/")[-2]);name=urllib.parse.parse_qs(parsed.query)["name"][0]
            if name in self.assets_by_release[rid]:raise AssertionError("asset overwrite")
            self.next+=1;item={"id":self.next,"name":name,"size":len(body),"state":"uploaded"}
            self.assets_by_release[rid][name]=item;self.data[item["id"]]=body;self.mutations.append(("upload",name))
            if self.unknown_upload:raise p.PublishError("owned-unknown-after-upload")
            return encoded(item)
        if method=="PATCH" and "/releases/assets/" in path:
            rid,name,item=get_asset(release_id());after=value["name"]
            if after in self.assets_by_release[rid]:raise AssertionError("rename overwrite")
            del self.assets_by_release[rid][name];item["name"]=after;self.assets_by_release[rid][after]=item
            self.mutations.append(("rename",name,after))
            if self.unknown_rename:raise p.PublishError("owned-unknown-after-rename")
            return encoded(item)
        if method=="PATCH":
            item=self.releases[release_id()];item.update(value);self.mutations.append(("publish",item["tag_name"]))
            return encoded(item)
        raise AssertionError("unexpected HTTP operation")
    def fixed(self,tag):return next(r for r in self.releases.values() if r["tag_name"]==tag)

def test_true_four_delivery_inputs_and_request_bindings():
    request,catalog,members=p.load_bundle(STAGE)
    assert set(members)==set(p.VERSION_ASSET_NAMES)|{p.ENVELOPE_NAME,p.ACTIVATION_NAME}
    assert catalog["version"]=="0.4.7.0" and catalog["sequence"]==2
    assert request["initialSetupBytes"]==849998 and request["repairBytes"]==914735
    assert len(p.INITIAL_FILES)==7 and len(p.REPAIR_FILES)==7
    for data,vector in ((members[p.INITIAL_NAME],p.INITIAL_FILES),(members[p.REPAIR_NAME],p.REPAIR_FILES)):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            assert len(archive.infolist())==7 and set(archive.namelist())==set(vector)
            for name,(size,digest) in vector.items():
                raw=archive.read(name);assert len(raw)==size and p.sha(raw)==digest
    p.verify_known_ui(members[p.PACKAGE_NAME],members[p.ENVELOPE_NAME])
    with zipfile.ZipFile(io.BytesIO(members[p.REPAIR_NAME])) as archive:
        p.verify_known_bootstrap({name:archive.read("repair-input/"+name) for name in p.KNOWN_BOOTSTRAP})
    for field,value in (("initialSetupBytes",True),("repairSha256","0"*64)):
        changed=dict(request);changed[field]=value
        denied(lambda:p.validate_inputs(p.canonical(changed),members[p.PACKAGE_NAME],members[p.ENVELOPE_NAME],members[p.INITIAL_NAME],members[p.REPAIR_NAME],members[p.ACTIVATION_NAME]),"initial-or-repair-request-pin")
    denied(lambda:p.verify_final_initial_and_repair(members[p.INITIAL_NAME],members[p.PACKAGE_NAME]),"repair-approved-package-binding")
    bad=members[p.REPAIR_NAME][:-1]+bytes([members[p.REPAIR_NAME][-1]^1])
    denied(lambda:p.verify_final_initial_and_repair(members[p.INITIAL_NAME],bad),"repair-approved-package-binding")
    return request,catalog,members

def assert_protected_ast_and_ownership():
    assert p.VERSION_ASSET_NAMES==("SSS-0.4.7.0-UI-x64.zip","SSS-0.4.7.0-Background-Initial-Setup.zip","SSS-0.4.7.0-Background-Repair-From-0.4.6.zip")
    assert p.RELEASE_BODY==LEGACY_BODY and p.release_body(p.STABLE_TAG)==LEGACY_BODY
    assert p.release_body(p.VERSION_TAG)==p.RELEASE_BODY_047!=LEGACY_BODY
    current=funcs(ast.parse(Path(p.__file__).read_text(encoding="utf-8-sig")))
    for name,digest in PROTECTED_AST_SHA256.items():assert hashlib.sha256(ast.dump(current[name]).encode("utf-8")).hexdigest()==digest,name
    expiry=[ast.dump(call) for call in ast.walk(current["publish"]) if isinstance(call,ast.Call) and isinstance(call.func,ast.Name) and call.func.id=="verify_envelope"]
    assert hashlib.sha256(json.dumps(expiry,separators=(",",":")).encode("utf-8")).hexdigest()==PUBLISH_EXPIRY_CALLS_SHA256

def test_real_record_allows_only_memory_publish(request,catalog,members):
    assert_protected_ast_and_ownership()
    record=members[p.ACTIVATION_NAME]
    assert len(record)==1247 and p.sha(record)=="9336e58820af11d9f26f0b3b837f2378cc3611e860e13183ef0c76c917c96bbc"
    value=p.require_actual_repair_activation(record,request,catalog,members[p.ENVELOPE_NAME],members[p.REPAIR_NAME])
    assert value["sourceReceiptSha256"]=="b01f2d5eed23e701e13ab410987cc60784a4c5e6817a8623e541e18a8f52ce7f"
    assert value["sourceReceiptBytes"]==3592 and value["sourceObservedUtc"]=="2026-10-29T07:59:27.8704907Z"
    assert value["latestVerified"] is False and value["nativeReady"] is False and value["grantsMaintenanceOrRemoteInput"] is False
    client=MemoryGitHub()
    # Seed only the actual historical signed046 feed in memory. Existing046
    # version assets are outside both new target tags and are never requested.
    stable=client.create_draft(p.STABLE_TAG,COMMIT);client.ensure_asset(stable,p.ENVELOPE_NAME,OLD_ENV);stable=client.publish_draft(stable)
    client.calls.clear();client.mutations.clear()
    p.publish(client,request,catalog,members,COMMIT)
    version=client.fixed(p.VERSION_TAG)
    assert set(client.assets(version))==set(p.VERSION_ASSET_NAMES)
    stable=client.fixed(p.STABLE_TAG)
    assert client.release(stable["id"])["body"]==LEGACY_BODY
    assert client.asset_bytes(client.assets(stable)[p.ENVELOPE_NAME],8192)==members[p.ENVELOPE_NAME]
    assert p.ACTIVATION_NAME not in client.assets(version) and p.ACTIVATION_NAME not in client.assets(stable)
    assert any(event["operation"]=="stable-feed-verified" for event in client.receipt["events"])
    count=len(client.mutations)
    denied(lambda:client.ensure_asset(version,p.ACTIVATION_NAME,record),"upload-name-or-size")
    denied(lambda:client.validate_release(dict(stable,body=p.RELEASE_BODY_047)),"release-metadata-unknown")
    assert len(client.mutations)==count

def test_bad_or_missing_record_wrong_tuple_and_caller_flags_before_api(request,catalog,members):
    cases=[]
    client=MemoryGitHub();missing=dict(members);missing.pop(p.ACTIVATION_NAME)
    denied(lambda:p.publish(client,request,catalog,missing,COMMIT),"fixed-five-inputs");cases.append("missing-record")
    changed=dict(members);changed[p.ACTIVATION_NAME]=members[p.ACTIVATION_NAME][:-1]+bytes([members[p.ACTIVATION_NAME][-1]^1])
    denied(lambda:p.publish(client,request,catalog,changed,COMMIT),"activation-record-byte-pin");cases.append("changed-raw-bytes")
    for fake in (True,b"true"):
        changed=dict(members);changed[p.ACTIVATION_NAME]=fake
        denied(lambda:p.publish(client,request,catalog,changed,COMMIT),"activation-record-size")
    cases.append("bool-or-true-is-not-a-record")
    changed_request=dict(request);changed_request["activationRecordSha256"]="0"*64
    denied(lambda:p.publish(client,changed_request,catalog,members,COMMIT),"activation-record-request-pin");cases.append("wrong-request-binding")
    changed_request=dict(request);changed_request["envelopeSha256"]="0"*64
    denied(lambda:p.require_actual_repair_activation(members[p.ACTIVATION_NAME],changed_request,catalog,members[p.ENVELOPE_NAME],members[p.REPAIR_NAME]),"activation-record-bundle-binding");cases.append("real-record-wrong-catalog-tuple")
    changed_catalog=dict(catalog);changed_catalog["sequence"]=3
    denied(lambda:p.publish(client,request,changed_catalog,members,COMMIT),"catalog-object-not-verified-bytes");cases.append("caller-manifest-replaced")
    for key,value in (("activationAllowed",True),("root","owned-alternate-root")):
        changed_request=dict(request);changed_request[key]=value
        denied(lambda:p.publish(client,changed_request,catalog,members,COMMIT),"unexpected-fields")
    cases.append("caller-bool-or-root-not-accepted")
    assert tuple(inspect.signature(p.require_actual_repair_activation).parameters)==("raw","request","catalog","envelope","repair")
    assert not client.calls and not client.mutations
    return cases

if __name__=="__main__":
    request,catalog,members=test_true_four_delivery_inputs_and_request_bindings()
    test_real_record_allows_only_memory_publish(request,catalog,members)
    negatives=test_bad_or_missing_record_wrong_tuple_and_caller_flags_before_api(request,catalog,members)
    print(json.dumps({"owned047R3FocusedResult":{"passed":3,"failed":0,"negativeSubcases":negatives,"exactSanitizedRaw1247AndAllFields":True,"realRecordBoundToActualBundle":True,"sourceCommitmentB01Fixed":True,"validRecordMemoryPublishOnly":True,"activationNotAReleaseAssetOrKeyProof":True,"badInputsRejectedBeforeAnyApi":True,"protectedStableAndExpiryAstUnchanged":True,"old19OrExpiry7OrInitial14OrRepairSuitesRerun":False,"privateRawReceiptRead":False,"realHTTP":False,"productExecuted":False,"actualPublicationExecuted":False,"newFees":0,"paidCredits":0,"exactTaskTokens":None}},separators=(",",":")))

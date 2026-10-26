# ruff: noqa: E501
"""Zscaler POV seed stack: writes SYNTHETIC records to the stack's own buckets and table, and empties them on delete.

Every person, card, number and diagnosis here is made up. Card numbers are the networks' published test numbers;
SSNs are in 987-65-4320..4329, the range the US SSA set aside for advertising (never issued); phone numbers are
555-01xx; emails are @example.com. Nothing outside this stack's buckets and table is touched.
"""
import io
import json
import os
import random
import urllib.request
import zipfile

import boto3

s3 = boto3.client("s3")
ddb = boto3.client("dynamodb")
FIRST = ["Avery", "Jordan", "Riley", "Casey", "Morgan", "Quinn", "Harper", "Rowan", "Emerson", "Reese", "Skyler",
         "Dakota", "Finley", "Hayden", "Parker", "Sawyer"]
LAST = ["Testwell", "Sampleton", "Fakeley", "Demoson", "Mockridge", "Placer", "Dummet", "Notreal", "Examplar",
        "Pretendo"]
CARDS = ["4111111111111111", "5555555555554444", "378282246310005", "6011111111111117", "4012888888881881",
         "5105105105105100", "4242424242424242"]
DIAG = ["E11.9 Type 2 diabetes", "I10 Essential hypertension", "J45.909 Asthma", "F41.1 Generalized anxiety disorder",
        "M54.5 Low back pain", "K21.9 Reflux disease"]
TAG = "zpov-synthetic=true"


def people(n, seed):
    r = random.Random(seed)
    out = []
    for i in range(n):
        f, last = r.choice(FIRST), r.choice(LAST)
        out.append({
            "customer_id": f"ZP{100000 + i}", "name": f"{f} {last}", "email": f"{f}.{last}{i}@example.com".lower(),
            "phone": f"(212) 555-01{i % 100:02d}", "address": f"{r.randint(10, 999)} Test Street, Springfield, NY 1{r.randint(1000, 1999)}",
            "date_of_birth": f"19{r.randint(55, 99)}-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}",
            "ssn": f"987-65-432{i % 10}", "card_number": r.choice(CARDS), "card_expiry": f"{r.randint(1, 12):02d}/{r.randint(27, 31)}",
            "iban": f"GB{r.randint(10, 99)}TEST{r.randint(10**13, 10**14 - 1)}", "diagnosis": r.choice(DIAG),
            "member_id": f"HP-{r.randint(10**7, 10**8 - 1)}", "salary_usd": r.randint(55, 240) * 1000})
    return out


def csv(rows, cols=None):
    cols = cols or list(rows[0])
    return ",".join(cols) + "\n" + "\n".join(",".join('"%s"' % str(x[c]).replace('"', "'") for c in cols) for x in rows) + "\n"


def lines_of(rows, cols):
    return [" | ".join(str(x[c]) for c in cols) for x in rows]


def pdf(title, lines):
    esc = lambda s: s.replace("\\", "/").replace("(", "[").replace(")", "]")  # noqa: E731
    text = "BT /F1 9 Tf 40 760 Td 12 TL (%s) Tj T* T* " % esc(title) + " ".join("(%s) Tj T*" % esc(x) for x in lines[:55]) + " ET"
    objs = ["<</Type/Catalog/Pages 2 0 R>>", "<</Type/Pages/Kids[3 0 R]/Count 1>>",
            "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 5 0 R>>>>/Contents 4 0 R>>",
            "<</Length %d>>stream\n%s\nendstream" % (len(text), text), "<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>"]
    body, offs = "%PDF-1.4\n", []
    for i, o in enumerate(objs):
        offs.append(len(body))
        body += "%d 0 obj\n%s\nendobj\n" % (i + 1, o)
    xref = "xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1) + "".join("%010d 00000 n \n" % o for o in offs)
    return (body + xref + "trailer<</Size %d/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, len(body))).encode("latin-1", "replace")


def docx(title, lines):
    esc = lambda s: s.replace("&", "and").replace("<", "").replace(">", "")  # noqa: E731
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
                   '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        z.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        paras = "".join("<w:p><w:r><w:t xml:space=\"preserve\">%s</w:t></w:r></w:p>" % esc(x) for x in [title] + lines)
        z.writestr("word/document.xml", '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                   "<w:body>%s</w:body></w:document>" % paras)
    return buf.getvalue()


def put(bucket, key, data, ctype):
    s3.put_object(Bucket=bucket, Key=key, Body=data if isinstance(data, bytes) else data.encode(), ContentType=ctype, Tagging=TAG)


README = ("SYNTHETIC TEST DATA for a Zscaler proof of value. Every person, card, account and diagnosis in this bucket is made up "
          "(card numbers are published test numbers; SSNs are in the never-issued 987-65-432x range). Deleting the "
          "CloudFormation stack deletes it all.\n")


def seed(n):
    rec, mis, trn, table = (os.environ[k] for k in ("RECORDS_BUCKET", "MISCONFIGURED_BUCKET", "TRAINING_BUCKET", "TABLE"))
    rows = people(n, 7)
    cust = ["customer_id", "name", "email", "phone", "address", "date_of_birth", "card_number", "card_expiry"]
    for b in (rec, mis, trn):
        put(b, "README-ZPOV.txt", README, "text/plain")
    for i in range(0, n, 100):
        put(rec, f"customers/customers-{i // 100 + 1:03d}.csv", csv(rows[i:i + 100], cust), "text/csv")
    put(rec, "customers/customers.json", json.dumps([{c: x[c] for c in cust} for x in rows], indent=1), "application/json")
    put(rec, "hr/payroll-2026.csv", csv(rows[:120], ["name", "ssn", "date_of_birth", "iban", "salary_usd"]), "text/csv")
    put(rec, "health/patients.json", json.dumps([{c: x[c] for c in ("name", "date_of_birth", "member_id", "diagnosis")} for x in rows[:150]], indent=1), "application/json")
    put(rec, "finance/card-export.txt", "\n".join(f"{x['name']}  {x['card_number']}  exp {x['card_expiry']}" for x in rows[:80]), "text/plain")
    for k in range(5):
        part = rows[k * 20:(k + 1) * 20]
        put(rec, f"docs/customer-statement-{k + 1}.pdf", pdf(f"Customer statement {k + 1} (synthetic test data)", lines_of(part, ["name", "card_number", "address"])), "application/pdf")
        put(rec, f"docs/hr-review-{k + 1}.docx", docx(f"HR review {k + 1} (synthetic test data)", lines_of(part, ["name", "ssn", "salary_usd", "diagnosis"])),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    put(rec, "confidential/project-falcon-roadmap.docx", docx("CONFIDENTIAL: Project Falcon roadmap (synthetic test data)",
        ["Internal only. Do not distribute.", "Q3: launch Falcon in EMEA; pricing 40 percent below the market leader.",
         "Acquisition target shortlist: Example Corp, Sample Ltd.", "Board approval expected at the November meeting."]),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    put(mis, "exports/customer-export.csv", csv(rows[:50], cust + ["ssn"]), "text/csv")
    put(mis, "backups/patients-backup.json", json.dumps(rows[50:100], indent=1), "application/json")
    put(mis, "public-decoy/zpov-decoy.csv", csv(rows[100:105], ["name", "email", "card_number"]), "text/csv")
    chats = []
    for x in rows[:60]:
        chats.append({"messages": [
            {"role": "user", "content": f"Hi, I'm {x['name']}, card {x['card_number']}, my order hasn't arrived. Email me at {x['email']}."},
            {"role": "assistant", "content": f"Sorry {x['name'].split()[0]}, I've reissued it to {x['address']}."}]})
    put(trn, "finetune/support-chats.jsonl", "\n".join(json.dumps(c) for c in chats) + "\n", "application/jsonl")
    claims = [{"prompt": f"Claim for {x['name']} (DOB {x['date_of_birth']}, member {x['member_id']}): {x['diagnosis']}. Approve?",
               "completion": "Approve" if i % 3 else "Refer to review"} for i, x in enumerate(rows[60:120])]
    put(trn, "finetune/claims-triage.jsonl", "\n".join(json.dumps(c) for c in claims) + "\n", "application/jsonl")
    for i in range(0, min(n, 200), 25):
        ddb.batch_write_item(RequestItems={table: [{"PutRequest": {"Item": {k: {"S": str(v)} for k, v in x.items()}}}
                                                   for x in rows[i:i + 25]]})


def empty(bucket):
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})
    except s3.exceptions.NoSuchBucket:
        pass


def respond(event, ctx, status, reason=""):
    body = json.dumps({"Status": status, "Reason": (reason or "see the function's CloudWatch log")[:900],
                       "PhysicalResourceId": event.get("PhysicalResourceId") or "zpov-seed-data",
                       "StackId": event["StackId"], "RequestId": event["RequestId"], "LogicalResourceId": event["LogicalResourceId"]}).encode()
    req = urllib.request.Request(event["ResponseURL"], data=body, method="PUT", headers={"Content-Type": "", "Content-Length": str(len(body))})
    urllib.request.urlopen(req, timeout=30)


def handler(event, ctx):
    try:
        if event["RequestType"] == "Delete":
            for k in ("RECORDS_BUCKET", "MISCONFIGURED_BUCKET", "TRAINING_BUCKET"):
                empty(os.environ[k])
        else:
            seed(int(event.get("ResourceProperties", {}).get("Records") or 300))
        respond(event, ctx, "SUCCESS")
    except Exception as e:   # noqa: BLE001
        print("seed failed:", repr(e))
        respond(event, ctx, "FAILED", f"{type(e).__name__}: {e}")

"""zpov-support-agent: a small AI agent for the POV seed stack. It reads its (synthetic) training data and asks a
Bedrock model about it. Its IAM role is deliberately broader than it needs, so AI-SPM and DSPM have a finding to show.
Test it from the Lambda console with {"question": "..."} or an empty event."""
import os

import boto3


def handler(event, ctx):
    s3 = boto3.client("s3")
    data = s3.get_object(Bucket=os.environ["TRAINING_BUCKET"], Key="finetune/support-chats.jsonl")["Body"].read().decode()[:3000]
    q = (event or {}).get("question") or "In two sentences: what is the most common support issue here? Leave out personal details."
    r = boto3.client("bedrock-runtime").converse(
        modelId=os.environ["MODEL_ID"], messages=[{"role": "user", "content": [{"text": q + "\n\n" + data}]}],
        inferenceConfig={"maxTokens": 300})
    return {"model": os.environ["MODEL_ID"], "answer": r["output"]["message"]["content"][0]["text"]}

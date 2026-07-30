import sys
import json
import time

try:
    from fastapi.testclient import TestClient
    from src.fake_certificate_verification_agent.main import app
except Exception as e:
    print(f"Error importing app: {e}")
    sys.exit(1)

client = TestClient(app)

print("\n--- 1. Testing GET /api/workflows ---")
res = client.get("/api/workflows")
print(f"Status: {res.status_code}")
assert res.status_code == 200
print(f"Workflows: {[w['workflow_id'] for w in res.json().get('workflows', [])]}")

print("\n--- 2. Testing GET /api/workflows/template-document-trust ---")
res = client.get("/api/workflows/template-document-trust")
print(f"Status: {res.status_code}")
assert res.status_code == 200
print(f"Workflow Name: {res.json().get('name')}")
print(f"Agents Count: {len(res.json().get('agents', []))}")

print("\n--- 3. Testing POST /api/verify/gdrive ---")
payload = {"drive_url": "https://drive.google.com/drive/folders/1A2B3C4D5E6F7G8H9I0J_TestDemoFolder"}
res = client.post("/api/verify/gdrive", json=payload)
print(f"Status: {res.status_code}")
assert res.status_code == 200
data = res.json()
print(f"Workflow ID: {data.get('workflow_id')}")
print(f"Workflow Status: {data.get('status')}")
print(f"Overall Decision: {data.get('report', {}).get('summary', {}).get('decision')}")
print(f"Trust Score: {data.get('report', {}).get('summary', {}).get('trust_score')}%")

wf_id = data.get('workflow_id')

print("\n--- 4. Testing GET /api/verify/gdrive/status/{workflow_id} ---")
res = client.get(f"/api/verify/gdrive/status/{wf_id}")
print(f"Status Code: {res.status_code}")
assert res.status_code == 200
print(f"Status Payload: {res.json()}")

print("\n--- 5. Testing GET /api/verify/gdrive/history ---")
res = client.get("/api/verify/gdrive/history")
print(f"Status Code: {res.status_code}")
assert res.status_code == 200
print(f"History Records Count: {res.json().get('count')}")

print("\n[SUCCESS] ALL BACKEND ENDPOINT TESTS PASSED SUCCESSFULLY!\n")

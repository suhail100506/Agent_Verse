import sys

try:
    from fastapi.testclient import TestClient
    from src.fake_certificate_verification_agent.main import app
except Exception as e:
    print(f"Error importing app: {e}")
    sys.exit(1)

client = TestClient(app)

print("\n--- 1. Testing Invalid Google Drive Link (Link Validation Check) ---")
res = client.post("/api/verify/gdrive", json={"drive_url": "invalid_url_string_http_not_drive"})
print(f"Status Code: {res.status_code}")
print(f"Response Payload Code: {res.json().get('detail', {}).get('code')}")
assert res.status_code == 400
assert res.json().get("detail", {}).get("code") == "GD001"
print("[SUCCESS] Invalid Link Validation correctly blocked with GD001!")

print("\n--- 2. Testing Link 1 (Sarah Jenkins Profile) ---")
link1 = "https://drive.google.com/drive/folders/1_SarahJenkins_DemoFolder_AAA"
res1 = client.post("/api/verify/gdrive", json={"drive_url": link1})
data1 = res1.json()
name1 = data1.get("agents", {}).get("identity", {}).get("output", {}).get("name")
trust1 = data1.get("report", {}).get("summary", {}).get("trust_score")
print(f"Link 1 ({link1}): Name='{name1}', Trust Score={trust1}%")

print("\n--- 3. Testing Link 2 (Elena Rostova Profile) ---")
link2 = "https://drive.google.com/drive/folders/2_ElenaRostova_DemoFolder_BBB"
res2 = client.post("/api/verify/gdrive", json={"drive_url": link2})
data2 = res2.json()
name2 = data2.get("agents", {}).get("identity", {}).get("output", {}).get("name")
trust2 = data2.get("report", {}).get("summary", {}).get("trust_score")
print(f"Link 2 ({link2}): Name='{name2}', Trust Score={trust2}%")

print("\n--- 4. Testing Link 3 (Alexander Wright Profile) ---")
link3 = "https://drive.google.com/drive/folders/3_AlexanderWright_DemoFolder_CCC"
res3 = client.post("/api/verify/gdrive", json={"drive_url": link3})
data3 = res3.json()
name3 = data3.get("agents", {}).get("identity", {}).get("output", {}).get("name")
trust3 = data3.get("report", {}).get("summary", {}).get("trust_score")
print(f"Link 3 ({link3}): Name='{name3}', Trust Score={trust3}%")

assert name1 != name2, "Results must be dynamic across different links!"
assert name2 != name3, "Results must be dynamic across different links!"

print("\n[SUCCESS] ALL DYNAMIC LINK TESTS AND VALIDATION CHECKS PASSED!\n")

import asyncio
from backend.main import health_check, run_scan, ScanRequest
from backend.scanner import SecurityScanner

async def main():
    print("1. Testing Health Check...")
    health = await health_check()
    print("   Health Result:", health)
    assert health["status"] == "ok"

    print("2. Testing Scan Endpoint with 'https://example.com'...")
    req = ScanRequest(url="https://example.com")
    scan_res = await run_scan(req)
    print("   Scan Target:", scan_res["target_url"])
    print("   Scan Score:", scan_res["score"], "Grade:", scan_res["grade"], "Risk:", scan_res["risk_level"])
    print("   Findings Detected:", len(scan_res["findings"]))
    assert scan_res["score"] >= 0
    assert len(scan_res["findings"]) > 0

    print("3. Testing Scanner on 'http://httpforever.com'...")
    scanner = SecurityScanner("http://httpforever.com")
    http_res = scanner.scan()
    print("   HTTP forever grade:", http_res["grade"], "Findings:", len(http_res["findings"]))
    assert any(f["id"] == "SEC-001" for f in http_res["findings"]), "HTTPS missing check failed!"

    print("\nALL BACKEND VERIFICATION TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    asyncio.run(main())

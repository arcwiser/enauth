import requests
import pyotp
import sys

BASE_URL = "https://127.0.0.1:8080"

def main():
    print("Starting programmatically automated 2FA system integration tests...")
    
    # Disable SSL warning for local self-signed cert
    requests.packages.urllib3.disable_warnings()
    session = requests.Session()
    session.verify = False

    # 1. Login with standard credentials
    print("\n1. Testing standard admin login...")
    login_res = session.post(f"{BASE_URL}/api/admin/auth/login", json={
        "username": "admin",
        "password": "EnAuth@Admin123!"
    })
    if login_res.status_code != 200:
        print(f"FAILED: Login returned {login_res.status_code}: {login_res.text}")
        sys.exit(1)
    
    login_data = login_res.json()
    token = login_data["token"]
    print(f"SUCCESS: Logged in. Token retrieved: {token[:10]}...")

    # Set authentication header for session
    session.headers.update({"Authorization": f"Bearer {token}"})

    # 2. Setup Two-Factor Authentication
    print("\n2. Requesting 2FA setup details...")
    setup_res = session.post(f"{BASE_URL}/api/admin/auth/2fa/setup")
    if setup_res.status_code != 200:
        print(f"FAILED: 2FA Setup returned {setup_res.status_code}: {setup_res.text}")
        sys.exit(1)
    
    setup_data = setup_res.json()
    secret = setup_data["secret"]
    provisioning_uri = setup_data["provisioning_uri"]
    print(f"SUCCESS: 2FA setup initiated. Secret: {secret}, URI: {provisioning_uri}")

    # 3. Generate TOTP code and Enable 2FA
    totp = pyotp.TOTP(secret)
    code = totp.now()
    print(f"\n3. Verifying setup with code {code}...")
    enable_res = session.post(f"{BASE_URL}/api/admin/auth/2fa/enable", json={
        "code": code
    })
    if enable_res.status_code != 200:
        print(f"FAILED: Enabling 2FA returned {enable_res.status_code}: {enable_res.text}")
        sys.exit(1)
    print("SUCCESS: Two-factor authentication successfully enabled!")

    # 4. Logout to test login redirect flow
    print("\n4. Logging out to test 2FA challenge...")
    session.post(f"{BASE_URL}/api/admin/auth/logout")
    session.headers.pop("Authorization", None)

    # 5. Attempt login with 2FA enabled
    print("\n5. Attempting to login with username and password...")
    login2fa_res = session.post(f"{BASE_URL}/api/admin/auth/login", json={
        "username": "admin",
        "password": "EnAuth@Admin123!"
    })
    if login2fa_res.status_code != 200:
        print(f"FAILED: Login failed: {login2fa_res.text}")
        sys.exit(1)
    
    login2fa_data = login2fa_res.json()
    if not login2fa_data.get("two_factor_required"):
        print("FAILED: Server did not require 2FA redirect token!")
        sys.exit(1)
    
    temp_token = login2fa_data["temp_token"]
    print(f"SUCCESS: 2FA required challenge triggered. Temp Token: {temp_token[:10]}...")

    # 6. Verify with incorrect code first
    print("\n6. Testing verification with invalid 2FA code...")
    verify_bad_res = session.post(f"{BASE_URL}/api/admin/auth/2fa/verify", json={
        "temp_token": temp_token,
        "code": "123456"
    })
    if verify_bad_res.status_code != 401:
        print(f"FAILED: Expected 401 Unauthorized for bad code, got {verify_bad_res.status_code}")
        sys.exit(1)
    print("SUCCESS: Rejected incorrect 2FA passcode.")

    # 7. Verify with correct code
    code = totp.now()
    print(f"\n7. Verifying challenge with valid code {code}...")
    verify_res = session.post(f"{BASE_URL}/api/admin/auth/2fa/verify", json={
        "temp_token": temp_token,
        "code": code
    })
    if verify_res.status_code != 200:
        print(f"FAILED: 2FA Verification returned {verify_res.status_code}: {verify_res.text}")
        sys.exit(1)
    
    verify_data = verify_res.json()
    new_token = verify_data["token"]
    print(f"SUCCESS: Authenticated! New session token retrieved: {new_token[:10]}...")
    session.headers.update({"Authorization": f"Bearer {new_token}"})

    # 8. Disable 2FA to return account to initial state
    code = totp.now()
    print(f"\n8. Disabling 2FA to clean up credentials...")
    disable_res = session.post(f"{BASE_URL}/api/admin/auth/2fa/disable", json={
        "code": code
    })
    if disable_res.status_code != 200:
        print(f"FAILED: Disabling 2FA returned {disable_res.status_code}: {disable_res.text}")
        sys.exit(1)
    print("SUCCESS: Two-factor authentication successfully disabled. Clean-up complete.")
    print("\nALL 2FA INTEGRATION TESTS PASSED WITH 100% CORRECTNESS!")

if __name__ == "__main__":
    main()

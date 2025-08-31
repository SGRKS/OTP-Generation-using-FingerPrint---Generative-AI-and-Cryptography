"""
Fingerprint OTP Generator - Combined Demo
----------------------------------------
This script demonstrates:
1. Direct usage of FingerprintOTPGenerator
2. API wrapper usage (FingerprintOTPAPI)
"""

# Import from your project files
from Fingerprint_OTP_Generation import FingerprintOTPGenerator
from api_wrapper import FingerprintOTPAPI, OTPRequest


def demo_direct_usage():
    print("\n=== Direct OTP Generator Demo ===")
    # Initialize OTP generator
    generator = FingerprintOTPGenerator(otp_length=8, otp_validity_minutes=5)

    # Generate OTP for a service
    otp_record = generator.generate_otp("user_123", "crypto_wallet")
    print(f"Generated OTP for crypto_wallet: {otp_record['otp']}")

    # Verify OTP
    is_valid = generator.verify_otp(
        otp_record["otp"], "user_123", "crypto_wallet", otp_record
    )
    print("Verification result:", "✅ Valid" if is_valid else "❌ Invalid")


def demo_api_usage():
    print("\n=== API Wrapper Demo ===")
    # Initialize API wrapper
    api = FingerprintOTPAPI()

    # Create request
    request = OTPRequest(user_id="user_456", service_name="netbanking")

    # Generate OTP
    response = api.generate_otp(request)
    if response.success:
        print(f"Generated OTP for netbanking: {response.otp}")

        # Verify OTP
        verify_resp = api.verify_otp(request, response.otp, response.otp_record)
        print("Verification result:", "✅ Valid" if verify_resp.success else "❌ Invalid")
    else:
        print("OTP generation failed.")


if __name__ == "__main__":
    demo_direct_usage()
    demo_api_usage()

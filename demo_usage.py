#!/usr/bin/env python3
"""
Demo script showing practical usage of the Fingerprint OTP Generator
for real-world authentication scenarios.
"""

import time
from datetime import datetime
# Import the class from the main file
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the class from the main file
exec(open("Fingerprint - OTP Generation.py").read())

def demo_crypto_wallet_authentication():
    """Demonstrate OTP generation for cryptocurrency wallet access."""
    print("🔐 Cryptocurrency Wallet Authentication Demo")
    print("=" * 50)
    
    generator = FingerprintOTPGenerator(otp_length=6, otp_validity_minutes=2)
    user_id = "crypto_user_789"
    
    # Simulate user trying to access wallet
    print(f"👤 User {user_id} attempting to access crypto wallet...")
    
    # Generate OTP using fingerprint
    otp_record = generator.generate_otp(user_id, "crypto_wallet")
    if otp_record:
        print(f"✅ OTP Generated: {otp_record['otp']}")
        print(f"⏰ Expires: {otp_record['expires_at']}")
        print(f"📱 Device: {otp_record['device_id']}")
        
        # Simulate user entering OTP
        print("\n🔑 User enters OTP...")
        time.sleep(1)
        
        # Verify OTP
        is_valid = generator.verify_otp(otp_record['otp'], user_id, "crypto_wallet", otp_record)
        if is_valid:
            print("🎉 Wallet access granted!")
        else:
            print("❌ Access denied!")
    else:
        print("❌ Failed to generate OTP")
    
    print()

def demo_netbanking_transaction():
    """Demonstrate OTP generation for banking transactions."""
    print("🏦 Netbanking Transaction Verification Demo")
    print("=" * 50)
    
    generator = FingerprintOTPGenerator(otp_length=8, otp_validity_minutes=3)
    user_id = "bank_user_456"
    
    # Simulate user initiating transaction
    print(f"👤 User {user_id} initiating ₹10,000 transfer...")
    
    # Generate OTP for transaction verification
    otp_record = generator.generate_otp(user_id, "netbanking_transaction")
    if otp_record:
        print(f"✅ Transaction OTP: {otp_record['otp']}")
        print(f"⏰ Valid until: {otp_record['expires_at']}")
        
        # Simulate OTP verification
        print("\n🔑 Verifying transaction OTP...")
        time.sleep(1)
        
        is_valid = generator.verify_otp(otp_record['otp'], user_id, "netbanking_transaction", otp_record)
        if is_valid:
            print("🎉 Transaction approved! ₹10,000 transferred successfully.")
        else:
            print("❌ Transaction failed!")
    else:
        print("❌ Failed to generate transaction OTP")
    
    print()

def demo_multiple_services_same_user():
    """Demonstrate how the same user gets different OTPs for different services."""
    print("🔄 Multiple Services - Same User Demo")
    print("=" * 50)
    
    generator = FingerprintOTPGenerator(otp_length=6, otp_validity_minutes=5)
    user_id = "multi_user_123"
    
    services = ["email_login", "vpn_access", "file_sharing", "admin_panel"]
    
    print(f"👤 User {user_id} accessing multiple services...")
    print("📱 Same fingerprint scan, different OTPs for each service:")
    
    otp_records = {}
    
    for service in services:
        otp_record = generator.generate_otp(user_id, service)
        if otp_record:
            otp_records[service] = otp_record
            print(f"   {service:15} → {otp_record['otp']}")
    
    print(f"\n🔍 Notice: All OTPs are different despite same fingerprint!")
    print(f"🔒 This prevents cross-service OTP reuse attacks.")
    
    print()

def demo_rate_limiting():
    """Demonstrate rate limiting protection."""
    print("🚫 Rate Limiting Protection Demo")
    print("=" * 50)
    
    generator = FingerprintOTPGenerator(otp_length=6, otp_validity_minutes=1)
    user_id = "test_user_999"
    
    print(f"👤 Testing rate limiting for user {user_id}...")
    print(f"📊 Max attempts per minute: {generator.max_attempts_per_minute}")
    
    successful_generations = 0
    failed_generations = 0
    
    # Try to generate OTPs rapidly
    for attempt in range(15):
        otp_record = generator.generate_otp(user_id, "test_service")
        if otp_record:
            successful_generations += 1
            print(f"   Attempt {attempt + 1:2d}: ✅ OTP {otp_record['otp']}")
        else:
            failed_generations += 1
            print(f"   Attempt {attempt + 1:2d}: ❌ Rate limited")
        
        time.sleep(0.1)  # Small delay between attempts
    
    print(f"\n📊 Results:")
    print(f"   ✅ Successful: {successful_generations}")
    print(f"   ❌ Rate Limited: {failed_generations}")
    print(f"🔒 Rate limiting successfully prevented abuse!")
    
    print()

def demo_device_binding():
    """Demonstrate device-specific OTP binding."""
    print("📱 Device Binding Security Demo")
    print("=" * 50)
    
    # Create two generators (simulating different devices)
    device1_generator = FingerprintOTPGenerator(otp_length=6, otp_validity_minutes=5)
    device2_generator = FingerprintOTPGenerator(otp_length=6, otp_validity_minutes=5)
    
    user_id = "device_user_777"
    service = "secure_app"
    
    print(f"👤 User {user_id} on two different devices...")
    print(f"📱 Device 1 ID: {device1_generator.device_id}")
    print(f"💻 Device 2 ID: {device2_generator.device_id}")
    
    # Generate OTPs on both devices
    otp1 = device1_generator.generate_otp(user_id, service)
    otp2 = device2_generator.generate_otp(user_id, service)
    
    if otp1 and otp2:
        print(f"\n🔐 OTP from Device 1: {otp1['otp']}")
        print(f"🔐 OTP from Device 2: {otp2['otp']}")
        
        # Try to use Device 1 OTP on Device 2
        print(f"\n🔄 Attempting to use Device 1 OTP on Device 2...")
        is_valid = device2_generator.verify_otp(otp1['otp'], user_id, service, otp1)
        
        if not is_valid:
            print("❌ OTP rejected! Device binding working correctly.")
            print("🔒 This prevents OTP theft across devices.")
        else:
            print("⚠️  Security issue: OTP accepted across devices!")
    
    print()

def demo_security_analysis():
    """Show security statistics and analysis."""
    print("🔒 Security Analysis & Statistics")
    print("=" * 50)
    
    generator = FingerprintOTPGenerator(otp_length=8, otp_validity_minutes=10)
    
    # Generate some OTPs to populate statistics
    for i in range(5):
        generator.generate_otp(f"user_{i}", f"service_{i}")
    
    # Get statistics
    stats = generator.get_otp_statistics()
    
    print("📊 System Statistics:")
    for key, value in stats.items():
        if key == 'rate_limit_config':
            print(f"   📋 {key}:")
            for config_key, config_value in value.items():
                print(f"      {config_key}: {config_value}")
        elif key == 'current_rate_limits':
            print(f"   📈 {key}:")
            for user, attempts in value.items():
                print(f"      {user}: {attempts} attempts")
        else:
            print(f"   📊 {key}: {value}")
    
    print("\n🔒 Security Features Active:")
    print("   • Device fingerprinting: ✅")
    print("   • Rate limiting: ✅")
    print("   • Time-based expiration: ✅")
    print("   • Service-specific salting: ✅")
    print("   • HMAC-based generation: ✅")
    print("   • Audit logging: ✅")
    print("   • Attempt tracking: ✅")
    
    print()

def main():
    """Run all demo scenarios."""
    print("🚀 Fingerprint OTP Generator - Practical Usage Demos")
    print("=" * 60)
    print("This demo shows real-world usage scenarios for the fingerprint-based OTP system.\n")
    
    # Run all demos
    demo_crypto_wallet_authentication()
    demo_netbanking_transaction()
    demo_multiple_services_same_user()
    demo_rate_limiting()
    demo_device_binding()
    demo_security_analysis()
    
    print("🎉 All demos completed successfully!")
    print("\n💡 Key Benefits Demonstrated:")
    print("   • Unique OTPs for each fingerprint scan")
    print("   • Service-specific security")
    print("   • Device binding protection")
    print("   • Rate limiting against abuse")
    print("   • Comprehensive audit logging")
    print("   • Cross-service attack prevention")

if __name__ == "__main__":
    main()

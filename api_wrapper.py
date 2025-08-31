#!/usr/bin/env python3
"""
API Wrapper for Fingerprint OTP Generator
Provides a clean interface for integrating the fingerprint OTP system into applications.
"""

import json
import time
from datetime import datetime
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, asdict

# Import the main generator
exec(open("Fingerprint - OTP Generation.py").read())

@dataclass
class OTPRequest:
    """Data class for OTP generation requests."""
    user_id: str
    service_name: str
    otp_length: Optional[int] = None
    validity_minutes: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class OTPResponse:
    """Data class for OTP generation responses."""
    success: bool
    otp: Optional[str] = None
    expires_at: Optional[str] = None
    device_id: Optional[str] = None
    user_id: Optional[str] = None
    service_name: Optional[str] = None
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class OTPVerificationRequest:
    """Data class for OTP verification requests."""
    otp: str
    user_id: str
    service_name: str
    otp_record: Dict[str, Any]

@dataclass
class OTPVerificationResponse:
    """Data class for OTP verification responses."""
    success: bool
    is_valid: bool
    user_id: Optional[str] = None
    service_name: Optional[str] = None
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class FingerprintOTPAPI:
    """
    High-level API wrapper for the Fingerprint OTP Generator.
    Provides clean interfaces for common operations.
    """
    
    def __init__(self, default_otp_length: int = 6, default_validity_minutes: int = 5):
        """
        Initialize the API wrapper.
        
        Args:
            default_otp_length: Default OTP length if not specified in requests
            default_validity_minutes: Default OTP validity in minutes if not specified
        """
        self.default_otp_length = default_otp_length
        self.default_validity_minutes = default_validity_minutes
        self.generator = FingerprintOTPGenerator(
            otp_length=default_otp_length,
            otp_validity_minutes=default_validity_minutes
        )
        
        # Store OTP records for verification (in production, use a database)
        self.otp_storage = {}
        
    def generate_otp(self, request: OTPRequest) -> OTPResponse:
        """
        Generate an OTP based on the request.
        
        Args:
            request: OTPRequest object containing generation parameters
            
        Returns:
            OTPResponse object with the result
        """
        try:
            # Use request parameters or defaults
            otp_length = request.otp_length or self.default_otp_length
            validity_minutes = request.validity_minutes or self.default_validity_minutes
            
            # Update generator settings if different from current
            if otp_length != self.generator.otp_length or validity_minutes != self.generator.otp_validity_minutes:
                self.generator = FingerprintOTPGenerator(otp_length, validity_minutes)
            
            # Generate OTP
            otp_record = self.generator.generate_otp(request.user_id, request.service_name)
            
            if otp_record:
                # Store OTP record for verification
                storage_key = f"{request.user_id}_{request.service_name}_{otp_record['otp']}"
                self.otp_storage[storage_key] = otp_record
                
                # Create response
                response = OTPResponse(
                    success=True,
                    otp=otp_record['otp'],
                    expires_at=otp_record['expires_at'],
                    device_id=otp_record['device_id'],
                    user_id=otp_record['user_id'],
                    service_name=otp_record['service_name'],
                    metadata={
                        'fingerprint_quality': otp_record['fingerprint_quality'],
                        'generated_at': otp_record['generated_at'],
                        'max_attempts': otp_record['max_attempts']
                    }
                )
                
                return response
            else:
                return OTPResponse(
                    success=False,
                    error_message="Failed to generate OTP. Rate limit may have been exceeded."
                )
                
        except Exception as e:
            return OTPResponse(
                success=False,
                error_message=f"Error generating OTP: {str(e)}"
            )
    
    def verify_otp(self, request: OTPVerificationRequest) -> OTPVerificationResponse:
        """
        Verify an OTP.
        
        Args:
            request: OTPVerificationRequest object containing verification parameters
            
        Returns:
            OTPVerificationResponse object with the result
        """
        try:
            # Find stored OTP record
            storage_key = f"{request.user_id}_{request.service_name}_{request.otp}"
            stored_record = self.otp_storage.get(storage_key)
            
            if not stored_record:
                return OTPVerificationResponse(
                    success=False,
                    is_valid=False,
                    user_id=request.user_id,
                    service_name=request.service_name,
                    error_message="OTP record not found or expired"
                )
            
            # Verify OTP
            is_valid = self.generator.verify_otp(
                request.otp,
                request.user_id,
                request.service_name,
                stored_record
            )
            
            if is_valid:
                # Remove used OTP from storage
                if storage_key in self.otp_storage:
                    del self.otp_storage[storage_key]
            
            return OTPVerificationResponse(
                success=True,
                is_valid=is_valid,
                user_id=request.user_id,
                service_name=request.service_name,
                metadata={
                    'verification_time': datetime.now().isoformat(),
                    'device_id': stored_record.get('device_id')
                }
            )
            
        except Exception as e:
            return OTPVerificationResponse(
                success=False,
                is_valid=False,
                user_id=request.user_id,
                service_name=request.service_name,
                error_message=f"Error verifying OTP: {str(e)}"
            )
    
    def get_user_otps(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Get all active OTPs for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of active OTP records for the user
        """
        user_otps = []
        current_time = datetime.now()
        
        for storage_key, otp_record in self.otp_storage.items():
            if otp_record['user_id'] == user_id and otp_record['is_valid']:
                # Check if OTP is expired
                expiration_time = datetime.fromisoformat(otp_record['expires_at'])
                if current_time <= expiration_time:
                    user_otps.append({
                        'otp': otp_record['otp'],
                        'service_name': otp_record['service_name'],
                        'expires_at': otp_record['expires_at'],
                        'attempts_used': otp_record['attempts_used'],
                        'max_attempts': otp_record['max_attempts']
                    })
        
        return user_otps
    
    def revoke_user_otps(self, user_id: str, service_name: Optional[str] = None) -> int:
        """
        Revoke all OTPs for a user (optionally for a specific service).
        
        Args:
            user_id: User identifier
            service_name: Optional service name to revoke only specific service OTPs
            
        Returns:
            Number of OTPs revoked
        """
        revoked_count = 0
        
        for storage_key, otp_record in list(self.otp_storage.items()):
            if otp_record['user_id'] == user_id:
                if service_name is None or otp_record['service_name'] == service_name:
                    if storage_key in self.otp_storage:
                        del self.otp_storage[storage_key]
                        revoked_count += 1
        
        return revoked_count
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics about the OTP system.
        
        Returns:
            Dictionary containing system statistics
        """
        # Get generator statistics
        generator_stats = self.generator.get_otp_statistics()
        
        # Add API-specific statistics
        api_stats = {
            'total_stored_otps': len(self.otp_storage),
            'active_otps': len([otp for otp in self.otp_storage.values() if otp['is_valid']]),
            'expired_otps': len([otp for otp in self.otp_storage.values() if not otp['is_valid']]),
            'storage_keys': list(self.otp_storage.keys())
        }
        
        # Combine statistics
        combined_stats = {**generator_stats, **api_stats}
        return combined_stats
    
    def cleanup_expired_otps(self) -> int:
        """
        Clean up expired OTPs from storage.
        
        Returns:
            Number of expired OTPs removed
        """
        current_time = datetime.now()
        removed_count = 0
        
        for storage_key, otp_record in list(self.otp_storage.items()):
            expiration_time = datetime.fromisoformat(otp_record['expires_at'])
            if current_time > expiration_time:
                if storage_key in self.otp_storage:
                    del self.otp_storage[storage_key]
                    removed_count += 1
        
        return removed_count


# Example usage and testing
def main():
    """Demonstrate the API wrapper functionality."""
    print("🚀 Fingerprint OTP Generator - API Wrapper Demo")
    print("=" * 55)
    
    # Initialize API
    api = FingerprintOTPAPI(default_otp_length=6, default_validity_minutes=3)
    
    # Example 1: Generate OTP for crypto wallet
    print("\n1️⃣  Generating OTP for Crypto Wallet...")
    crypto_request = OTPRequest(
        user_id="crypto_user_123",
        service_name="crypto_wallet",
        otp_length=8,
        validity_minutes=5
    )
    
    crypto_response = api.generate_otp(crypto_request)
    if crypto_response.success:
        print(f"✅ OTP Generated: {crypto_response.otp}")
        print(f"⏰ Expires: {crypto_response.expires_at}")
        print(f"📱 Device: {crypto_response.device_id}")
        
        # Verify the OTP
        print("\n🔑 Verifying OTP...")
        verify_request = OTPVerificationRequest(
            otp=crypto_response.otp,
            user_id=crypto_response.user_id,
            service_name=crypto_response.service_name,
            otp_record=api.otp_storage[f"{crypto_response.user_id}_{crypto_response.service_name}_{crypto_response.otp}"]
        )
        
        verify_response = api.verify_otp(verify_request)
        if verify_response.success and verify_response.is_valid:
            print("🎉 OTP verified successfully!")
        else:
            print(f"❌ OTP verification failed: {verify_response.error_message}")
    
    # Example 2: Generate OTPs for multiple services
    print("\n2️⃣  Generating OTPs for Multiple Services...")
    services = ["netbanking", "email", "vpn"]
    
    for service in services:
        request = OTPRequest(user_id="multi_user_456", service_name=service)
        response = api.generate_otp(request)
        
        if response.success:
            print(f"   {service:12} → {response.otp}")
        else:
            print(f"   {service:12} → Failed: {response.error_message}")
    
    # Example 3: Get user statistics
    print("\n3️⃣  User OTP Statistics...")
    user_otps = api.get_user_otps("multi_user_456")
    print(f"📊 Active OTPs for multi_user_456: {len(user_otps)}")
    
    for otp_info in user_otps:
        print(f"   {otp_info['service_name']:12} → {otp_info['otp']} (expires: {otp_info['expires_at']})")
    
    # Example 4: System statistics
    print("\n4️⃣  System Statistics...")
    stats = api.get_statistics()
    print(f"📊 Total stored OTPs: {stats['total_stored_otps']}")
    print(f"📊 Active OTPs: {stats['active_otps']}")
    print(f"📊 Device ID: {stats['device_id']}")
    
    # Example 5: Cleanup expired OTPs
    print("\n5️⃣  Cleaning up expired OTPs...")
    removed_count = api.cleanup_expired_otps()
    print(f"🧹 Removed {removed_count} expired OTPs")
    
    print("\n🎉 API Wrapper Demo Completed!")
    print("\n💡 Key Features Demonstrated:")
    print("   • Clean API interface for OTP generation")
    print("   • Structured request/response objects")
    print("   • Automatic OTP storage and management")
    print("   • User-specific OTP tracking")
    print("   • System statistics and monitoring")
    print("   • Automatic cleanup of expired OTPs")


if __name__ == "__main__":
    main()

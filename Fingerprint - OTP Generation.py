#!/usr/bin/env python3
"""
Fingerprint-Based OTP Generator
A secure OTP generation system using fingerprint biometrics for enhanced authentication.
"""

import hashlib
import time
import uuid
import platform
import subprocess
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple
import secrets
import hmac

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('fingerprint_otp.log'),
        logging.StreamHandler()
    ]
)

class FingerprintOTPGenerator:
    """
    Generates unique OTPs using fingerprint biometrics with enhanced security features.
    """
    
    def __init__(self, otp_length: int = 6, otp_validity_minutes: int = 5):
        """
        Initialize the Fingerprint OTP Generator.
        
        Args:
            otp_length: Length of the generated OTP (default: 6)
            otp_validity_minutes: OTP validity period in minutes (default: 5)
        """
        self.otp_length = otp_length
        self.otp_validity_minutes = otp_validity_minutes
        self.device_id = self._get_device_identifier()
        self.rate_limit_attempts = {}
        self.max_attempts_per_minute = 10
        
        logging.info(f"Fingerprint OTP Generator initialized for device: {self.device_id}")
    
    def _get_device_identifier(self) -> str:
        """
        Generate a unique device identifier using hardware and system information.
        
        Returns:
            Unique device identifier string
        """
        try:
            # Get system information
            system_info = {
                'platform': platform.system(),
                'platform_version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'node': platform.node()
            }
            
            # Get MAC address (if available)
            try:
                if platform.system() == "Darwin":  # macOS
                    result = subprocess.run(['ifconfig', 'en0'], capture_output=True, text=True)
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if 'ether' in line:
                                mac = line.split('ether')[1].strip()
                                system_info['mac_address'] = mac
                                break
                elif platform.system() == "Linux":
                    result = subprocess.run(['cat', '/sys/class/net/eth0/address'], capture_output=True, text=True)
                    if result.returncode == 0:
                        system_info['mac_address'] = result.stdout.strip()
            except:
                pass
            
            # Create hash of system info
            device_hash = hashlib.sha256(json.dumps(system_info, sort_keys=True).encode()).hexdigest()
            return device_hash[:16]
            
        except Exception as e:
            logging.warning(f"Could not get device identifier: {e}")
            return str(uuid.uuid4())[:16]
    
    def _get_fingerprint_data(self) -> Dict[str, any]:
        """
        Simulate fingerprint data collection. In a real implementation, this would
        interface with fingerprint hardware to get actual biometric data.
        
        Returns:
            Dictionary containing fingerprint data and metadata
        """
        # Simulate fingerprint sensor data
        current_time = time.time()
        
        # In a real implementation, you would:
        # 1. Capture fingerprint image
        # 2. Extract minutiae points
        # 3. Calculate quality metrics
        # 4. Get sensor-specific data
        
        fingerprint_data = {
            'timestamp': current_time,
            'quality_score': secrets.randbelow(100) + 1,  # 1-100 quality score
            'minutiae_count': secrets.randbelow(50) + 20,  # 20-70 minutiae points
            'sensor_id': f"sensor_{secrets.randbelow(1000):03d}",
            'capture_attempts': secrets.randbelow(3) + 1,
            'finger_position': secrets.choice(['thumb', 'index', 'middle', 'ring', 'little']),
            'pressure_level': secrets.randbelow(100) + 1,
            'moisture_level': secrets.randbelow(100) + 1
        }
        
        logging.info(f"Fingerprint data captured: {fingerprint_data}")
        return fingerprint_data
    
    def _check_rate_limit(self, user_id: str) -> bool:
        """
        Check if user has exceeded rate limiting for OTP generation.
        
        Args:
            user_id: Unique identifier for the user
            
        Returns:
            True if rate limit not exceeded, False otherwise
        """
        current_time = time.time()
        minute_ago = current_time - 60
        
        # Clean old attempts
        if user_id in self.rate_limit_attempts:
            self.rate_limit_attempts[user_id] = [
                attempt_time for attempt_time in self.rate_limit_attempts[user_id]
                if attempt_time > minute_ago
            ]
        else:
            self.rate_limit_attempts[user_id] = []
        
        # Check if limit exceeded
        if len(self.rate_limit_attempts[user_id]) >= self.max_attempts_per_minute:
            logging.warning(f"Rate limit exceeded for user: {user_id}")
            return False
        
        # Add current attempt
        self.rate_limit_attempts[user_id].append(current_time)
        return True
    
    def _generate_entropy_string(self, fingerprint_data: Dict[str, any]) -> str:
        """
        Generate entropy string from fingerprint data and system information.
        
        Args:
            fingerprint_data: Fingerprint sensor data
            
        Returns:
            Entropy string for OTP generation
        """
        # Combine multiple entropy sources
        entropy_sources = [
            str(fingerprint_data['timestamp']),
            str(fingerprint_data['quality_score']),
            str(fingerprint_data['minutiae_count']),
            fingerprint_data['sensor_id'],
            str(fingerprint_data['capture_attempts']),
            fingerprint_data['finger_position'],
            str(fingerprint_data['pressure_level']),
            str(fingerprint_data['moisture_level']),
            self.device_id,
            str(int(time.time() * 1000)),  # Millisecond precision
            str(uuid.uuid4()),  # Random UUID
            str(secrets.randbelow(1000000))  # Random number
        ]
        
        # Combine all sources
        combined_entropy = "|".join(entropy_sources)
        
        # Create hash for consistent length
        entropy_hash = hashlib.sha256(combined_entropy.encode()).hexdigest()
        
        return entropy_hash
    
    def generate_otp(self, user_id: str, service_name: str = "default") -> Optional[Dict[str, any]]:
        """
        Generate a unique OTP using fingerprint biometrics.
        
        Args:
            user_id: Unique identifier for the user
            service_name: Name of the service requesting OTP (e.g., "crypto_wallet", "netbanking")
            
        Returns:
            Dictionary containing OTP and metadata, or None if generation fails
        """
        try:
            # Check rate limiting
            if not self._check_rate_limit(user_id):
                return None
            
            # Get fingerprint data
            fingerprint_data = self._get_fingerprint_data()
            
            # Generate entropy string
            entropy_string = self._generate_entropy_string(fingerprint_data)
            
            # Create service-specific salt
            service_salt = hashlib.sha256(f"{service_name}_{self.device_id}".encode()).hexdigest()
            
            # Generate OTP using HMAC
            hmac_obj = hmac.new(
                service_salt.encode(),
                entropy_string.encode(),
                hashlib.sha256
            )
            
            # Convert HMAC to numeric OTP
            hmac_hex = hmac_obj.hexdigest()
            hmac_int = int(hmac_hex, 16)
            
            # Generate OTP of specified length
            otp = str(hmac_int % (10 ** self.otp_length)).zfill(self.otp_length)
            
            # Calculate expiration time
            expiration_time = datetime.now() + timedelta(minutes=self.otp_validity_minutes)
            
            # Create OTP record
            otp_record = {
                'otp': otp,
                'user_id': user_id,
                'service_name': service_name,
                'generated_at': datetime.now().isoformat(),
                'expires_at': expiration_time.isoformat(),
                'device_id': self.device_id,
                'fingerprint_quality': fingerprint_data['quality_score'],
                'is_valid': True,
                'attempts_used': 0,
                'max_attempts': 3
            }
            
            # Log OTP generation
            logging.info(f"OTP generated for user {user_id} on service {service_name}")
            
            return otp_record
            
        except Exception as e:
            logging.error(f"Error generating OTP: {e}")
            return None
    
    def verify_otp(self, otp: str, user_id: str, service_name: str, otp_record: Dict[str, any]) -> bool:
        """
        Verify if the provided OTP is valid.
        
        Args:
            otp: OTP to verify
            user_id: User ID
            service_name: Service name
            otp_record: Original OTP record
            
        Returns:
            True if OTP is valid, False otherwise
        """
        try:
            # Check if OTP is expired
            expiration_time = datetime.fromisoformat(otp_record['expires_at'])
            if datetime.now() > expiration_time:
                logging.warning(f"OTP expired for user {user_id}")
                return False
            
            # Check if OTP is already used
            if not otp_record['is_valid']:
                logging.warning(f"OTP already used for user {user_id}")
                return False
            
            # Check if max attempts exceeded
            if otp_record['attempts_used'] >= otp_record['max_attempts']:
                logging.warning(f"Max attempts exceeded for user {user_id}")
                return False
            
            # Verify OTP
            if otp == otp_record['otp']:
                # Mark OTP as used
                otp_record['is_valid'] = False
                logging.info(f"OTP verified successfully for user {user_id}")
                return True
            else:
                # Increment attempt counter
                otp_record['attempts_used'] += 1
                logging.warning(f"Invalid OTP attempt for user {user_id}. Attempts: {otp_record['attempts_used']}")
                return False
                
        except Exception as e:
            logging.error(f"Error verifying OTP: {e}")
            return False
    
    def get_otp_statistics(self) -> Dict[str, any]:
        """
        Get statistics about OTP generation and usage.
        
        Returns:
            Dictionary containing statistics
        """
        return {
            'device_id': self.device_id,
            'total_otps_generated': len([k for k, v in self.rate_limit_attempts.items()]),
            'rate_limit_config': {
                'max_attempts_per_minute': self.max_attempts_per_minute,
                'otp_length': self.otp_length,
                'otp_validity_minutes': self.otp_validity_minutes
            },
            'current_rate_limits': {
                user_id: len(attempts) for user_id, attempts in self.rate_limit_attempts.items()
            }
        }


def main():
    """
    Main function to demonstrate the Fingerprint OTP Generator.
    """
    print("🔐 Fingerprint-Based OTP Generator")
    print("=" * 50)
    
    # Initialize the generator
    generator = FingerprintOTPGenerator(otp_length=8, otp_validity_minutes=3)
    
    # Example usage for different services
    services = ["crypto_wallet", "netbanking", "email_login", "vpn_access"]
    user_id = "user_12345"
    
    print(f"\n📱 Device ID: {generator.device_id}")
    print(f"👤 User ID: {user_id}")
    print(f"⏱️  OTP Validity: {generator.otp_validity_minutes} minutes")
    print(f"🔢 OTP Length: {generator.otp_length} digits")
    
    print("\n🚀 Generating OTPs for different services...")
    
    for service in services:
        print(f"\n--- {service.upper()} ---")
        
        # Generate OTP
        otp_record = generator.generate_otp(user_id, service)
        if otp_record:
            print(f"✅ OTP Generated: {otp_record['otp']}")
            print(f"   Expires: {otp_record['expires_at']}")
            print(f"   Quality Score: {otp_record['fingerprint_quality']}")
            
            # Simulate verification
            is_valid = generator.verify_otp(otp_record['otp'], user_id, service, otp_record)
            print(f"   Verification: {'✅ Valid' if is_valid else '❌ Invalid'}")
        else:
            print("❌ Failed to generate OTP")
    
    # Show statistics
    print("\n📊 Statistics:")
    stats = generator.get_otp_statistics()
    for key, value in stats.items():
        if key != 'current_rate_limits':
            print(f"   {key}: {value}")
    
    print("\n🔒 Security Features Implemented:")
    print("   • Unique OTP for each fingerprint scan")
    print("   • Device-specific binding")
    print("   • Rate limiting protection")
    print("   • Time-based expiration")
    print("   • Multiple entropy sources")
    print("   • HMAC-based generation")
    print("   • Audit logging")
    print("   • Attempt tracking")


if __name__ == "__main__":
    main()

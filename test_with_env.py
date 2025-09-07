#!/usr/bin/env python3
"""
Test with environment variables set
"""

import os
import sys

# Set test environment variables
os.environ['SECRET_KEY'] = 'test-secret-key-123'
os.environ['JWT_SECRET_KEY'] = 'test-jwt-secret-456'
os.environ['DATABASE_URL'] = 'https://x8ki-letl-twmt.n7.xano.io/api:9gHb5-cO'

# Now import and test
from app import app, db, User, google

def test_with_credentials():
    """Test with Google OAuth credentials"""
    print("🔍 Testing with Google OAuth credentials...")
    
    # Set test Google OAuth credentials
    os.environ['GOOGLE_CLIENT_ID'] = 'test-client-id-123'
    os.environ['GOOGLE_CLIENT_SECRET'] = 'test-client-secret-456'
    
    # Re-import to get updated config
    import importlib
    import app
    importlib.reload(app)
    
    if app.google:
        print("✅ Google OAuth client initialized with test credentials")
        return True
    else:
        print("❌ Google OAuth still not configured")
        return False

def test_google_login_route():
    """Test Google login route with credentials"""
    print("\n🔍 Testing Google Login Route...")
    
    with app.test_client() as client:
        response = client.get('/api/auth/google/login?account_type=patient')
        print(f"   - Status Code: {response.status_code}")
        
        if response.status_code == 302:
            print("   - ✅ Redirect to Google OAuth (this is good!)")
            print(f"   - Location: {response.headers.get('Location', 'Not set')}")
            return True
        elif response.status_code == 400:
            print("   - ❌ Still getting 400 error")
            return False
        else:
            print(f"   - ⚠️  Unexpected status code: {response.status_code}")
            return False

if __name__ == '__main__':
    print("🚀 Testing with Environment Variables")
    print("=" * 50)
    
    # Test with credentials
    oauth_ok = test_with_credentials()
    
    if oauth_ok:
        # Test route
        route_ok = test_google_login_route()
        
        if route_ok:
            print("\n🎉 Google OAuth is working correctly!")
            print("\n📝 To fix your Google OAuth:")
            print("1. Get real Google OAuth credentials from Google Cloud Console")
            print("2. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables")
            print("3. Configure redirect URI in Google Console: https://YOUR-DOMAIN/api/auth/google/callback")
        else:
            print("\n❌ Route test failed")
    else:
        print("\n❌ OAuth configuration failed")

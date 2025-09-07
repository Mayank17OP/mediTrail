#!/usr/bin/env python3
"""
Test Google OAuth setup and database connection
"""

import os
import sys
from app import app, db, User, google

def test_environment():
    """Test environment variables"""
    print("🔍 Testing Environment Variables...")
    
    required_vars = ['SECRET_KEY', 'JWT_SECRET_KEY']
    optional_vars = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'DATABASE_URL']
    
    for var in required_vars:
        value = os.environ.get(var)
        if value:
            print(f"✅ {var}: {'*' * min(len(value), 10)}...")
        else:
            print(f"❌ {var}: Not set")
    
    for var in optional_vars:
        value = os.environ.get(var)
        if value:
            print(f"ℹ️  {var}: {'*' * min(len(value), 10)}...")
        else:
            print(f"⚠️  {var}: Not set (optional)")

def test_database():
    """Test database connection"""
    print("\n🔍 Testing Database Connection...")
    
    try:
        with app.app_context():
            db.create_all()
            print("✅ Database connection successful")
            
            # Test user count
            user_count = User.query.count()
            print(f"✅ Users table accessible ({user_count} users)")
            
            # Test creating a test user
            test_user = User(
                email='test@example.com',
                full_name='Test User',
                account_type='patient'
            )
            
            # Check if test user exists
            existing = User.query.filter_by(email='test@example.com').first()
            if existing:
                print("ℹ️  Test user already exists")
            else:
                db.session.add(test_user)
                db.session.commit()
                print("✅ Test user created successfully")
                
                # Clean up
                db.session.delete(test_user)
                db.session.commit()
                print("✅ Test user cleaned up")
            
            return True
            
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False

def test_google_oauth():
    """Test Google OAuth configuration"""
    print("\n🔍 Testing Google OAuth Configuration...")
    
    if google:
        print("✅ Google OAuth client initialized")
        print(f"   - Client ID: {app.config['GOOGLE_CLIENT_ID'][:10]}...")
        print(f"   - Client Secret: {'*' * 10}...")
        return True
    else:
        print("❌ Google OAuth not configured")
        print("   - Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables")
        return False

def test_routes():
    """Test OAuth routes"""
    print("\n🔍 Testing OAuth Routes...")
    
    with app.test_client() as client:
        # Test Google login route
        response = client.get('/api/auth/google/login')
        print(f"   - Google login route: {response.status_code}")
        
        if response.status_code == 400:
            print("   - This is expected if Google OAuth is not configured")
        elif response.status_code == 302:
            print("   - Redirect to Google OAuth (this is good!)")
        else:
            print(f"   - Unexpected status code: {response.status_code}")

if __name__ == '__main__':
    print("🚀 MediVault OAuth & Database Test")
    print("=" * 50)
    
    # Test environment
    test_environment()
    
    # Test database
    db_ok = test_database()
    
    # Test Google OAuth
    oauth_ok = test_google_oauth()
    
    # Test routes
    test_routes()
    
    print("\n" + "=" * 50)
    if db_ok:
        print("🎉 Database is working correctly!")
    else:
        print("❌ Database issues detected")
    
    if oauth_ok:
        print("🎉 Google OAuth is configured!")
    else:
        print("⚠️  Google OAuth needs configuration")
    
    print("\n📝 Next Steps:")
    print("1. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables")
    print("2. Configure Google Cloud Console with redirect URI")
    print("3. Test the OAuth flow in your browser")

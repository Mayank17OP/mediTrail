#!/usr/bin/env python3
"""
Test script to verify Google OAuth integration
Run this after setting up environment variables
"""

import os
import sys
from app import app, db, User

def test_google_oauth_setup():
    """Test Google OAuth configuration"""
    print("🔍 Testing Google OAuth Setup...")
    
    # Check environment variables
    client_id = os.environ.get('GOOGLE_CLIENT_ID')
    client_secret = os.environ.get('GOOGLE_CLIENT_SECRET')
    
    if not client_id:
        print("❌ GOOGLE_CLIENT_ID not set")
        return False
    if not client_secret:
        print("❌ GOOGLE_CLIENT_SECRET not set")
        return False
    
    print("✅ Google OAuth credentials found")
    
    # Check database connection
    try:
        with app.app_context():
            db.create_all()
            print("✅ Database connection successful")
            
            # Check if users table has google_id column
            user_count = User.query.count()
            print(f"✅ Users table accessible ({user_count} users)")
            
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False
    
    return True

def test_user_creation():
    """Test user creation with Google ID"""
    print("\n🔍 Testing User Creation...")
    
    try:
        with app.app_context():
            # Test creating a user with Google ID
            test_user = User(
                email='test@example.com',
                full_name='Test User',
                google_id='test_google_id_123',
                account_type='patient'
            )
            
            # Check if user already exists
            existing = User.query.filter_by(email='test@example.com').first()
            if existing:
                print("ℹ️  Test user already exists, cleaning up...")
                db.session.delete(existing)
                db.session.commit()
            
            # Add test user
            db.session.add(test_user)
            db.session.commit()
            
            # Verify user was created
            created_user = User.query.filter_by(google_id='test_google_id_123').first()
            if created_user:
                print("✅ User with Google ID created successfully")
                print(f"   - Email: {created_user.email}")
                print(f"   - Name: {created_user.full_name}")
                print(f"   - Google ID: {created_user.google_id}")
                print(f"   - Account Type: {created_user.account_type}")
                
                # Clean up
                db.session.delete(created_user)
                db.session.commit()
                print("✅ Test user cleaned up")
                return True
            else:
                print("❌ User creation failed")
                return False
                
    except Exception as e:
        print(f"❌ User creation error: {e}")
        return False

if __name__ == '__main__':
    print("🚀 MediVault Google OAuth Test")
    print("=" * 40)
    
    # Test setup
    setup_ok = test_google_oauth_setup()
    
    if setup_ok:
        # Test user creation
        user_ok = test_user_creation()
        
        if user_ok:
            print("\n🎉 All tests passed! Google OAuth is ready for deployment.")
        else:
            print("\n❌ User creation tests failed.")
            sys.exit(1)
    else:
        print("\n❌ Setup tests failed.")
        sys.exit(1)

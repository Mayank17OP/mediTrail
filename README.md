## Deployment on Render

Environment variables required:

- SECRET_KEY
- JWT_SECRET_KEY
- GOOGLE_CLIENT_ID
- GOOGLE_CLIENT_SECRET
- DATABASE_URL (Render Postgres)

Start command (Procfile):

```
web: gunicorn app:app --bind 0.0.0.0:${PORT}
```

Google OAuth configuration (very important):

1. **Google Cloud Console Setup**:
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing one
   - Enable Google+ API
   - Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client IDs"
   - Set Application type to "Web application"
   - Add authorized redirect URI: `https://YOUR-RENDER-DOMAIN/api/auth/google/callback`
   - Copy the Client ID and Client Secret

2. **Render Environment Variables**:
   - Set `GOOGLE_CLIENT_ID` to your Google Client ID
   - Set `GOOGLE_CLIENT_SECRET` to your Google Client Secret
   - Ensure the app domain matches the origin users load the login page from

3. **Testing**:
   - Test both patient and doctor account types
   - Verify users are created in database with Google ID
   - Check that existing users can link their Google account

# medivault2
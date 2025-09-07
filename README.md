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

- Authorized redirect URI in Google Console must be: `https://YOUR-RENDER-DOMAIN/api/auth/google/callback`
- Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` env vars in Render
- Ensure the app domain matches the origin users load the login page from

# medivault2
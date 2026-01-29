### API Endpoints

- All endpoints require:

    ```
    X-Service-Key : <SERVICE_API_KEY>
    ```

### POST /auth/login

- Used when backend already auth the user

    ```
    {
        "user_id": "123",
        "device_id": "device-uuid",
        "remember_me": true / false
    }
    ```

- Response:

    ```
    {
        "access_token": "...",
        "refresh_token": "..."
    }
    ```

### POST /auth/oauth/login

- Used when Central-Auth validates OAuth (Google)

    ```
    {
        "provider": "google",
        "id_token": "...",
        "device_id": "device-uuid",
        "remember_me": true
    }
    ```

- Callback

### POST /auth/refresh

- Return new access token

    ```
    {
        "refresh_token": "..."
    }
    ```

### POST /auth/logout & /auth/loguout-all

- Revokes this device session & all session for this user

### POST /auth/verify

- Validates AccessToken and confirms Redis session still exists

    ```
    {
        "user_id": "123",
        "device_id": "...",
        "exp": 1700000000
    }
    ```

# Notes

- Tokens are never stored in localStorage and plaintext (hash only in DB and HttpOnly cookie)

- Redis Controls active sessions


## Google login

```
Frontend
 ↓
Kratos - Authentication(인증)
 ↓
Google
 ↓
Kratos
 ↓
Frontend
 ↓
Central-auth - BFF (세션 + Token브릿지)
 ↓
Hydra - Authorization (토큰 발급)
```

## Login with ID/PW

```
Email/Password
↓
Kratos Login Flow
↓
Kratos Session
↓
BFF Login
↓
__session
↓
whoami
```

Browser
↓
__session
↓
BFFAPIBridgeMiddleware
↓
Bearer Token 주입
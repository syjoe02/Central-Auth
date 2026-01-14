# Go
- install dependencies
```
go get github.com/gin-gonic/gin
go mod tidy

go get github.com/redis/go-redis/v9
go get github.com/golang-jwt/jwt/v5
google.golang.org/api/idtoken
go get github.com/google/uuid
go get github.com/jackc/pgx/v5/pgxpool@v5.8.0

```

- run server

```
go run ./cmd/server/main.go
```

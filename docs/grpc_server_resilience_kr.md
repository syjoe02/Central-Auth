# PR 리뷰 문서: Central-Auth — gRPC 서버, 복원력 계층, Kafka 소비자, GitOps CI/CD

**날짜:** 2026-04-06
**브랜치:** `dev` → `main`
**저장소:** `syjoe02/Central-Auth`
**커밋:** `2c200e9` (feat), `[security-fix]` (fix)

---

## 1. 개요

이번 PR은 Central-Auth Go BFF 서비스에 세 가지 주요 아키텍처 변경을 도입합니다.

1. **gRPC 서버 (포트 50051) 추가** — 기존 HTTP API와 병행하여 Django 및 다른 내부 서비스들이 gRPC를 통해 인증 서비스를 호출할 수 있도록 합니다. gRPC 서버에는 8개의 인터셉터 체인이 포함됩니다.

2. **복원력 계층 (Resilience Layer) 추가** — Redis 장애 시 자동으로 PostgreSQL 블랙리스트와 인메모리 L1 캐시로 폴백하는 서킷브레이커 기반 레이어를 추가합니다.

3. **Kafka 소비자 및 DB 마이그레이션** — `auth.session.created` 이벤트를 소비하여 `device_sessions` 테이블에 비동기로 저장하고, `golang-migrate`를 이용한 자동 DB 마이그레이션을 도입합니다.

4. **GitOps CI/CD 파이프라인** — GitHub Actions를 통해 GHCR에 Docker 이미지를 푸시하고, `yq`로 Infra 저장소의 `values.yaml`을 자동 업데이트합니다.

### 주요 변경 파일 수

| 구분 | 수량 |
|------|------|
| 신규 파일 | 47개 |
| 수정 파일 | 19개 |
| 총 삽입 | +5,257줄 |
| 총 삭제 | -118줄 |

---

## 2. 보안 검토 결과

**검토 도구:** `security-reviewer` 에이전트
**최종 결과: ✅ PASS (조건부)**

### 발견 사항

| 심각도 | 항목 | 파일 | 조치 |
|--------|------|------|------|
| CRITICAL | 없음 | — | — |
| HIGH | 인-프로세스 속도 제한기 — 수평 확장 시 무력화 | `internal/grpc/interceptor/token_bucket.go` | 코드 주석으로 Redis 기반 구현 필요성 명시. 단일 인스턴스 운영 중에는 허용 가능. 수평 확장 전 Redis-backed rate limiter로 교체 필요 |
| MEDIUM | `ServiceAuth` 인터셉터가 키 길이를 검증하지 않음 | `internal/grpc/interceptor/service_auth.go` | `config/server.go`에서 최소 길이 검증 이미 수행 중. 인터셉터 단독 사용 시 잠재적 위험. 허용 수준으로 판단 |
| INFO | `latest` 태그가 `main` 브랜치 푸시마다 무조건 적용 | `.github/workflows/deploy.yml` | GitOps 방식에서 `latest`는 참고용. 실제 배포는 SHA 태그 사용 |
| INFO | 멱등성 키가 호출자 ID로 스코핑되지 않음 | `internal/grpc/interceptor/idempotency.go` | 내부 신뢰 네트워크 환경에서 낮은 위험. 향후 개선 권고 |

### 긍정적 보안 구현 사항

- `service_auth.go`: `subtle.ConstantTimeCompare`로 타이밍 공격 방지 ✓
- `blacklist_pg_repository.go`: pgx 위치 매개변수(`$1`, `$2`) 사용 — SQL 인젝션 없음 ✓
- `database/migrate.go`: 마이그레이터 오류에서 DSN 비밀번호 자동 제거 ✓
- CI/CD: `INFRA_REPO_PAT`이 로그에 노출되지 않음 ✓
- SQL 마이그레이션 파일: 순수 DDL만 포함, 하드코딩된 시크릿 없음 ✓

---

## 3. 테스트 및 커버리지

**검증 방법:** `go test -race -coverprofile=coverage.out ./...`

| 패키지 | 결과 | 커버리지 |
|--------|------|----------|
| `internal/blacklist` | ✅ PASS | — |
| `internal/http/handler` | ✅ PASS | — |
| `internal/hydra` | ✅ PASS | — |
| `internal/kafka` | ✅ PASS | — |
| `internal/repository` | ✅ PASS | — |
| `internal/requestid` | ✅ PASS | — |
| `internal/resilience` | ✅ PASS | — |
| `internal/service` | ✅ PASS | 63.4% |
| `internal/session` | ✅ PASS | 79.3% |
| **전체 합계** | **9 PASS / 0 FAIL** | **21.9% (전체)** |

> **참고:** 전체 커버리지 21.9%는 gRPC 서버, 인터셉터, DB 마이그레이터 등 통합 테스트가 필요한 컴포넌트가 포함되어 낮게 측정됩니다. 핵심 비즈니스 로직 패키지(`service`, `session`)는 60-79% 수준을 달성했습니다.

**빌드 검증:** `go build ./...` — ✅ 오류 없음
**경쟁 감지:** `-race` 플래그 — ✅ 데이터 레이스 없음

---

## 4. 주요 코드 변경점

### 4-1. gRPC 서버 (`internal/grpc/`)

**아키텍처:** 기존 HTTP Gin 서버와 병행하여 `:50051` 포트에 gRPC 서버를 구동합니다.

**신규 파일:**

| 파일 | 역할 |
|------|------|
| `server/auth_server.go` | `auth.v1.AuthService` gRPC 구현체. `Signup`, `Login` (3가지 방법), `Refresh`, `Logout`, `LogoutAll`, `Verify`, `GoogleLogin` 메서드 제공 |
| `server/errors.go` | 도메인 오류를 gRPC 상태 코드로 변환 |
| `interceptor/service_auth.go` | `x-service-key` 메타데이터를 상수 시간 비교로 검증 |
| `interceptor/rate_limit.go` | 토큰 버킷 기반 RPS 제한 |
| `interceptor/idempotency.go` | Redis를 이용한 멱등성 키 캐싱 |
| `interceptor/kafka_access_log.go` | 모든 gRPC 요청을 Kafka `access-logs` 토픽에 기록 |
| `interceptor/prometheus.go` | 요청 카운터, 지연 시간 히스토그램 메트릭 |
| `interceptor/request_id.go` | `x-request-id` 메타데이터를 컨텍스트에 주입 |
| `interceptor/logging.go` | 메서드명, 요청 ID, 상태 코드, 지연시간 구조적 로깅 |
| `interceptor/recovery.go` | 패닉을 `codes.Internal`로 변환 (스택 트레이스 미노출) |

### 4-2. 복원력 계층 (`internal/resilience/`)

**설계 원칙:** Redis가 다운되더라도 인증 서비스가 중단 없이 동작해야 합니다.

| 컴포넌트 | 동작 방식 |
|----------|----------|
| `circuit_breaker.go` | 3상태(Closed/Open/HalfOpen) 서킷브레이커. 지터 지수 백오프 포함 |
| `resilient_redis_repo.go` | Redis 장애 시 인메모리 캐시(L1)로 폴백 |
| `resilient_blacklist.go` | Redis 서킷 오픈 시 PostgreSQL 블랙리스트로 폴백 |
| `resilient_session_store.go` | 세션 저장소 Redis 실패 시 폴백 |
| `idempotency_guard.go` | Redis 기반 멱등성 가드 (gRPC 중복 요청 방지) |
| `metrics.go` | 서킷 상태 변경 Prometheus 메트릭 |

### 4-3. Kafka 소비자 및 DB 마이그레이션

| 컴포넌트 | 역할 |
|----------|------|
| `kafka/consumer.go` | `auth.session.created` 이벤트 소비 → `device_sessions` 테이블 upsert |
| `kafka/startup.go` | 서버 시작/종료 시 소비자 생명주기 관리 |
| `database/migrate.go` | `golang-migrate` 내장 SQL 마이그레이션 실행기 |
| `migrations/000001~000004` | `blacklisted_sessions`, `device_sessions` 테이블 및 인덱스 4개 |

### 4-4. CI/CD 파이프라인 (`.github/workflows/deploy.yml`)

```
Push/Tag → go test -race → docker buildx push → checkout Infra → yq patch values.yaml → git push
```

- **이미지 태그 전략:** `main` 브랜치 → `sha-<8자리 SHA>` / `v*` 태그 → 태그명 그대로
- **시크릿 처리:** `GITHUB_TOKEN`(GHCR 푸시), `INFRA_REPO_PAT`(Infra 저장소 업데이트)

---

## 5. 참조 링크

- 변경 파일 목록: `git show --stat dev`
- 관련 PR: [Hackonomics-2026 gRPC 어댑터](../../../Hackonomics-2026/docs/review/PR_20260406_grpc_adapter_django.md)
- 관련 PR: [Hackonomics-Infra GitOps](../../../Hackonomics-Infra/docs/review/PR_20260406_gitops_helm_argocd.md)

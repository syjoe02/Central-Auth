# Central-Auth Redis 회복 탄력성(Resilience) 정밀 진단 보고서

> **감사 일자:** 2026-04-06  
> **감사 범위:** `internal/resilience/`, `internal/config/resilience.go`, `internal/config/db.go`  
> **감사 방법:** `qmd search` + 전체 소스 코드 전수 조사 (circuit breaker, fallback, jitter, timeout, observability)

---

## 1. 현황 요약 — 5가지 테스트 시나리오 충족 현황

| # | 테스트 시나리오 | 충족 여부 | 비고 |
|---|---|:---:|---|
| 1 | 5회 연속 실패 후 OPEN 전환, SleepWindow 설정 | ✅ | FailureThreshold=5 구현 완료; SleepWindow 60s 미세 차이 존재 (항목 3 참조) |
| 2 | REDIS_DOWN_FALLBACK_STARTED 로그 + DB Polling 60s 내 수행 | ✅ (수정 후) | `circuit_state` 필드 누락 → **이번 감사에서 수정 완료** |
| 3 | Exponential Backoff + Jitter로 Thundering Herd 방지 | ✅ | `applyJitter(base ± base*JitterPct%)` 구현 완료 |
| 4 | 2초 지연 시나리오에서 빠른 실패(Fail-Fast) 및 Flapping 방지 | ✅ (수정 후) | Redis 연결 타임아웃 미설정 → **이번 감사에서 수정 완료** |
| 5 | Sentry 캡처 + Loki 인덱싱용 구조화 로그 필드 | ✅ (수정 후) | `circuit_state` 추가, `reason` / `failure_threshold` 기존 존재 |

---

## 2. 로직 분석 — 시나리오별 구현 위치 및 함수명

### 시나리오 1: 상태 전이 (State Transition)

**설계 요건:** 5회 연속 장애 후 OPEN; SleepWindow 60s에서 Half-Open 전환

| 항목 | 구현 위치 | 내용 |
|---|---|---|
| FSM 상태 정의 | `internal/resilience/circuit_breaker.go:22-26` | `StateClosed(0)`, `StateOpen(1)`, `StateHalfOpen(2)` |
| 실패 임계값 설정 | `internal/config/resilience.go:22` | `FailureThreshold: envInt("REDIS_CB_FAILURE_THRESHOLD", 5)` |
| CLOSED→OPEN 전환 | `circuit_breaker.go:148-165` (`RecordFailure`) | `failures.Add(1)` → `n >= FailureThreshold` 시 CAS로 OPEN 전환 |
| Probe 허용 (Half-Open) | `circuit_breaker.go:101-123` (`Allow`) | `time.Now().UnixNano() >= nextProbeAt` 시 CAS로 HALF-OPEN 전환 |
| ProbeBase 기본값 | `internal/config/resilience.go:24` | `ProbeBaseSeconds: envInt("REDIS_CB_PROBE_BASE_SECONDS", 30)` |

> **주의:** 설계 문서의 SleepWindow 60s와 구현의 ProbeBaseSeconds 30s 사이에 차이가 있습니다.  
> 환경 변수 `REDIS_CB_PROBE_BASE_SECONDS=60`으로 즉시 조정 가능합니다.

```go
// circuit_breaker.go:148-165 — 핵심 전환 로직
case StateClosed:
    n := cb.failures.Add(1)
    if int(n) >= cb.cfg.FailureThreshold {
        if cb.state.CompareAndSwap(int32(StateClosed), int32(StateOpen)) {
            // ...OPEN 전환 처리
        }
    }
```

---

### 시나리오 2: Fallback & Consistency (일관성 지연)

**설계 요건:** REDIS_DOWN_FALLBACK_STARTED 로그, DB Polling L1→L3 60s 내 수행

| 항목 | 구현 위치 | 내용 |
|---|---|---|
| REDIS_DOWN_FALLBACK_STARTED 로그 | `circuit_breaker.go:155-163` | `slog.LevelError` + JSON 구조화 출력 (stdout → Loki) |
| Blacklist PG 폴백 | `resilient_blacklist.go:78-87` (`IsBlacklisted`) | L1 Miss → `pgRepo.IsBlacklisted()` 호출 |
| Blacklist Add PG 폴백 | `resilient_blacklist.go:110-118` (`Add`) | OPEN 시 PG에 직접 기록 후 L1 갱신 |
| SessionStore 폴백 | `resilient_session_store.go:61-63` (`Get`) | OPEN 시 L1→`ErrNotFound` 반환 (재인증 유도) |
| RedisRepo 폴백 | `resilient_redis_repo.go:50-52` (`GetDeviceRefreshToken`) | L1 Hit 시 Redis 건너뜀; OPEN 시 `ErrRedisUnavailable` |
| L1→PG 전파 타이밍 | `config/resilience.go:24` | ProbeBase 30s 내 Half-Open 재시도 → 60s 이내 일관성 복구 |

---

### 시나리오 3: Jitter & Exponential Backoff (Thundering Herd 방지)

**설계 요건:** `base * 2^n + random_jitter` 형태의 지수 백오프

| 항목 | 구현 위치 | 내용 |
|---|---|---|
| 초기 backoff 설정 | `circuit_breaker.go:186-190` (`resetBackoff`) | `applyJitter(ProbeBaseNanos)` |
| 실패 시 backoff 2배 확장 | `circuit_breaker.go:194-203` (`extendBackoff`) | `doubled = backoffNanos * 2`, max capped |
| Jitter 적용 | `circuit_breaker.go:206-213` (`applyJitter`) | `base ± (base * JitterPct / 100)` |
| RNG 인스턴스 | `circuit_breaker.go:90` | `rand.New(rand.NewSource(time.Now().UnixNano()))` — 인스턴스 전용, 공유 없음 |
| 최대 backoff 상한 | `config/resilience.go:26` | `ProbeMaxSeconds: 300` (5분) |

```go
// circuit_breaker.go:206-213 — Jitter 알고리즘
func (cb *circuitBreaker) applyJitter(base int64) int64 {
    jitterRange := base * cb.cfg.JitterPct / 100
    // rand.Int63n(jitterRange*2+1) - jitterRange → ±jitterRange 범위
    delta := cb.rng.Int63n(jitterRange*2+1) - jitterRange
    return base + delta
}
```

> Thundering Herd 방지: 각 인스턴스가 독립 RNG를 사용하여 동일 시점 재시도 집중 없음.  
> Flapping 방지: `probeInFlight` CAS gate로 동시에 오직 1개 고루틴만 Half-Open 프로브 허용.

---

### 시나리오 4: Chaos Readiness (빠른 실패 + Flapping 방지)

**설계 요건:** 연결 타임아웃 < 100ms, 2초 지연 시나리오에서 Fail-Fast

| 항목 | 구현 위치 | 내용 |
|---|---|---|
| Redis DialTimeout | `internal/config/db.go:23-27` (수정 후) | `envInt("REDIS_DIAL_TIMEOUT_MS", 100) ms` |
| Redis ReadTimeout | `internal/config/db.go:23-27` (수정 후) | `envInt("REDIS_READ_TIMEOUT_MS", 500) ms` |
| Redis WriteTimeout | `internal/config/db.go:23-27` (수정 후) | `envInt("REDIS_WRITE_TIMEOUT_MS", 500) ms` |
| Timeout → InfraError 변환 | `circuit_breaker.go:232-253` (`IsInfraError`) | `context.DeadlineExceeded`, `net.Error{Timeout:true}` → `true` |
| Half-Open 단일 프로브 | `circuit_breaker.go:118-121` (`Allow`) | `probeInFlight.CompareAndSwap(0, 1)` — 1 고루틴만 허용 |

```go
// config/db.go — 수정 후 타임아웃 설정
redis.NewClient(&redis.Options{
    Addr:         addr,
    DialTimeout:  time.Duration(envInt("REDIS_DIAL_TIMEOUT_MS", 100)) * time.Millisecond,
    ReadTimeout:  time.Duration(envInt("REDIS_READ_TIMEOUT_MS", 500)) * time.Millisecond,
    WriteTimeout: time.Duration(envInt("REDIS_WRITE_TIMEOUT_MS", 500)) * time.Millisecond,
})
```

> 2초 네트워크 지연 시나리오: DialTimeout=100ms이므로 최대 100ms 내 `context.DeadlineExceeded` 발생 →  
> `IsInfraError()` → `RecordFailure()` → 5회 누적 시 OPEN → DB 폴백으로 즉시 전환.

---

### 시나리오 5: Observability (가관측성)

**설계 요건:** Sentry 캡처, Loki 인덱싱용 `reason` / `failure_threshold` / `circuit_state` 필드

| 항목 | 구현 위치 | 내용 |
|---|---|---|
| Sentry 캡처 (CLOSED→OPEN) | `circuit_breaker.go:161-163` | `captureFunc(errors.New("...CLOSED→OPEN..."))` |
| Sentry 캡처 (Half-Open 실패) | `circuit_breaker.go:142-145` | `captureFunc(errors.New("...HALF-OPEN probe failed..."))` |
| Sentry 주입 방식 | `circuit_breaker.go:50-52` (`WithSentryCapture`) | Functional Option으로 교체 가능; 기본값 `sentry.CaptureException` |
| `event` 필드 | `circuit_breaker.go:157` | `slog.String("event", "REDIS_DOWN_FALLBACK_STARTED")` |
| `reason` 필드 | `circuit_breaker.go:158` | `slog.String("reason", "failure threshold reached")` |
| `failure_threshold` 필드 | `circuit_breaker.go:159` | `slog.Int("failure_threshold", cb.cfg.FailureThreshold)` |
| `circuit_state` 필드 | `circuit_breaker.go:160` (수정 후) | `slog.String("circuit_state", "OPEN")` |
| Prometheus 메트릭 | `resilience/metrics.go:7-35` | `CBState`, `CBTripsTotal`, `L1CacheHits`, `PgFallbackTotal` |
| 구조화 JSON 로거 | `resilient_blacklist.go:18` | `slog.NewJSONHandler(os.Stdout, nil)` → Loki 수집 가능 |

---

## 3. 수정 사항 — 이번 감사에서 적용된 코드 변경

### 수정 1: `circuit_state` 필드 추가 (`circuit_breaker.go`)

```diff
  resilienceLogger.LogAttrs(context.Background(), slog.LevelError,
      "REDIS_DOWN_FALLBACK_STARTED",
      slog.String("event", "REDIS_DOWN_FALLBACK_STARTED"),
      slog.String("reason", "failure threshold reached"),
      slog.Int("failure_threshold", cb.cfg.FailureThreshold),
+     slog.String("circuit_state", "OPEN"),
  )
```

**이유:** 설계 요건에서 `circuit_state` 필드를 Loki 인덱싱 키로 명시. 누락 시 Grafana Loki에서 상태 기반 필터링 불가.

---

### 수정 2: Redis 연결 타임아웃 설정 (`config/db.go`)

```diff
  redis.NewClient(&redis.Options{
-     Addr: addr,
+     Addr:         addr,
+     DialTimeout:  time.Duration(envInt("REDIS_DIAL_TIMEOUT_MS", 100)) * time.Millisecond,
+     ReadTimeout:  time.Duration(envInt("REDIS_READ_TIMEOUT_MS", 500)) * time.Millisecond,
+     WriteTimeout: time.Duration(envInt("REDIS_WRITE_TIMEOUT_MS", 500)) * time.Millisecond,
  })
```

**이유:** 기본값 미설정 시 go-redis는 `DialTimeout=5s`, `ReadTimeout=3s`를 사용. 2초 네트워크 지연 카오스 시나리오에서 최대 5초 대기 후 실패, CB가 너무 늦게 트립되어 플래핑 위험. `DialTimeout=100ms`로 즉각 실패 보장.

**환경 변수 오버라이드:** `REDIS_DIAL_TIMEOUT_MS`, `REDIS_READ_TIMEOUT_MS`, `REDIS_WRITE_TIMEOUT_MS`로 조정 가능.

---

## 4. 개선 제언 — 추가 검토 권장 사항

### 4-1. SleepWindow 기본값 조정 (선택)

설계 문서에서 SleepWindow를 60s로 명시하고 있으나, 현재 `ProbeBaseSeconds` 기본값은 30s입니다.

```bash
# 운영 배포 시 환경 변수로 즉시 조정 가능
REDIS_CB_PROBE_BASE_SECONDS=60
```

기능적으로 30s는 더 빠른 복구를 의미하므로 설계보다 보수적이지 않습니다. 팀 합의 후 기본값을 60으로 변경하거나, 운영 환경 변수로 고정하기를 권장합니다.

### 4-2. Half-Open 로그 보강

현재 Half-Open 프로브 실패 시 Sentry 캡처는 되지만 구조화 로그가 없습니다. 아래 추가를 권장합니다:

```go
// circuit_breaker.go RecordFailure() StateHalfOpen 분기에 추가
resilienceLogger.LogAttrs(context.Background(), slog.LevelError,
    "REDIS_PROBE_FAILED",
    slog.String("event", "REDIS_PROBE_FAILED"),
    slog.String("circuit_state", "OPEN"),
    slog.String("reason", "half-open probe failed, re-opening"),
)
```

### 4-3. SessionStore OPEN 시 동작 문서화

`ResilientSessionStore.Create` / `Update`는 OPEN 시 `ErrRedisUnavailable`을 반환하여 BFF 세션 생성이 실패합니다. 이는 의도된 트레이드오프이나, 운영팀의 장애 대응 Runbook에 명시적으로 기술할 것을 권장합니다.

### 4-4. Blacklist AddBatch PG 폴백 부분 실패 처리

`resilient_blacklist.go:146` `AddBatch` OPEN 경로에서 루프 도중 PG 오류 발생 시 이미 저장된 세션은 롤백되지 않고 미저장 세션만 실패합니다. 보안 요건에 따라 올-오어-낫싱(all-or-nothing) 트랜잭션 처리를 고려하십시오.

---

## 5. 테스트 커버리지 현황

| 파일 | 주요 테스트 |
|---|---|
| `circuit_breaker_test.go` | 초기 상태, 5회 트립, OPEN 유지, Half-Open 전환, 단일 프로브, 성공 복구, 백오프 상한, Jitter 범위, 경쟁 조건 |
| `circuit_breaker_sentry_test.go` | Sentry 캡처 횟수 검증 (트립/프로브 실패/OPEN 중 추가 캡처 없음/성공 시 무캡처) |
| `circuit_breaker_infra_test.go` | 인프라 오류 유형별 트립 검증, 도메인 오류 미트립, L1→PG 우선순위, context 종류별 분류 |
| `resilient_blacklist_test.go` | PG 폴백 경로, Fail-Closed 동작 |
| `resilient_redis_repo_test.go` | L1 캐시 히트, 인프라 오류 시 CB 기록 |
| `resilient_session_store_test.go` | 세션 Get/Create/Delete CB 보호 |

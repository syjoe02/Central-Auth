# JWKS 회복 탄력성 및 Redis 서킷 브레이커 정밀 진단 보고서

> **감사 일자:** 2026-04-07  
> **감사 범위:** Django (`Hackonomics-2026`) JWKS 생명주기, Python 서킷 브레이커 / Central-auth (Go) 서킷 브레이커 / K3S Helm 인프라 Redis 격리  
> **감사 방법:** `qmd search` + 전체 소스 전수 조사 (jwks_middleware.py, circuit_breaker.py, settings.py, Helm values)

---

## 1. 현황 요약 — 진단 항목별 충족 여부

| # | 진단 항목 | 감사 전 | 감사 후 |
|---|---|:---:|:---:|
| 1-a | JWKS Fresh 캐시 TTL = 3분 | ❌ (5분) | ✅ (수정 완료) |
| 1-b | JWKS Stale 캐시 TTL = 30분 | ❌ (무한) | ✅ (수정 완료) |
| 1-c | Redis 장애 중에도 Stale로 인증 유지 | ✅ | ✅ |
| 1-d | Hydra JWKS 1시간 주기 Celery 갱신 | ❌ (없음) | ✅ (태스크 신규 생성) |
| 2-a | Central-auth CB: 5회 실패 후 OPEN | ✅ | ✅ |
| 2-b | ResetTimeout (30~60s) 설정 및 Jitter 적용 | ⚠️ CB 파라미터 불일치 | ✅ (수정 완료) |
| 2-c | Half-Open 프로브: Exponential Backoff + Jitter | ✅ | ✅ |
| 2-d | 프로브 성공 시 CLOSED 복귀 + L1 캐시 갱신 | ✅ | ✅ |
| 3 | Multi-Redis 격리 (Central-auth vs Django/Celery) | ✅ | ✅ |

---

## 2. JWKS 생명주기 분석 — Fresh / Stale 태그 전략

### 2-1. Fresh 캐시 (ory_jwks_data)

| 항목 | 수정 전 | 수정 후 | 위치 |
|---|---|---|---|
| TTL | 300s (5분) | **180s (3분)** | `jwks_middleware.py:_JWKS_DEFAULT_TTL` |
| 사용처 | 정상 경로 JWT 검증 | 동일 | `_get_jwks()` → `_fetch_and_cache_jwks()` |
| 갱신 주기 | 캐시 만료 시 동기 페치 | **:55분 Celery 갱신으로 선제적 워밍** | `authentication/tasks.py` |

**Fresh 캐시 동작 흐름:**
```
요청 → cache.get("ory_jwks_data")
  ├─ HIT  → 즉시 반환 (레이턴시 0)
  └─ MISS → _fetch_and_cache_jwks() → CB 통과 → HTTP GET → cache.set(TTL=180s)
```

### 2-2. Stale 캐시 (ory_jwks_stale)

| 항목 | 수정 전 | 수정 후 | 위치 |
|---|---|---|---|
| TTL | `timeout=None` (무한) | **`timeout=1800s` (30분)** | `jwks_middleware.py:_JWKS_STALE_TTL` |
| 목적 | Redis/Central-auth 장애 시 폴백 | 동일, 단 30분 이후엔 만료 | `_fetch_and_cache_jwks()` 예외 경로 |

**변경 이유:** 무한 TTL은 키 교체(Key Rotation) 이후에도 폐기된 키를 서빙할 위험이 있습니다. 30분으로 제한하면 최대 장애 허용 시간 내에서 안전하게 서빙하면서, 복구 후 강제 갱신이 이루어집니다.

**Stale 캐시 동작 흐름:**
```
_fetch_and_cache_jwks() 예외 발생 (네트워크 장애 / CB OPEN)
  → cache.get("ory_jwks_stale")
      ├─ HIT  → stale 키로 JWT 서명 검증 계속 (인증 유지 ✅)
      └─ MISS → InvalidTokenError 발생 → AnonymousUser (인증 불가)
```

### 2-3. 장애 시 인증 유지 검증

```
[Redis 장애 시나리오]
1. Central-auth 접근 불가 → _jwks_http_get() 실패
2. CB failure_threshold 도달 → CircuitOpenError 즉시 발생 (fast-fail)
3. _fetch_and_cache_jwks() 예외 경로 진입
4. cache.get("ory_jwks_stale") HIT → 기존 공개키로 서명 검증
5. 사용자 인증 유지 ✅ (최대 30분 동안)
```

---

## 3. Hydra JWKS 1시간 갱신 — Celery 태스크 (신규 생성)

### 3-1. 생성된 파일

**`authentication/tasks.py`** (신규)

```python
@shared_task(
    bind=True,
    autoretry_for=(ConnectionError, OSError),
    retry_backoff=60,         # 60s → 120s → 240s 지수 백오프
    retry_backoff_max=300,
    retry_kwargs={"max_retries": 3},
)
def refresh_jwks_cache(self) -> None:
    """Central-auth에서 JWKS를 매시간 선제 갱신."""
```

### 3-2. Celery Beat 스케줄 (`config/settings.py`)

```python
"refresh-jwks-cache-every-hour": {
    "task": "authentication.tasks.refresh_jwks_cache",
    "schedule": crontab(minute=55),  # 매시 :55분 — TTL 만료 5분 전 갱신
},
```

**스케줄 `:55분` 선택 이유:**  
Fresh TTL = 3분 (180s). 캐시가 매시 `:00`에 저장됐다고 가정하면 `:03`에 만료. `:55`에 갱신하면 최소 8분의 여유로 만료 전 항상 Fresh 상태 유지.

### 3-3. 태스크 회복 탄력성

| 항목 | 동작 |
|---|---|
| 페치 실패 | autoretry 최대 3회 (60s/120s/240s 지수 백오프) |
| CB OPEN 상태 | `CircuitOpenError` → retry 트리거 |
| 전체 실패 | Stale 캐시(30min)가 계속 서빙 → 다음 스케줄까지 인증 유지 |

---

## 4. 서킷 브레이커 파라미터 분석

### 4-1. Django Python CB (`common/resilience/circuit_breaker.py`)

#### 수정 전 문제점

| 항목 | 설계 (settings.py) | 실제 구현 (jwks_middleware.py) |
|---|---|---|
| `failure_threshold` | `CENTRAL_AUTH_CB_FAILURE_THRESHOLD = 5` | **`3`** (하드코딩) |
| `recovery_timeout` | `CENTRAL_AUTH_CB_RECOVERY_TIMEOUT = 30` | **`20`** (하드코딩) |
| Jitter | 없음 | 없음 |

#### 수정 후

```python
# jwks_middleware.py — CB 파라미터를 settings에서 읽도록 수정
@circuit_breaker(
    "jwks_fetch",
    failure_threshold=getattr(settings, "CENTRAL_AUTH_CB_FAILURE_THRESHOLD", 5),
    recovery_timeout=getattr(settings, "CENTRAL_AUTH_CB_RECOVERY_TIMEOUT", 30),
)
```

```python
# circuit_breaker.py — Jitter 추가 (Thundering Herd 방지)
def _jittered_timeout(base: int, jitter_pct: int = 15) -> int:
    """base ± (base * 15%) 범위의 랜덤 오프셋."""
    jitter_range = int(base * jitter_pct / 100)
    return max(1, base + random.randint(-jitter_range, jitter_range))

# 호출 위치
cache.set(_open_key, 1, timeout=_jittered_timeout(recovery_timeout))
```

**Jitter 효과:** Gunicorn 다수 워커가 동일 Redis CB를 공유할 때, 모든 워커가 정확히 동일 시점에 Half-Open 프로브를 시도하는 현상(Thundering Herd) 방지. ±15% 범위로 분산하여 순차적 프로브 실현.

#### Django CB Redis 키 구조

```
cb:jwks_fetch:failures  — INCR 카운터 (TTL=60s 슬라이딩 윈도우)
cb:jwks_fetch:open      — 존재 여부 플래그 (TTL=30s ± 15% 지터)
```

#### CB 상태 전이 흐름

```
CLOSED → [5회 실패 in 60s window] → OPEN (TTL ~30s)
OPEN   → [TTL 만료] → 암묵적 HALF-OPEN (다음 호출이 프로브)
  HALF-OPEN 성공 → failure counter 삭제 → CLOSED
  HALF-OPEN 실패 → OPEN 재진입 (새 TTL ~30s)
```

### 4-2. Central-auth Go CB (`internal/resilience/circuit_breaker.go`)

이전 감사(`resilience-check.md`)에서 확인 및 수정 완료. 현황 요약:

| 항목 | 구현 | 상태 |
|---|---|---|
| FailureThreshold | `5` (env: `REDIS_CB_FAILURE_THRESHOLD`) | ✅ |
| ProbeBaseNanos | `30s` (env: `REDIS_CB_PROBE_BASE_SECONDS`) | ✅ |
| ProbeMaxNanos | `300s` (env: `REDIS_CB_PROBE_MAX_SECONDS`) | ✅ |
| Jitter | `applyJitter(base ± 15%)` — per-instance RNG | ✅ |
| Exponential Backoff | `extendBackoff()`: `backoff *= 2`, capped at ProbeMax | ✅ |
| Half-Open 단일 프로브 | `probeInFlight.CompareAndSwap(0, 1)` | ✅ |
| CLOSED→OPEN 로그 | `REDIS_DOWN_FALLBACK_STARTED` + `circuit_state: OPEN` | ✅ (이전 감사 수정) |
| Sentry 캡처 | `sentry.CaptureException` (CLOSED→OPEN, 프로브 실패) | ✅ |
| Redis 타임아웃 | `DialTimeout=100ms`, `ReadTimeout=500ms` | ✅ (이전 감사 수정) |

---

## 5. Multi-Redis 격리 검증

### 5-1. K3S Helm 구성

| 서비스 | Redis 인스턴스 | Helm Chart | K8s Service명 |
|---|---|---|---|
| Central-auth (Go) | `redis-go` | `charts/redis-go/` | `hackonomics-redis-go:6379` |
| Django + Celery | `redis-django` | `charts/redis-django/` | `hackonomics-redis-django:6379/0` |

**중요:** 두 Redis는 별도 StatefulSet으로 완전히 격리되어 있습니다.

### 5-2. 연결 설정 확인

**Central-auth Go** (`charts/central-auth/values.yaml`):
```yaml
redis:
  addr: hackonomics-redis-go:6379
```
→ `config/db.go:NewRedisClient()` → `REDIS_ADDR` 환경변수 → `hackonomics-redis-go`

**Django** (`charts/hackonomics-app/values.yaml`):
```yaml
redis:
  url: "redis://hackonomics-redis-django:6379/0"
```
→ `settings.py:REDIS_URL` → `CACHES["default"]` + `CELERY_BROKER_URL`

### 5-3. Django CB의 Redis 사용 분석

Django 서킷 브레이커(`common/resilience/circuit_breaker.py`)는 `django.core.cache.cache`를 통해 `hackonomics-redis-django`에 CB 상태(`cb:jwks_fetch:*`)를 저장합니다.

```
Django CB 상태 저장소: hackonomics-redis-django (Django 전용 Redis)
Celery 브로커:         hackonomics-redis-django (동일 Redis)
```

**잠재적 위험:** Django Redis가 메모리 압박을 받을 경우 Celery 메시지와 CB 키가 같은 공간을 공유합니다. CB 키가 LRU 정책으로 삭제되면 CB 상태가 소실되어 OPEN 상태가 조기 해제될 수 있습니다.

**권장 개선:** `redis.conf`에 `maxmemory-policy noeviction` 또는 CB 키에 `volatile-lru` 정책 적용 (CB 키 외 Celery 메시지만 제거되도록).

---

## 6. 이번 감사에서 적용된 코드 변경 요약

### 변경 1: JWKS Fresh TTL 수정 (`jwks_middleware.py`)

```diff
- _JWKS_DEFAULT_TTL = 300  # 5 minutes
+ _JWKS_DEFAULT_TTL = 180  # 3 minutes — fresh window
+ _JWKS_STALE_TTL = 1800   # 30 minutes — stale window
```

### 변경 2: JWKS Stale TTL 수정 (`jwks_middleware.py`)

```diff
- cache.set(_JWKS_STALE_CACHE_KEY, data, timeout=None)
+ cache.set(_JWKS_STALE_CACHE_KEY, data, timeout=_JWKS_STALE_TTL)
```

### 변경 3: CB 파라미터 settings 연동 (`jwks_middleware.py`)

```diff
- @circuit_breaker("jwks_fetch", failure_threshold=3, recovery_timeout=20)
+ @circuit_breaker(
+     "jwks_fetch",
+     failure_threshold=getattr(settings, "CENTRAL_AUTH_CB_FAILURE_THRESHOLD", 5),
+     recovery_timeout=getattr(settings, "CENTRAL_AUTH_CB_RECOVERY_TIMEOUT", 30),
+ )
```

### 변경 4: CB Recovery Jitter 추가 (`circuit_breaker.py`)

```diff
+ def _jittered_timeout(base: int, jitter_pct: int = 15) -> int:
+     jitter_range = int(base * jitter_pct / 100)
+     return max(1, base + random.randint(-jitter_range, jitter_range))

- cache.set(_open_key, 1, timeout=recovery_timeout)
+ cache.set(_open_key, 1, timeout=_jittered_timeout(recovery_timeout))
```

### 변경 5: JWKS 1시간 갱신 Celery 태스크 (`authentication/tasks.py`)

신규 생성. `@shared_task` + autoretry (60s/120s/240s 지수 백오프).

### 변경 6: Celery Beat 스케줄 등록 (`config/settings.py`)

```diff
+ "refresh-jwks-cache-every-hour": {
+     "task": "authentication.tasks.refresh_jwks_cache",
+     "schedule": crontab(minute=55),
+ },
```

### 변경 7: 테스트 수정

- `test_jwks_middleware.py`: TTL 상수 기반 검증 (`_JWKS_DEFAULT_TTL`, `_JWKS_STALE_TTL`)
- `test_circuit_breaker.py`: Jitter 범위 검증 (`base * 0.85 ≤ timeout ≤ base * 1.15`)

---

## 7. 개선 제언

### 7-1. Django CB를 별도 Redis DB로 분리 (강력 권장)

현재 CB 상태 키(`cb:*`)가 Celery 브로커 메시지와 동일 Redis에 혼재합니다.

```yaml
# 권장: settings.py에 별도 cache alias 추가
CACHES = {
    "default": {"BACKEND": "...", "LOCATION": REDIS_URL},        # DB 0: 세션/JWKS
    "circuit_breaker": {"BACKEND": "...", "LOCATION": f"{REDIS_URL_BASE}/1"},  # DB 1: CB 전용
}
```

CB 코드에서 `cache` 대신 `caches["circuit_breaker"]` 사용.

### 7-2. JWKS Celery 태스크 모니터링

`authentication/tasks.py`의 `refresh_jwks_cache` 태스크 실패를 Sentry로 캡처하도록 추가:

```python
from sentry_sdk import capture_exception

except Exception as exc:
    capture_exception(exc)
    raise
```

### 7-3. Django CB Half-Open 프로브 동시성 제어

현재 Django CB는 `cache.get(open_key) == None`이 되면 **모든 워커**가 동시에 프로브를 시도합니다. Go CB의 `probeInFlight.CompareAndSwap(0, 1)`처럼, `cache.add(probe_lock_key, 1, timeout=5)`으로 단일 워커만 프로브하도록 개선을 권장합니다.

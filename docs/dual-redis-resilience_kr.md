# Dual-Redis 회복 탄력성 정밀 진단 보고서

> **감사 일자:** 2026-04-07  
> **감사 범위:** Django-Redis (뉴스 수집) + Auth-Redis (Central-auth Go) + Celery-Beat 스케줄러  
> **변경 파일:** `common/resilience/circuit_breaker.py`, `news/adapters/orm/models.py`, `news/migrations/0005_newstaskstate.py`, `news/application/services/business_news_service.py`, `news/tasks.py`, `config/celery_scheduler.py`, `config/settings.py`, `requirements.txt`

---

## 1. 현황 요약 — 감사 전/후 충족 여부

| # | 진단 항목 | 감사 전 | 감사 후 |
|---|---|:---:|:---:|
| 1-a | Celery-Beat Redis 5회 실패 → OPEN | ❌ | ✅ `ResilientBeatScheduler` |
| 1-b | OPEN 시 DatabaseScheduler 폴백 | ❌ | ✅ 항상 DB 스케줄링 |
| 1-c | HALF-OPEN: Exp Backoff + Jitter 프로브 | ❌ | ✅ `_BrokerCircuitBreaker` |
| 1-d | Beat 회복 후 자동 CLOSED 복귀 + Sentry | ❌ | ✅ |
| 2-a | Worker DB 레벨 `select_for_update()` 락 | ❌ (Redis 락만 존재) | ✅ `NewsTaskState` |
| 2-b | Gemini API 전 `last_run_at` Double-Check | ❌ | ✅ `_acquire_lock_and_check()` |
| 2-c | 중복 태스크 Abort (Gemini 호출 차단) | ❌ | ✅ |
| 3-a | Auth-Redis CB Sentry 알람 | ✅ (Go) | ✅ |
| 3-b | Django CB Sentry 알람 (OPEN 시) | ❌ | ✅ `_sentry_capture_circuit_open()` |
| 3-c | Sentry 구조화 컨텍스트 (`circuit_state`, `failed_service`, `task_id`) | ❌ | ✅ |

---

## 2. 장애 대응 워크플로우 — Redis → DB 폴백

### 2-1. 아키텍처 개요

```
┌─────────────────────────────────────────────────────────────┐
│                    K3S Cluster                               │
│                                                              │
│  ┌──────────────────┐        ┌─────────────────────────┐   │
│  │  Central-auth    │        │   Django / Celery       │   │
│  │  (Go Service)    │        │                         │   │
│  │                  │        │  ResilientBeatScheduler │   │
│  │  Go CircuitBreaker──────→ │  ┌─────────────────┐   │   │
│  │  (atomic, lock-free)│     │  │ BrokerCircuitBkr│   │   │
│  └──────────────────┘        │  └────────┬────────┘   │   │
│           │                  │           │ping         │   │
│           ▼                  │           ▼             │   │
│  ┌─────────────┐             │  ┌───────────────────┐  │   │
│  │ redis-go    │             │  │ redis-django      │  │   │
│  │ :6379       │             │  │ :6379/0           │  │   │
│  │ (Auth only) │             │  │ (Django+Celery)   │  │   │
│  └─────────────┘             │  └───────────────────┘  │   │
│                              │           │              │   │
│                              │  ┌────────▼────────┐    │   │
│                              │  │  PostgreSQL DB  │    │   │
│                              │  │  - Beat schedule│    │   │
│                              │  │  - NewsTaskState│    │   │
│                              │  └─────────────────┘    │   │
│                              └─────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 2-2. Celery-Beat 스케줄러 장애 대응 흐름

```
[정상 상태 — CLOSED]
ResilientBeatScheduler
  ├── 10초마다 Redis broker ping
  ├── DatabaseScheduler로 스케줄 관리 (항상 PostgreSQL)
  └── 태스크 dispatch → Redis broker → Celery Worker

[장애 감지 — CLOSED → OPEN]
Redis ping 실패 1회 → BrokerCircuitBreaker.record_failure() → failures += 1
Redis ping 실패 5회 → circuit trips to OPEN
  ├── logger.error("Beat broker circuit → OPEN")
  ├── Sentry alert: circuit_state=OPEN, failed_service=django_redis_broker
  └── next_probe_at = now + 60s ± 15% (jitter)

[OPEN 상태]
Beat: 스케줄링 계속 (PostgreSQL 기반, Redis 불필요)
Worker: dispatch 불가 (broker=Redis → 태스크 대기)
Beat CB: probe 타이머 대기 (dispatch는 중단되나 스케줄 기록은 유지)

[회복 프로브 — OPEN → HALF-OPEN]
next_probe_at 경과 → allow_probe() → True → HALF-OPEN
  ├── Redis ping 성공 → record_success()
  │     ├── state = CLOSED, failures = 0
  │     └── Sentry recovery: circuit_state=CLOSED, downtime=Xs
  └── Redis ping 실패 → on_probe_failure()
        ├── probe_attempt += 1
        ├── backoff = min(60 * 2^attempt, 300) ± 15% jitter
        └── state = OPEN (extended backoff)
```

#### Exponential Backoff 계산식

```
backoff(attempt) = min(base * 2^attempt, max) ± (value * 15%)

attempt=0: min(60*1, 300) = 60s ± 9s  → [51s, 69s]
attempt=1: min(60*2, 300) = 120s ± 18s → [102s, 138s]
attempt=2: min(60*4, 300) = 240s ± 36s → [204s, 276s]
attempt=3: min(60*8, 300) = 300s ± 45s → [255s, 345s] (capped)
```

### 2-3. 스케줄러 구현 핵심 코드

**`config/celery_scheduler.py`**

```python
class ResilientBeatScheduler(DatabaseScheduler):
    def tick(self, event_t=None, *args, **kwargs):
        self._maybe_check_broker()       # ① Redis 헬스 체크
        return super().tick(...)         # ② DB 기반 스케줄링 실행

    def _maybe_check_broker(self):
        if cb.state == CLOSED and ping fails:
            cb.record_failure()          # 실패 카운트
        elif cb.allow_probe():           # HALF-OPEN 프로브
            if ping fails:
                cb.on_probe_failure()   # 백오프 연장
            else:
                cb.record_success()     # CLOSED 복귀 + Sentry
```

---

## 3. Worker 원자적 처리 로직 — Lock & Double-Check

### 3-1. 문제: Redis 락의 취약점

기존 코드:
```python
# business_news_service.py (수정 전)
if not cache.add(lock_key, "locked", timeout=LOCK_TTL):
    return  # Redis 다운 시 → cache.add 실패 or 예외 → 락 소실
```

**Redis 다운 시 발생하는 문제:**
- `cache.add()` → 예외 또는 `False` 반환 → 락 획득 실패로 처리
- 모든 워커가 락 획득에 "성공"한 것으로 판단
- 다수 워커가 동시에 Gemini API 호출 → **중복 유료 API 호출 발생**

### 3-2. 해결: DB 레벨 `select_for_update()` + Double-Check

#### `NewsTaskState` 모델 (`news/adapters/orm/models.py`)

```python
class NewsTaskState(models.Model):
    country_code = models.CharField(max_length=10, unique=True, db_index=True)
    last_run_at  = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "news_task_state"
```

#### 2단계 원자적 처리 흐름

```
Worker A, B 동시 실행 시나리오:
─────────────────────────────────────────────────────────
Worker A                          Worker B
─────────────────────────────────────────────────────────
BEGIN TRANSACTION
select_for_update(nowait=True)    → (A가 행 잠금 획득)
  ├─ last_run_at 확인 (NULL)
  ├─ last_run_at = now() 저장      BEGIN TRANSACTION
  └─ COMMIT (잠금 해제)            select_for_update(nowait=True)
                                     → OperationalError 즉시 발생
Gemini API 호출 (잠금 해제 후)      (Worker B: Skip 처리)
결과 저장
NewsTaskState.last_run_at 갱신

--- 6시간 후 재실행 시 ---
Worker C
BEGIN TRANSACTION
select_for_update(nowait=True)
  ├─ last_run_at = 5시간 55분 전
  ├─ age < UPDATE_INTERVAL_HOURS → Abort!
  └─ COMMIT (Gemini 호출 없음)
─────────────────────────────────────────────────────────
```

#### 구현 코드 (`business_news_service.py:_acquire_lock_and_check`)

```python
def _acquire_lock_and_check(self, country_code, force, task_id) -> bool:
    with transaction.atomic():
        # ① DB 행 잠금 — nowait=True: 다른 워커가 잠금 보유 시 즉시 OperationalError
        state, _ = NewsTaskState.objects.select_for_update(nowait=True).get_or_create(
            country_code=country_code
        )
        # ② Double-Check: 잠금 획득 후 재확인 (선점한 워커가 이미 갱신했을 수 있음)
        if state.last_run_at and not force:
            age = timezone.now() - state.last_run_at
            if age < timedelta(hours=UPDATE_INTERVAL_HOURS):
                # ③ Abort: Gemini API 호출 차단 + Sentry info 이벤트
                sentry_sdk.capture_message(
                    f"News task aborted (double-check fresh): {country_code}",
                    level="info",
                )
                return False
        # ④ In-flight 마킹: 이후 워커가 중복 실행 방지
        state.last_run_at = timezone.now()
        state.save(update_fields=["last_run_at"])
        return True
    # 트랜잭션 종료 = 잠금 해제

# 잠금 해제 후 Gemini API 호출 (긴 외부 호출 동안 DB 잠금 미보유)
news_items = self.news_port.get_country_news(country_code)
```

### 3-3. `nowait=True` vs `nowait=False` 선택 이유

| 항목 | `nowait=False` (blocking) | `nowait=True` (skip) |
|---|---|---|
| 동작 | 잠금 해제까지 대기 | 즉시 `OperationalError` |
| Celery 태스크에서 | 워커 스레드 블로킹 | 즉시 Skip → Celery 워커 반환 |
| 6시간 주기 태스크 | 과도한 대기 위험 | **권장: Skip이 안전** |

`nowait=True` 선택 이유: Celery 워커가 블로킹되면 다른 태스크 처리가 지연됩니다. 6시간 주기 태스크는 중복 실행을 Skip하는 것이 올바른 동작입니다.

---

## 4. Sentry 알람 임계치 및 구조화 컨텍스트

### 4-1. Auth-Redis (Central-auth Go) — Sentry 이벤트

| 이벤트 | 트리거 | 레벨 | 주요 필드 |
|---|---|---|---|
| CB CLOSED→OPEN | 5회 연속 Redis 인프라 오류 | `error` | `circuit_state=OPEN`, `failure_threshold=5`, `circuit_state` (로그) |
| HALF-OPEN 프로브 실패 | 프로브 응답 오류 | `error` | `circuit_state=OPEN`, `reason=probe_failed` |
| Blacklist PG 폴백 실패 | PG 쿼리 오류 | `error` | `session_id`, `error_type` |

구현 위치: `Central-auth/internal/resilience/circuit_breaker.go:captureFunc`

### 4-2. Django-Redis — Sentry 이벤트

#### `common/resilience/circuit_breaker.py` — JWKS / gRPC CB

```python
def _sentry_capture_circuit_open(name, failures, window):
    with sentry_sdk.push_scope() as scope:
        scope.set_tag("circuit_state", "OPEN")
        scope.set_tag("failed_service", name)        # e.g. "jwks_fetch"
        scope.set_extra("failure_count", failures)
        scope.set_extra("failure_window_seconds", window)
        sentry_sdk.capture_message(
            f"Circuit OPEN: {name} ({failures} failures in {window}s)",
            level="error",
        )
```

**트리거:** `failure_threshold` (기본 5회) 도달 시 자동 발화

#### `config/celery_scheduler.py` — Beat 브로커 CB

| 이벤트 | 함수 | 레벨 | 구조화 필드 |
|---|---|---|---|
| 브로커 OPEN | `_sentry_broker_open()` | `error` | `circuit_state=OPEN`, `failed_service=django_redis_broker`, `failure_count`, `scheduler` |
| 브로커 회복 | `_sentry_broker_recovered()` | `info` | `circuit_state=CLOSED`, `downtime_seconds` |

#### `news/application/services/business_news_service.py` — Worker 태스크

| 이벤트 | 트리거 | 레벨 | 구조화 필드 |
|---|---|---|---|
| 태스크 Abort | Double-Check: 데이터 Fresh | `info` | `abort_reason=double_check_fresh`, `country_code`, `task_id`, `data_age_seconds` |
| Gemini 예외 | API 오류 | `error` | `failed_service=gemini`, `country_code`, `task_id` |

#### `news/tasks.py` — 태스크 레벨

| 이벤트 | 트리거 | 레벨 | 구조화 필드 |
|---|---|---|---|
| 태스크 실패 | 미처리 예외 | `error` | `failed_service=news_fetch`, `country_code`, `task_id`, `force` |

### 4-3. Sentry 알람 임계치 권장 설정 (Sentry UI)

```
Alert Rule 1 — Redis Circuit Open (Critical)
  조건: event.tags.circuit_state = OPEN
  임계: 1회 발생
  알림: Slack #on-call + PagerDuty
  레벨: error

Alert Rule 2 — Beat Broker Recovered (Info)
  조건: message contains "circuit CLOSED"
  임계: 1회 발생
  알림: Slack #deploys
  레벨: info

Alert Rule 3 — News Task Abort Rate (Warning)
  조건: event.tags.abort_reason = double_check_fresh
  임계: 10회 / 1시간 초과
  알림: Slack #backend-alerts
  레벨: warning
  의미: 정상이면 낮아야 하며, 높으면 태스크 중복 dispatch 조사 필요
```

---

## 5. 변경 파일 요약

### 5-1. `requirements.txt`

```diff
+ django-celery-beat
```

### 5-2. `common/resilience/circuit_breaker.py`

```diff
+ import sentry_sdk
+
+ def _sentry_capture_circuit_open(name, failures, window):
+     with sentry_sdk.push_scope() as scope:
+         scope.set_tag("circuit_state", "OPEN")
+         ...
+
  cache.set(_open_key, 1, timeout=_jittered_timeout(recovery_timeout))
+ _sentry_capture_circuit_open(name, failures, failure_window)
```

### 5-3. `news/adapters/orm/models.py`

```diff
+ class NewsTaskState(models.Model):
+     country_code = models.CharField(max_length=10, unique=True)
+     last_run_at  = models.DateTimeField(null=True, blank=True)
```

### 5-4. `news/migrations/0005_newstaskstate.py` (신규)

`NewsTaskState` 테이블 생성 마이그레이션.

### 5-5. `news/application/services/business_news_service.py`

```diff
- from django.core.cache import cache            # Redis 락 의존
+ from django.db import OperationalError, transaction
+ from news.adapters.orm.models import NewsTaskState
+ import sentry_sdk

- LOCK_TTL = 60 * 10
- lock_key = self._lock_key(country_code)
- if not cache.add(lock_key, "locked", timeout=LOCK_TTL):
-     return

+ try:
+     should_run = self._acquire_lock_and_check(country_code, force, task_id)
+ except OperationalError:
+     return  # DB lock held by another worker
+ if not should_run:
+     return  # double-check: data still fresh

+ def _acquire_lock_and_check(self, country_code, force, task_id) -> bool:
+     with transaction.atomic():
+         state, _ = NewsTaskState.objects.select_for_update(nowait=True).get_or_create(...)
+         # double-check last_run_at
+         state.last_run_at = timezone.now()
+         state.save(update_fields=["last_run_at"])
+         return True
```

### 5-6. `news/tasks.py`

```diff
+ import sentry_sdk
  # task_id 전달, Sentry capture_exception 추가
+ news_service.fetch_and_store_news(code, task_id=task_id)
```

### 5-7. `config/celery_scheduler.py` (신규)

`ResilientBeatScheduler` + `_BrokerCircuitBreaker` 전체 구현.

### 5-8. `config/settings.py`

```diff
  INSTALLED_APPS = [
+     "django_celery_beat",
      ...
  ]

+ CELERY_BEAT_SCHEDULER = "config.celery_scheduler.ResilientBeatScheduler"
```

---

## 6. 운영 체크리스트

```bash
# django-celery-beat 마이그레이션 적용 (최초 1회)
python manage.py migrate django_celery_beat
python manage.py migrate news  # 0005_newstaskstate 포함

# Beat 실행 (ResilientBeatScheduler 자동 사용)
celery -A config beat -l info

# Celery Beat 스케줄 DB에 등록 (django-celery-beat 관리 명령)
python manage.py shell -c "
from django_celery_beat.models import PeriodicTask, CrontabSchedule
sched, _ = CrontabSchedule.objects.get_or_create(hour='*/6', minute='0')
PeriodicTask.objects.get_or_create(
    name='fetch-business-news-every-6-hours',
    defaults={'crontab': sched, 'task': 'news.tasks.fetch_business_news'}
)
"
```

## 7. 개선 제언

### 7-1. Beat CB 상태 지속성

현재 `_BrokerCircuitBreaker`는 in-process 메모리 상태입니다. Beat 재시작 시 CB 상태가 초기화됩니다. Beat는 단일 프로세스이므로 실용적이지만, 장기 운영 시 DB 또는 파일 기반 상태 저장을 고려하십시오.

### 7-2. Dead Letter Queue

Beat가 OPEN 상태에서 dispatch를 시도하면 태스크가 유실될 수 있습니다. Celery의 `task_reject_on_worker_lost` + RabbitMQ DLX 또는 Redis Streams 기반 Dead Letter Queue를 구성하여 유실 태스크를 재처리하십시오.

### 7-3. NewsTaskState 정리 태스크

`NewsTaskState` 테이블은 무제한 성장합니다. 활성 국가가 삭제된 경우 고아 행이 남습니다. 주간 정리 태스크(`DELETE WHERE country_code NOT IN (active countries)`)를 추가하십시오.

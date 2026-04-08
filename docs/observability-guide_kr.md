# Hackonomics 2026 — 3계층 관측성 가이드

> **언제 어떤 도구를 써야 하는가**: Grafana(상태), Loki(추적), Sentry(코드 디버깅)
>
> 세 도구는 `service_name`, `env`, `request_id` 라는 공통 레이블로 연결됩니다.

---

## 1. 도구별 역할 분담

| 계층 | 도구 | 핵심 질문 | 주요 레이블 |
|------|------|----------|------------|
| **메트릭 (Metrics)** | Prometheus + Grafana | "지금 시스템이 정상인가?" | `service`, `env`, `namespace` |
| **로그 (Logs)** | Loki + Grafana Explore | "이 요청은 어디서 무슨 일이 있었나?" | `service_name`, `request_id`, `level` |
| **오류 (Errors)** | Sentry | "이 코드가 왜 죽었나?" | `circuit_state`, `alert_id`, `from_state`, `to_state` |

---

## 2. 언제 Grafana(Prometheus)를 쓰는가

**대답할 수 있는 질문:**
- 로그인 성공률이 정상 범위(분당 5건 이상)인가?
- Kafka 컨슈머 지연이 허용 범위(1,000건 이하)인가?
- 뉴스 수집 처리량이 줄었는가?
- 서킷 브레이커가 현재 열려(OPEN) 있는가?
- HTTP 엔드포인트별 요청 레이트와 P99 레이턴시는?

**주요 대시보드 패널 (`dashboards/pipeline.json`):**

| 패널 | PromQL / LogQL | 임계값 |
|------|--------------|--------|
| Login Success Rate | `rate(central_auth_auth_operations_total{operation="login",result="ok"}[5m]) * 60` | < 5/min → 경고 |
| News Collection Throughput | `count_over_time({service_name="hackonomics-app"} \|= "News updated" [$__range])` | 0 → 스탈 경고 |
| Kafka Consumer Lag | `central_auth_kafka_consumer_lag` | > 5,000 → 위험 |
| Circuit Breaker State | `central_auth_circuit_breaker_state` | 1=OPEN, 2=HALF-OPEN |

**접속:** `http://grafana.hackonomics.internal:3000` → **Hackonomics Pipeline** 대시보드

---

## 3. 언제 Loki(분산 추적)를 쓰는가

**대답할 수 있는 질문:**
- 특정 사용자의 로그인 요청이 Go 서비스와 Django 서비스를 거치며 어디서 실패했는가?
- 특정 `request_id`에 관련된 모든 서비스의 로그를 한눈에 볼 수 있는가?
- 오류 레벨 로그가 갑자기 급증했는가?

### 3-1. request_id 기반 크로스 서비스 추적

모든 서비스는 JSON 로그에 `request_id`를 포함합니다. Promtail이 이를 Loki 레이블로 승격합니다.

**LogQL 쿼리 — 단일 요청 전체 추적:**
```logql
{namespace="default", request_id="<rid>"}
  | json
  | line_format "{{.service_name}} [{{.level}}] {{.msg}}"
```

**LogQL 쿼리 — 서비스 전체 오류만:**
```logql
{service_name=~"central-auth|hackonomics-app", level="error"}
  | json
  | line_format "[{{.ts}}] {{.event}}: {{.error}}"
```

**LogQL 쿼리 — 로그인 오류 패턴:**
```logql
{service_name="central-auth"}
  | json
  | operation="login"
  | result="error"
  | line_format "{{.ts}} {{.error}}"
```

### 3-2. Loki 경보 규칙

Helm 차트 `templates/loki-rules.yaml`에 다음 규칙이 배포됩니다:

| 규칙 | 조건 | 심각도 |
|------|------|--------|
| `LoginSuccessRateLow` | 1분 이동 평균 로그인 성공 < 5건 지속 1분 | warning |
| `NewsPipelineStalled` | 30분 내 "News updated" 로그 없음 | warning |
| `RedisCircuitOpenSustained` | REDIS_DOWN_FALLBACK_STARTED 5분 지속 | critical |

**Loki Ruler 설정 확인:**
```bash
kubectl exec -n default deploy/loki -- \
  wget -qO- http://localhost:3100/loki/api/v1/rules/hackonomics
```

### 3-3. Promtail 레이블 구조

```yaml
# Promtail이 JSON 로그에서 추출하는 레이블:
service_name: "central-auth"   # Go: slog "service" 필드 / Django: "service_name" 필드
request_id:   "abc-123-..."    # 모든 서비스 공통 — 분산 추적 키
level:        "error"          # 로그 레벨 필터링
event:        "REDIS_DOWN_FALLBACK_STARTED"  # 구조화 이벤트명
```

### 3-4. Kafka 기반 비즈니스 로그 추적

Django의 `outbox_to_kafka` 컨슈머가 `user-activities` 토픽에 발행한 이벤트는
**Promtail → Kafka → Loki** 경로로 수집됩니다. 이를 통해 뉴스 수집·환율·시뮬레이션 등
비즈니스 이벤트도 표준 파드 로그와 동일한 레이블로 Grafana Explore에서 조회할 수 있습니다.

**수집 경로:**
```
Django outbox_to_kafka
  └─ Kafka topic: user-activities
       └─ Promtail kafka scrape job (group_id: promtail-user-activities)
            └─ JSON pipeline (service_name, request_id, level 레이블 승격)
                 └─ Loki (tenant: hackonomics)
```

**메시지 페이로드 레이블 필드:**

| JSON 필드 | Loki 레이블 | 값 예시 |
|-----------|-----------|---------|
| `service_name` | `service_name` | `hackonomics-app` |
| `request_id` | `request_id` | `a1b2c3-...` |
| `level` | `level` | `info` |
| `event_type` | `event` | `news.created` |
| `occurred_at` | (타임스탬프) | RFC3339Nano |

**LogQL 쿼리 — Kafka 발행 이벤트 전체 조회:**
```logql
{source="kafka", service_name="hackonomics-app"}
  | json
  | line_format "{{.event_type}} agg={{.aggregate_type}}/{{.aggregate_id}}"
```

**LogQL 쿼리 — 특정 request_id의 비즈니스 이벤트 추적:**
```logql
{source="kafka", request_id="<rid>"}
  | json
  | line_format "[{{.occurred_at}}] {{.event_type}}: {{.aggregate_id}}"
```

**LogQL 쿼리 — 파드 로그와 Kafka 이벤트 동시 추적 (크로스 소스):**
```logql
{namespace="default", request_id="<rid>"}
  | json
  | line_format "{{.service_name}} [{{.level}}] {{.msg}}{{.event_type}}"
```

> **참고:** Promtail Kafka 스크레이프 설정은
> `charts/promtail/templates/configmap.yaml` — `kafka-user-activities` 잡을 확인하세요.

---

## 4. 언제 Sentry를 쓰는가

**대답할 수 있는 질문:**
- 어떤 코드 라인에서 예외가 발생했는가?
- 서킷 브레이커가 열릴 때 호출 스택은 무엇인가?
- Redis 장애 중 실제로 어떤 오류가 전파됐는가?
- 개별 오류 이벤트의 컨텍스트(태그, extras, 스택 트레이스)는?

### 4-1. Go (Central-auth) — Sentry 통합 현황

| 이벤트 | Sentry 타입 | 레벨 | 태그 |
|--------|-----------|------|------|
| `CLOSED → OPEN` | Exception (스택 포함) | **fatal** | `alert_id=REDIS_DOWN_CIRCUIT_OPEN`, `from_state`, `to_state`, `target=redis` |
| `OPEN → HALF-OPEN` | Message (스택 포함) | warning | `from_state`, `to_state`, `target=redis` |
| `HALF-OPEN → CLOSED` | Message (스택 포함) | warning | `from_state`, `to_state`, `target=redis` |
| HTTP 패닉 | Exception (gin recovery) | error | (자동 캡처) |
| Gemini API 예외 | Exception | error | `failed_service=gemini`, `country_code` |

`AttachStacktrace: true`가 `sentry.Init()`에 설정되어 있어, `CaptureMessage`와 `CaptureException` 모두 실행 시점의 Go 스택 트레이스를 포함합니다.

### 4-2. Django (Hackonomics-app) — Sentry 통합 현황

| 이벤트 | Sentry 타입 | 레벨 | 태그 |
|--------|-----------|------|------|
| `Circuit → OPEN` | Exception (스택 포함) | **fatal** | `circuit_state=OPEN`, `alert_id=REDIS_DOWN_CIRCUIT_OPEN`, `failed_service` |
| `Circuit → HALF-OPEN` | Exception (스택 포함) | warning | `circuit_state=HALF_OPEN`, `failed_service` |
| `Redis 스케줄러 폴백` | Message | **fatal** | `alert_id=REDIS_DOWN_SCHEDULER_FALLBACK_ACTIVE` |
| Gemini 예외 | Exception (자연 발생) | error | `failed_service=gemini`, `country_code` |
| 뉴스 태스크 중복 방지 중단 | Breadcrumb (quota 0) | info | `abort_reason=double_check_fresh` |

스택 트레이스는 `try/except` 패턴으로 합성 예외를 발생시켜 Sentry Python SDK에 전달합니다. `capture_exception()` 호출 시 활성 예외 컨텍스트가 있어야 스택이 첨부됩니다.

### 4-3. Sentry 태그로 조회 필터링

```
# Sentry 검색 쿼리 예시
alert_id:REDIS_DOWN_CIRCUIT_OPEN
circuit_state:OPEN failed_service:redis-django
level:fatal
from_state:CLOSED to_state:OPEN
```

---

## 5. 3도구 연결 방법 — 인시던트 워크플로우

```
1. Grafana 알림 수신
   └─ "LoginSuccessRateLow: 분당 2건 (정상: 15건)"
        │
        ▼
2. Loki Explore에서 원인 분석
   └─ {service_name="central-auth", level="error"} | json
   └─ → "REDIS_DOWN_FALLBACK_STARTED" 이벤트 다수 발견
   └─ request_id 추출 → {request_id="abc-123"} 로 cross-service 추적
        │
        ▼
3. Sentry에서 코드 레벨 디버깅
   └─ alert_id:REDIS_DOWN_CIRCUIT_OPEN 검색
   └─ Exception 스택 트레이스 확인
   └─ → 호출 스택에서 Redis 연결 풀 소진 원인 파악
        │
        ▼
4. 조치
   └─ Redis Pod 재시작 or 네트워크 복구
   └─ Grafana에서 CB State = 0(CLOSED) 복귀 확인
   └─ Loki에서 "circuit breaker: OPEN → HALF-OPEN → CLOSED" 로그 확인
```

---

## 6. K3S 환경 설정 확인

### Prometheus Scraping 확인
```bash
# central-auth 메트릭 엔드포인트 직접 확인
kubectl port-forward svc/hackonomics-central-auth 9091:9091
curl -s http://localhost:9091/metrics | grep central_auth_auth_operations

# ServiceMonitor 등록 확인
kubectl get servicemonitor -n default
```

### Loki 로그 수집 확인
```bash
# Promtail 상태 확인
kubectl logs -n default -l app.kubernetes.io/name=promtail --tail=50

# Loki에서 central-auth 로그 확인 (LogQL)
kubectl port-forward svc/loki 3100:3100
curl -G http://localhost:3100/loki/api/v1/query_range \
  --data-urlencode 'query={service_name="central-auth"}' \
  --data-urlencode 'limit=10'
```

### Sentry 연결 확인
```bash
# central-auth Sentry DSN 설정 확인
kubectl get secret -n default hackonomics-central-auth -o jsonpath='{.data.SENTRY_DSN}' | base64 -d

# Django Sentry DSN 확인
kubectl get secret -n default hackonomics-hackonomics-app -o jsonpath='{.data.SENTRY_DSN}' | base64 -d
```

---

## 7. 공통 레이블 매핑

세 도구는 다음 공통 필드로 연결됩니다:

| 필드 | Grafana(Prometheus) | Loki | Sentry |
|------|-------------------|------|--------|
| 서비스 식별 | `job`, `namespace` | `service_name` label | `server_name`, `environment` |
| 요청 추적 | — | `request_id` label | Sentry `transaction` |
| 오류 레벨 | metric label `result` | `level` label | Sentry `level` |
| 환경 구분 | `env` label | `namespace` label | `environment` tag |

**레이블 일관성 규칙:**
- `service_name` 값은 Kubernetes `app.kubernetes.io/name` 레이블과 일치해야 함
- `request_id`는 Go에서 `X-Request-ID` 헤더 / Django에서 `correlation_id` 미들웨어로 주입
- Sentry `environment`는 `APP_ENV` 환경변수 (`staging` / `production`)

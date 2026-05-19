# Red Hat 개발자 블로그: netstacklat을 활용한 네트워크 레이턴시 트러블슈팅

> 원문: [Boosting speed: Use eBPF and netstacklat to troubleshoot latency](https://developers.redhat.com/articles/2026/04/29/boosting-speed-use-ebpf-and-netstacklat-troubleshoot-latency)
> 저자: Toke Høiland-Jørgensen, Simone Ferlin-Reiter, Simon Sundberg (2026.04.29)

---

## 1. 배경: 네트워크 레이턴시의 중요성

- 네트워크 애플리케이션의 체감 성능에서 **레이턴시는 대역폭보다 훨씬 중요**함 (Chromium 연구 인용)
- 구글/아마존 연구(약 20년 전)에서 밝혀진 바와 같이, 상업 웹사이트의 불필요한 대기 시간은 **측정 가능한 고객 이탈**로 직결
- Bufferbloat 프로젝트 등의 노력으로 네트워크 자체의 레이턴시 문제는 많이 해결되었으나, **호스트 내부(커널 네트워크 스택)에서 발생하는 레이턴시**는 여전히 문제

## 2. netstacklat이란?

### 핵심 개념
- eBPF 기반 모니터링 도구로, **수신 패킷이 리눅스 네트워크 스택 내부에서 얼마나 오래 체류하는지** 추적
- 커널의 소프트웨어 타임스탬핑(`SOF_TIMESTAMPING_RX_SOFTWARE`)을 활용하여 패킷 도착 시점 기록
- 네트워크 스택의 다양한 지점에 eBPF 프로브를 부착하여 각 구간별 레이턴시 측정

### 측정 가능한 후크 포인트 (7개)
| 후크 이름 | 설명 |
|-----------|------|
| `ip-start` | IP 스택 도달 (traffic control 계층 통과 후) |
| `tcp-start` | TCP 스택 도달 (IP/라우팅 스택 통과 후) |
| `udp-start` | UDP 스택 도달 (IP/라우팅 스택 통과 후) |
| `tcp-socket-enqueued` | TCP 소켓 큐에 적재 (커널 수신 스택 끝) |
| `udp-socket-enqueued` | UDP 소켓 큐에 적재 (커널 수신 스택 끝) |
| `tcp-socket-read` | TCP 소켓에서 애플리케이션이 데이터 읽음 (유저스페이스 전달) |
| `udp-socket-read` | UDP 소켓에서 애플리케이션이 데이터 읽음 (유저스페이스 전달) |

### 레이턴시 원인 분석 방법 (구간별 비교)
- `tcp-socket-read`가 높고 `tcp-socket-enqueued`가 낮으면 → **애플리케이션이 소켓 데이터를 늦게 읽는 문제** (앱 지연 또는 CPU 스케줄링 문제)
- `tcp-socket-enqueued`와 `tcp-start` 사이가 높으면 → **TCP 계층 처리 지연**
- `ip-start`와 `tcp-start` 사이가 높으면 → **IP 계층 지연** (예: Netfilter 방화벽 규칙 과다)

### 데이터 집계 방식
- 개별 패킷 출력 대신 **지수 히스토그램(base-2)**으로 집계
- 각 빈(bin)이 이전의 2배 너비 → 나노초~수 초 범위를 컴팩트하게 표현
- 백분위수(percentile) 근사값 산출 가능
- 3% 수준의 미세한 최적화 감지에는 부적합하지만, **p99가 수 마이크로초에서 수 초로 급등하는 이상 현상 탐지에 적합**

## 3. 실전 데모: nginx 서버 성능 분석

### 시나리오
- nginx 서버에서 10KB 웹페이지(원주율 10,000자리) 서빙
- 목표: 15,000 RPS 처리
- 100Gbps 직결 링크 환경 (네트워크 지연 무시 가능)

### 1단계: nginx worker 2개 (과부하 상태)
- 실제 처리량: ~9,000 RPS (목표 미달)
- 중간값 응답 시간: 109ms (로컬 네트워크임에도)
- netstacklat 결과:
  - `tcp-socket-enqueued`: 평균 96.43μs (소켓 큐 도달까지 빠름)
  - `tcp-socket-read`: **평균 109.84ms** (nginx가 읽기까지 매우 느림)
  - 일부 요청은 8초 이상 소요
- **진단**: nginx가 심각하게 과부하되어 소켓 데이터를 제때 읽지 못함

### 2단계: nginx worker 6개로 증가
- 처리량: 15,000 RPS 달성
- 중간값 응답 시간: 0.95ms
- `tcp-socket-read`: **평균 1.02ms** (대폭 개선)
- 그러나 `tcp-socket-enqueued`가 여전히 100μs+ → 스택 통과 시간이 비정상적으로 김

### 3단계: 불필요한 nftables 규칙 10,000개 제거
- `tcp-start`: 평균 89.58μs → **2.30μs** (38배 개선)
- `tcp-socket-enqueued`: 평균 109.30μs → **4.18μs** (26배 개선)
- `tcp-socket-read`: 평균 1.02ms → **299.43μs** (3.4배 개선)
- **근본 원인**: 누군가 시스템에 불필요한 방화벽 규칙 10,000개를 남겨둠

## 4. 운영 모드

### CLI 모드
- `sudo netstacklat -i <인터페이스>` 형태로 실행
- 실시간 디버깅용

### Prometheus 연동 (장기 모니터링)
- [ebpf_exporter](https://github.com/cloudflare/ebpf_exporter)와 연동하여 Prometheus로 메트릭 내보내기
- Grafana 대시보드를 통한 시각화 가능
- 프로덕션 서버의 시스템 전체 네트워크 스택 성능 지표로 활용 가능

## 5. 기술적 구현 특성

- 원작자: Jesper Dangaard Brouer의 bpftrace 스크립트에서 출발
- 현재 소스: [xdp-project/bpf-examples](https://github.com/xdp-project/bpf-examples/tree/main/netstacklat)
- CO-RE(Compile Once - Run Everywhere) 호환 libbpf 기반
- ebpf_exporter와 호환되는 BPF 코드 설계
- TCP/UDP 양쪽 모두 지원
- 인터페이스별 필터링 지원
- cgroup별 그룹핑 옵션 제공

## 6. 핵심 가치 요약

| 항목 | 설명 |
|------|------|
| **문제 도메인** | 호스트 내부 네트워크 스택 레이턴시 |
| **차별점** | 스택 내 다중 구간 측정으로 병목 지점 정밀 특정 |
| **오버헤드** | eBPF 기반으로 낮은 오버헤드 |
| **대상 사용자** | 네트워크 성능 엔지니어, SRE, 시스템 관리자 |
| **활용 시나리오** | 애플리케이션 과부하 탐지, 방화벽 규칙 영향 분석, 스택 처리 병목 식별 |

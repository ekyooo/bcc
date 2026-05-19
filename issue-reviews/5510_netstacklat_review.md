# Issue #5510 Review: Adding 'netstacklat' as a new libbpf-tools utility

> Issue: https://github.com/iovisor/bcc/issues/5510
> Author: @tohojo (Toke Høiland-Jørgensen, Red Hat / xdp-project contributor)
> Source: https://github.com/xdp-project/bpf-examples/tree/main/netstacklat
> Reference: https://developers.redhat.com/articles/2026/04/29/boosting-speed-use-ebpf-and-netstacklat-troubleshoot-latency

---

## 1. 이슈 요약

xdp-project/bpf-examples 저장소에서 개발된 `netstacklat` 유틸리티를 BCC의 libbpf-tools에 추가하는 것에 대한 적합성 문의. 저자는 PR 제출 전 man page 등 필요한 조정 작업이 있음을 인지하고 있으며, 먼저 관심도를 확인하려는 단계.

---

## 2. 도구 개요

**netstacklat**은 수신 패킷이 리눅스 커널 네트워크 스택 내부의 각 계층을 통과하는 데 걸리는 시간을 측정하는 eBPF 기반 모니터링 도구.

### 핵심 메커니즘
- 커널의 `SOF_TIMESTAMPING_RX_SOFTWARE` 타임스탬핑 활용
- 네트워크 스택의 7개 후크 포인트에서 패킷 도착 시간 측정
- base-2 지수 히스토그램으로 집계 (per-event 출력이 아닌 map aggregation)
- ebpf_exporter 호환으로 Prometheus 연동 가능

### 측정 구간
```
ip-start → tcp-start → tcp-socket-enqueued → tcp-socket-read
                      → udp-socket-enqueued → udp-socket-read
```

---

## 3. BCC/libbpf-tools 적합도 평가

### ✅ 적합한 이유

| 항목 | 평가 |
|------|------|
| **Scope fit** | ✅ 네트워크 스택 성능 관측 도구 — BCC의 도구 범주에 정확히 부합 |
| **Production value** | ✅ Red Hat 블로그에서 실전 nginx 사례 시연. 방화벽 규칙 병목, 애플리케이션 과부하 등 실제 문제 진단에 활용 |
| **기술 기반** | ✅ 이미 libbpf CO-RE 기반으로 구현됨. vmlinux.h 사용, BPF CO-RE 패턴 준수 |
| **유지보수 부담** | ✅ 코드량이 적고 (bpf.c + .c + .h 3파일), 로직이 단순 (타임스탬프 차이 계산) |
| **저자 신뢰도** | ✅ xdp-project 핵심 기여자 (Toke Høiland-Jørgensen), Red Hat 네트워크 팀 |
| **Unix 철학** | ✅ "한 가지 일을 잘 하는" 도구 — 커널 네트워크 스택 내부 레이턴시 측정에 특화 |
| **BPF 성능 원칙** | ✅ BPF 내에서 히스토그램 집계 (map aggregation) → 고빈도 이벤트에서도 오버헤드 최소화 |

### ⚠️ 고려사항

| 항목 | 상세 |
|------|------|
| **커널 의존성** | `SOF_TIMESTAMPING_RX_SOFTWARE` 지원 필요. 단, 툴이 직접 활성화하므로 사용자 개입 불필요 (아래 상세 설명 참고) |
| **TAI 오프셋** | `ntp_gettimex()`로 자동 감지하여 `obj->rodata->TAI_OFFSET`에 주입 — 사용자 개입 불필요 |
| **인터페이스 필터링** | `-i` 옵션은 하드웨어 의존성이 아닌 선택적 필터 — 미지정 시 전체 인터페이스 모니터링 (아래 상세 설명 참고) |

#### Q1. `SOF_TIMESTAMPING_RX_SOFTWARE`는 보통 비활성화 상태인가?

**아니다. 별도 활성화 작업이 필요 없다.**

`SOF_TIMESTAMPING_RX_SOFTWARE`는 전역 커널 설정이 아니라 **소켓 단위 옵션**이다. 리눅스 커널은 시스템에서 어떤 소켓이든 이 옵션을 설정하면 그 순간부터 **모든 수신 패킷에 타임스탬프를 찍기 시작**한다 (커널은 패킷이 들어올 때 아직 어느 소켓의 것인지 모르기 때문에 ip_rcv 시점에서 전역으로 타임스탬핑함).

netstacklat은 이 동작을 의도적으로 활용한다. `enable_sw_rx_tstamps()` 함수 (소스 참고):

```c
static int enable_sw_rx_tstamps(void)
{
    int tstamp_opt = SOF_TIMESTAMPING_RX_SOFTWARE;
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(sock_fd, SOL_SOCKET, SO_TIMESTAMPING,
               &tstamp_opt, sizeof(tstamp_opt));
    return sock_fd; // 소켓을 열어둔 채로 유지
}
```

툴이 시작하면 내부적으로 UDP 소켓 하나를 열고 `SO_TIMESTAMPING` 옵션을 설정한 뒤 **프로세스가 실행되는 동안 계속 유지**한다. 이것만으로 커널 전체 패킷에 타임스탬프가 찍히기 시작한다. 별도의 커널 파라미터 설정이나 재부팅은 불필요하다. `CONFIG_NET_SKB_TIMESTAMPING`은 주요 배포판에서 기본 활성화되어 있고, 이 기능 자체는 커널 2.6.30부터 존재한다.

**실제 제약사항**: 툴 실행 중 이미 패킷이 커널에 도달하고 있어야 한다. 타임스탬프는 소켓 옵션 설정 이후 들어오는 패킷부터 찍히므로, 실행 직전에 들어온 패킷은 측정 불가. 이는 구조적 한계이며 정상 동작이다.

#### Q2. "특정 NIC 인터페이스에 바인딩"은 무슨 뜻인가? 임의 NIC에서 사용 불가한가?

**아니다. 하드웨어 제한이 전혀 없다.**

`-i` / `--interfaces` 옵션은 **선택적 필터**이다. 이름에서 오해가 생길 수 있는데, 소스 코드를 보면 실제 동작은 다음과 같다:

- BPF 프로그램은 `ip_rcv_core`, `tcp_v4_rcv` 등 커널 함수에 **전역으로 attach**됨
- `-i` 없이 실행하면 → 시스템의 **모든 인터페이스 패킷을 모니터링**
- `-i eth0,eth1` 처럼 지정하면 → BPF 프로그램 내에서 `filter_ifindex` 플래그로 해당 인터페이스 외 패킷을 skip
- 즉 tcpdump의 `-i` 플래그와 동일한 개념: **있으면 필터, 없으면 전체**

특정 NIC 드라이버나 하드웨어 기능(e.g. RSS, hardware timestamping)에 의존하지 않는다. 리눅스 커널 네트워킹 스택을 거치는 모든 수신 패킷에 동작한다. NIC 종류나 벤더 무관하다.

---

## 4. 기존 도구와의 중복 분석

### 가장 유사한 기존 도구: `tcppktlat`

| 비교 항목 | tcppktlat | netstacklat |
|-----------|-----------|-------------|
| **측정 범위** | 패킷 수신 → 유저스페이스 읽기 (단일 구간) | 패킷 진입 → IP → TCP/UDP → 소켓 적재 → 읽기 (다중 구간) |
| **프로토콜** | TCP만 | TCP + UDP |
| **출력 방식** | per-event (개별 패킷) | 히스토그램 집계 |
| **필터링** | PID, TID, 포트 | 인터페이스, cgroup |
| **용도** | 특정 연결의 패킷 지연 디버깅 | 시스템 전체 네트워크 스택 성능 프로파일링 |
| **메커니즘** | `tcp_rcv_space_adjust` + `__tcp_cleanup_rbuf` 후킹 | 커널 SW 타임스탬프 기반 |

### 결론: 🟢 중복 아님 — 상호 보완적

`tcppktlat`은 **개별 패킷 수준**에서 "소켓 도착 → 앱 읽기" 구간만 측정하는 반면, `netstacklat`은 **시스템 전체 수준**에서 네트워크 스택의 **여러 계층을 관통하는 레이턴시 분포**를 측정한다. 두 도구는 서로 다른 추상화 수준과 사용 시나리오를 다루며, 다음과 같이 구분됨:

- **tcppktlat**: "특정 프로세스의 TCP 패킷이 왜 늦게 읽히는가?" → 미시적 디버깅
- **netstacklat**: "커널 네트워크 스택의 어느 계층에서 병목이 발생하는가?" → 거시적 프로파일링

### 기타 네트워크 도구와의 비교

| 도구 | 측정 대상 | 중복 여부 |
|------|-----------|-----------|
| `tcpconnlat` | TCP 연결 설정 지연 (handshake) | ❌ 다른 레이어 |
| `tcprtt` | TCP 왕복 시간 (ACK 기반) | ❌ 다른 메트릭 |
| `tcplife` | TCP 연결 수명/처리량 | ❌ 다른 관점 |
| `tcpretrans` | TCP 재전송 이벤트 | ❌ 다른 문제 도메인 |
| `tcpstates` | TCP 상태 전이 | ❌ 다른 관점 |
| `tcpdrop` | 커널 내 TCP 패킷 드롭 | ❌ 다른 문제 도메인 |
| `netqtop` | NIC 큐 패킷 분포 | ❌ 다른 레이어 |
| `gethostlatency` | DNS 조회 지연 | ❌ 애플리케이션 계층 |

---

## 5. PR 제출 시 필요한 사항 (libbpf-tools 요구사항 기반)

### 필수 (blocker)
- [ ] `libbpf-tools/netstacklat.bpf.c` — BPF 프로그램
- [ ] `libbpf-tools/netstacklat.c` — 유저스페이스 프로그램
- [ ] `libbpf-tools/netstacklat.h` — 공유 헤더
- [ ] Makefile 엔트리 (스켈레톤 생성)
- [ ] `man/man8/netstacklat.8` — **OVERHEAD 섹션 포함** man page
- [ ] `README.md` 엔트리 추가

### 권장
- [ ] `libbpf-tools/netstacklat_example.txt` — 예제 출력

### 기술 요구사항 (libbpf-tools 규칙)
- [ ] `vmlinux.h` 사용 (커널 타입 재정의 금지)
- [ ] `BPF_CORE_READ` 계열 사용
- [ ] split lifecycle: `__open()` → configure → `__load()` → `__attach()`
- [ ] 모든 map lookup 후 NULL 체크
- [ ] 모든 malloc/calloc 후 NULL 체크
- [ ] BPF 스택 사용량 512바이트 미만
- [ ] 기본 출력 폭 80자 미만
- [ ] BTF-style map 정의 사용
- [ ] 리소스 정리: `goto cleanup` 패턴

---

## 6. 종합 평가

### 🟢 추천: PR 환영 대상

**근거:**
1. **고유한 가치**: 커널 네트워크 스택 내부의 다중 계층 레이턴시 프로파일링은 기존 BCC 도구에 없는 기능
2. **실용적 가치**: 실제 프로덕션 환경에서 방화벽 규칙 병목, 애플리케이션 과부하 등의 문제를 정밀하게 진단 가능
3. **기술적 성숙도**: 이미 작동하는 libbpf CO-RE 코드가 존재하며, ebpf_exporter 연동까지 검증됨
4. **저자 역량**: Red Hat 네트워크 팀 + xdp-project 핵심 기여자
5. **유지보수 부담 낮음**: 단순한 타임스탬프 차이 계산 로직, 코드량 적음
6. **BCC 도구 철학 부합**: 한 가지 일(네트워크 스택 레이턴시)을 잘 하며, BPF 내 히스토그램 집계로 성능 원칙 준수

### 권고사항
1. 현재 저장소의 코드를 libbpf-tools 규약에 맞게 조정 필요 (lifecycle, 코딩 스타일 등)
2. man page에 최소 커널 버전 요구사항 명시
3. `SOF_TIMESTAMPING_RX_SOFTWARE` 활성화 요구사항을 문서에 명확히 기술
4. 출력 폭 80자 제한 준수 확인
5. 도구 이름 `netstacklat` — 약간 길지만 기능을 명확히 설명하므로 수용 가능

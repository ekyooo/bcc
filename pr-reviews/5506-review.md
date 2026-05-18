# PR #5506 코드 리뷰

**제목**: [libbpf-tools: Fix ringbuf leaks that leak prior events to userspace](https://github.com/iovisor/bcc/pull/5506)  
**저자**: @vdasu  
**리뷰 날짜**: 2026-05-15

---

## 개요

`reserve_buf()`가 반환하는 메모리(ringbuf 슬롯 또는 per-CPU heap 배열)를 zero-initialize하지 않아,
이전 이벤트의 잔류 데이터가 userspace로 누출되는 문제를 수정합니다.

특히 `mountsnoop`의 `struct event`는 tagged union을 포함하여 하나의 arm만 쓰이고
나머지 arm의 바이트가 이전 레코드 데이터를 그대로 보유합니다 (Linux 6.8에서 실증됨).

영향 파일: `mountsnoop`, `opensnoop`, `filelife`, `oomkill`, `tcppktlat`

---

## `zero_buf()` 구현 분석 — `compat.bpf.h`

```c
static __noinline void zero_buf(void *p, __u64 sz)
{
    for (__u64 i = 0; i < sz; i++)
        *(volatile char *)((char *)p + i) = 0;
}
```

### ✅ 올바른 설계 결정들

- **`__noinline`**: 각 call site에서 루프를 인라인하지 않고 단일 BPF-to-BPF subprogram으로 공유.
  코드 크기와 verifier instruction limit 절약에 유리.
- **`volatile` cast**: LLVM의 loop-idiom recognition이 이를 `__builtin_memset`으로 re-lower하지
  못하게 막음. BPF backend에 `memset` 심볼이 없으므로 컴파일 실패를 방지하는 핵심 기법.
- **완전성**: 현재 코드베이스에서 `reserve_buf()`를 호출하는 모든 5개 파일을 커버. 누락 없음.

---

## 🔴 중요 이슈 — BPF Bounded Loop 커널 버전 제한

`__noinline` 함수 내의 `for (__u64 i = 0; i < sz; i++)` 루프는 **런타임 변수**(`sz`)를 상한으로
사용합니다. BPF verifier가 루프 종료를 증명해야 하므로 **Linux 5.3 이상**에서만 동작합니다
(bounded loop 지원 도입). 5.3 미만 커널에서는 verifier가 루프를 거부합니다.

### 커널 버전별 동작

| 커널 버전 | ringbuf | bounded loop | 동작 |
|---|---|---|---|
| < 5.3 | 없음 | 없음 | **프로그램 로드 실패** (verifier reject) |
| 5.3 ~ 5.7 | 없음 | 지원 | per-CPU heap 경로, `zero_buf()` 정상 동작 |
| ≥ 5.8 | 지원 | 지원 | 완전 정상 동작 |

5.3 미만에서는 다음과 같은 에러가 발생합니다:
```
libbpf: load bpf program failed: Invalid argument
back-edge from insn X to Y  (또는 "loop not allowed")
```

**조치 필요**: PR 설명 또는 해당 툴 man page에 `zero_buf()` 사용으로 인한 최소 커널 버전(5.3) 명시.

---

## 🟡 경고 1 — `__u64` 루프 카운터

```c
for (__u64 i = 0; i < sz; i++)
```

`__u64`로 선언하면 BPF verifier 입장에서 `sz`가 이론상 `[0, 2^64-1]`의 어느 값이든
될 수 있어 verifier의 range tracking 부담이 커집니다. `MAX_EVENT_SIZE`는 10240 바이트이므로
`__u32`로 충분합니다.

```c
// 권장
static __noinline void zero_buf(void *p, __u32 sz)
{
    for (__u32 i = 0; i < sz; i++)
        *(volatile char *)((char *)p + i) = 0;
}
```

실제로는 call site에서 `sizeof(*eventp)` 같은 컴파일타임 상수를 넘기므로 현재도 통과하겠지만,
`__u32`가 의미상 더 정확하고 verifier 부담도 적습니다.

---

## 🟡 경고 2 — `reserve_buf()` 내부 중앙화 제안

현재 구조는 각 caller가 `zero_buf()`를 직접 호출해야 하므로, 향후 `reserve_buf()`를 사용하는
새 BPF 프로그램이 추가될 때 같은 버그를 반복할 수 있습니다.

`reserve_buf()` 자체에서 zero-init하는 방어적 방식:

```c
static __always_inline void *reserve_buf(__u64 size)
{
    static const int zero = 0;
    void *buf;

    if (bpf_core_type_exists(struct bpf_ringbuf))
        buf = bpf_ringbuf_reserve(&events, size, 0);
    else
        buf = bpf_map_lookup_elem(&heap, &zero);

    if (buf)
        zero_buf(buf, (__u32)size);
    return buf;
}
```

이렇게 하면 각 .bpf.c 파일의 `zero_buf()` 호출을 모두 제거할 수 있고,
향후 추가될 툴이 자동으로 보호됩니다.

---

## Copilot Reviewer 피드백 검토

> **Copilot**: "zero_buf()가 1바이트씩 지우므로 큰 이벤트 구조체에서 CPU 오버헤드가 발생할 수 있다.
> 8바이트 단위 volatile store + tail로 최적화를 고려하라."

**평가**: 🟡 타당하지만 현재 버전에서 필수는 아님.

- `mountsnoop`의 `struct event`는 최대 ~9,000+ 바이트로 바이트 루프 ~9000번 반복 발생.
- 8바이트 단위로 처리하면 ~1125 반복으로 약 8× 빠르지만, 코드 복잡도 증가.
- mountsnoop/opensnoop 등은 syscall 단위 이벤트로 hot path가 아님.
  syscall 자체가 수천~수만 ns인데, zero_buf 오버헤드는 수십~수백 ns 수준으로 무시 가능.
- 저자(@vdasu)의 "필요하다면 최적화를 커밋하겠다"는 입장이 적절. 현재는 correctness 우선.

---

## zero_buf 필요성에 대한 심층 검토

### "모든 필드를 명시적으로 쓰기" 접근의 한계

tagged union 구조(mountsnoop)에서는 inactive arm을 원천적으로 쓸 수 없어 구조적으로 불가능.
코드 리뷰로 강제하기 어렵고, 향후 필드 추가 시 회귀 위험이 높음.

### 커널이 zero-init해서 주면 안 되나?

커널 개발자들이 **의도적으로** 하지 않기로 결정:
- ringbuf는 zero-copy 고성능 설계 원칙 — reserve 시마다 zeroing하면 이점 반감.
- per-CPU heap 배열은 scratch buffer 용도로 설계되어 재사용 시 이전 값 유지가 의도된 동작.

### 다른 프로젝트 사례

- **bpftrace**: 스택 변수 `= {}` zero-init 사용.
- **Cilium**: Go 레이어에서 수신 버퍼 관리, BPF 측은 사용 필드만 작성 + packed 구조체 설계.
- **Linux 커널 샘플**: 소형 struct는 `= {}`, 대형은 `__builtin_memset` (LLVM 한계 workaround 각양각색).

**결론**: syscall 단위 이벤트에서 성능 트레이드오프는 무시 가능하며, union 구조상 `zero_buf()`가 가장 안전하고 유지보수성 높은 선택.

---

## 종합 평가

| 항목 | 평가 |
|---|---|
| 보안 문제 수정 정확성 | ✅ 올바름 |
| `volatile` + `__noinline` 설계 | ✅ LLVM lowering 방지 정확 |
| `reserve_buf()` 사용 파일 완전 커버 | ✅ 5개 전부 포함 |
| 커널 버전 호환성 명시 | 🔴 Bounded loop → Linux 5.3+ 명시 필요 |
| `__u64` 카운터 → `__u32` 권장 | 🟡 개선 가능 |
| `reserve_buf()` 중앙화 | 🟡 장기적으로 더 안전한 대안 |
| Copilot 8-byte 최적화 제안 | 🟡 타당하나 지금 필수 아님 |

버그픽스로서 방향은 올바르나, **BPF bounded loop의 최소 커널 버전(5.3) 명시**가 blocker 수준으로 필요합니다.

---

## 추가 분석 (2026-05-18)

### opensnoop zero_buf 오버헤드 분석

각 도구별 이벤트 크기와 빈도:

| 도구 | 이벤트 크기 | 빈도 | zero_buf 부담 |
|---|---|---|---|
| **opensnoop** | **~8,228 B** | `open`/`openat` 시스콜마다 (높음) | **🔴 유의미** |
| **tcppktlat** | ~72 B | TCP 패킷마다 (잠재적으로 매우 높음) | 🟢 무시 가능 |
| mountsnoop | ~8,764 B | mount/umount (매우 낮음) | 🟢 무시 가능 |
| filelife | ~8,196 B | 짧은 수명 파일 삭제 (보통) | 🟡 보통 |
| oomkill | ~48 B | OOM kill (극히 드묾) | 🟢 무시 가능 |

opensnoop이 가장 우려됨. 바쁜 서버에서 `openat`은 초당 수천~수만 회 발생하며, 이벤트 구조체가 ~8KB.
매 이벤트마다 8,228번의 volatile byte store 실행:
- BPF instruction 기준: ~41,000 instructions/event
- 실행 시간: ~40~120 μs/event (openat 시스콜 자체가 ~1~10 μs)
- probe overhead가 원래 시스콜 latency보다 커질 수 있음

tcppktlat은 빈도 높지만 72B만 zeroing하므로 무시 가능.

**제안**: opensnoop에서는 8-byte 단위 최적화가 실질적으로 필요한 케이스.

### bpftrace의 ringbuffer zero-init 방식

bpftrace 컴파일러가 이벤트 구조체를 코드 생성할 때, 사용자가 작성한 스크립트에서
어떤 필드를 쓰는지 정적 분석하여:
1. 스택 변수 → `= {}` 또는 `__builtin_memset` 삽입
2. ringbuf reserve 후 → 코드 생성 단계에서 `memset`을 LLVM IR 생성기가 직접 삽입

bpftrace 사용자는 이 문제를 신경 쓸 필요 없음 — 컴파일러가 자동 처리.
libbpf-tools는 개발자가 직접 BPF C를 작성하므로 수동 해결 필요.

### `__builtin_memset` 사용 가능 여부

- **작은 struct (≤~256B)**: 사용 가능. LLVM이 inline store로 전개.
- **큰 struct (>~256B)**: 사용 불가. LLVM이 libcall(call memset)로 lowering → BPF에 memset 심볼 없음 → 링크 실패.

oomkill(48B), tcppktlat(72B)에는 `__builtin_memset` 안전하게 동작하나,
5개 도구에 일관된 방식을 위해 `zero_buf()` 통일이 유지보수 측면에서 합리적.

### `__noinline` 상세 동작

BPF-to-BPF call (Linux 4.16 도입). `__noinline`을 쓰면 LLVM이 별도 BPF 함수로 emit하고,
call site에서는 `call` instruction 하나만 남음. Verifier는 `zero_buf`를 한 번만 검증하고 결과를 캐시.

inline되면 → 5개 파일 × 루프 코드 복제 → 코드 크기 5배 + verifier 검증 비용 5배.
`__noinline`이면 → 1개 공유 함수 + 각 site에서 call 1개.

### `volatile` cast 상세 동작

LLVM의 Loop Idiom Recognition 최적화 패스가 byte-store 루프를 자동으로 `memset` 호출로
변환하는 것을 방지. `volatile`의 C 의미: "이 메모리 접근은 side effect이므로 변환 금지".
리눅스 커널의 `memzero_explicit()`도 동일한 패턴 사용.

### ringbuf 재사용과 zeroing 필요성 재검토

**ringbuf 메모리 모델**:

ringbuf는 커널에서 고정 크기 circular buffer를 할당하고 reserve/commit으로 재사용하는 구조.

```
[할당 시점] 커널이 페이지 할당 → zero-init (page allocator가 __GFP_ZERO)
[1st reserve] slot A → BPF 프로그램이 부분적으로 채움 → commit → userspace 소비
[2nd reserve] slot A 재사용 → 이전 이벤트의 잔류 데이터 포함
```

재사용 시점에서 이전 데이터가 남는 것이 문제인데, 이전 데이터도 이미 userspace에 전달된 것이므로:
- **같은 프로세스(같은 BPF 프로그램)의 이전 이벤트** → 동일 사용자에게 이미 노출된 데이터
- 보안적으로는 **cross-process 정보 유출이 아님**

따라서 "매번 zeroing"이 정말 필요한 시나리오는:
1. **tagged union에서 inactive arm의 이전 데이터가 혼동을 줄 때** (mountsnoop)
   - 이전 MOUNT 이벤트의 src/dest가 UMOUNT 이벤트에 딸려옴 → userspace 파서가 잘못 해석 가능
2. **struct padding/정렬 바이트**가 userspace로 넘어갈 때
   - 이론적으로 KASLR 등 커널 정보 유출 가능... 하지만 ringbuf는 이미 userspace에 노출된 데이터

**핵심 논점**: 실제로 "보안 유출"이라기보다는 **데이터 무결성 문제**(잘못된 필드 값이
userspace에 도달)에 가깝다. 이전 이벤트 데이터가 새 이벤트의 inactive union arm에
남으면 userspace 파서가 혼동할 수 있음.

### 커널 API 개선안 vs 현재 패치의 가치

**커널 API 측면에서 가능한 개선**:
- `bpf_ringbuf_reserve_zero()` — reserve 시 zero-init된 슬롯 반환 (커널 패치 필요)
- `BPF_MAP_TYPE_RINGBUF` 생성 시 `BPF_F_ZERO_ON_RESERVE` 플래그

실제로 이런 제안이 커널 메일링 리스트에 논의된 적이 있으나, 성능 우려로 채택되지 않음.
"필요한 사용자만 자체 zeroing" 원칙 유지.

### 커널 5.3 제한과 유지보수 부담

**런타임 분기 불가능한 이유**:
- BPF 프로그램은 로드 시점에 verifier가 **모든 코드 경로를 정적 분석**
- "커널 버전이 5.3이면 이 경로, 아니면 저 경로" 같은 런타임 분기를 해도,
  verifier는 **양쪽 다 검증** → 루프가 있는 경로가 5.3 미만에서 reject됨
- CO-RE의 `bpf_core_type_exists`도 verifier가 dead code elimination 후 검증하지만,
  loop 자체의 존재는 CO-RE로 우회 불가

**실질적 영향 평가**:
- ringbuf 자체가 Linux 5.8에서 도입됨
- `compat.bpf.h`의 `reserve_buf()`는 ringbuf 없으면 per-CPU heap fallback
- per-CPU heap 경로도 `zero_buf()` 호출 → 5.3 미만에서 프로그램 로드 실패
- 하지만 현실적으로 BCC libbpf-tools는 이미 5.x 후반 기능을 많이 사용
- **대부분의 사용 환경이 5.8+** (ringbuf 사용 가능 환경 = 이미 5.3+ 보장)

**결론**: 5.3 미만 환경에서의 regression은 이론적으로 존재하나,
해당 환경에서 이 도구들이 실제로 사용되는 비율은 극히 낮음.
패치의 가치(데이터 무결성 수정)가 유지보수 부담보다 큼.

---

## 추가 분석 2 (2026-05-18)

### bpftrace의 `__builtin_memset` 한계 우회 방식

bpftrace는 자체 LLVM IR 생성기를 갖고 있어 일반적인 BPF C 컴파일과 경로가 다름:

```
[libbpf-tools 방식]
  C 소스 → clang/LLVM frontend → LLVM IR → 최적화 패스 → BPF backend
  └── __builtin_memset → LLVM이 libcall 변환 → 💥 링크 실패

[bpftrace 방식]
  스크립트 → bpftrace AST → bpftrace가 직접 LLVM IR 생성 → BPF backend
  └── store i64 0, ptr %p       ← 개별 store를 직접 나열
      store i64 0, ptr %p+8     ← Loop Idiom Recognition 대상 아님
      store i64 0, ptr %p+16
      ...
```

bpftrace는 구조체 크기를 컴파일 타임에 정확히 알고, LLVM IR 수준에서 개별 store를
직접 emit하므로 LLVM 최적화 패스의 memset 변환에 걸리지 않음.
libbpf-tools 개발자는 이런 코드 생성기를 사용할 수 없으므로 `volatile` loop workaround가 필요.

### ringbuf 재사용과 zeroing 필요성 재검토

**ringbuf 메모리 모델**:
```
[초기]  커널이 256KB 연속 공간 할당 (page allocator → GFP_ZERO로 zero-init)
[1st reserve] slot A → BPF가 부분 기록 → commit → userspace 소비
[2nd reserve] slot A 재사용 → 이전 이벤트의 잔류 데이터 포함
```

**보안 문제인가, 데이터 무결성 문제인가?**

엄밀히 말하면 보안 유출이 아님:
- ringbuf의 이전 데이터 = 같은 BPF 프로그램이 이전에 동일 userspace 소비자에게 보낸 데이터
- cross-process, cross-user 정보 유출 아님, KASLR 우회도 아님

실제 문제는 데이터 무결성:
- UMOUNT 이벤트를 받았는데 inactive union arm에 이전 MOUNT의 경로 잔류
- userspace 파서가 잘못된 정보를 표시하거나 혼동 유발
- 디버깅/모니터링 도구에서 잘못된 데이터 → 오진단

**커널 API 개선의 한계**:
ringbuf는 circular buffer 재사용 구조이므로 "처음 한 번 zero"는 이미 page allocator가 하고 있음.
문제는 재사용 시점. `bpf_ringbuf_reserve_zero()` 같은 API가 논의된 적 있으나
성능 우려로 채택 안 됨 — "필요한 사용자만 자체 zeroing" 원칙 유지.

### 커널 5.3 제한과 패치 가치

**런타임 분기 불가능한 이유**:
BPF verifier는 로드 시점에 **모든 코드 경로를 정적 검증**.
"5.3이면 이 경로, 아니면 저 경로" 분기를 해도 verifier가 양쪽 다 검증 → 루프가 있는 경로 reject.
CO-RE의 `bpf_core_type_exists`는 타입 존재 여부로 dead code elimination하지만,
"bounded loop 지원 여부" 자체는 CO-RE로 감지 불가.

**실질적 영향**:
- ringbuf 자체가 5.8 도입 → `reserve_buf()` 사용 환경은 이미 5.8+가 대부분
- 5.3 미만 per-CPU heap fallback 경로 사용자는 극소수
- 현실적으로 BCC libbpf-tools 사용자의 대다수가 5.8+ 환경

**패치 가치 종합**:

| 관점 | 평가 |
|---|---|
| 수정의 필요성 | 데이터 무결성 — 실제 잘못된 출력 방지 |
| 보안적 시급성 | 낮음 (cross-user leak 아님) |
| 5.3 미만 regression | 이론상 존재, 실질적 영향 극히 작음 |
| 유지보수 부담 | `zero_buf()` 12줄 + 각 call site 1줄 — 낮음 |
| 대안 복잡도 | 각 union arm 명시적 초기화 → 더 복잡하고 오류 가능성 높음 |

**결론**: opensnoop의 성능 영향(~8KB zeroing per event)이 실질적으로 검토되어야 할 문제이며,
5.3 미만 regression은 문서화로 충분히 커버 가능. 패치 가치가 유지보수 부담보다 큼.

### tagged union 개념

C의 `union`은 같은 메모리 공간을 여러 타입으로 해석하는 구조체:

```c
union {
    int   i;    // 4바이트
    float f;    // 4바이트
    char  c[4]; // 4바이트
}; // 메모리는 4바이트 하나
```

어떤 멤버를 쓰든 **같은 메모리를 공유**하므로, 동시에 여러 멤버에 유효한 값을 가질 수 없음.

**tagged union** = union + **어느 arm이 현재 유효한지 알려주는 tag(식별자)**:

```c
struct event {
    enum op op;    // ← tag: 어느 arm을 써야 하는지 알려줌
    union {
        struct { char src[4096]; char dest[4096]; ... } mount;   // op == MOUNT일 때
        struct { char dest[4096]; }                   umount;   // op == UMOUNT일 때
        struct { char fs[8]; }                        fsopen;   // op == FSOPEN일 때
    };
};
```

사용법:
```c
if (event->op == MOUNT)
    printf("src=%s", event->mount.src);   // mount arm 읽기
else if (event->op == UMOUNT)
    printf("dest=%s", event->umount.dest); // umount arm 읽기
```

**이 PR과의 관계**:

union의 메모리는 가장 큰 arm 크기만큼 할당됨 (`mount` arm = src[4096]+dest[4096]+... ≈ 8720B).
UMOUNT 이벤트가 발생하면 `umount` arm(dest[4096] = 4096B)만 쓰고
나머지 **4000B+ 는 쓰지 않음** → 이전 MOUNT 이벤트의 src, data 등이 그대로 잔류 → userspace로 누출.

---

## 추가 분석 3 (2026-05-18)

### tagged union active arm만 읽는다면, "previously emitted record 노출" 이슈인가?

코드 기준으로 보면 **inactive union arm 자체는 실질 이슈가 아님**.

`libbpf-tools/mountsnoop.c`의 userspace 처리 코드는 `switch (e->op)`로 분기하여
각 이벤트 타입의 **active arm만 읽음**:

```c
switch (e->op) {
case UMOUNT:
    e->umount.dest, e->umount.flags 만 사용
    break;
case MOUNT:
    e->mount.src, e->mount.dest, e->mount.fs, e->mount.data 만 사용
    break;
...
}
```

따라서 userspace가 현재처럼 올바르게 구현되어 있으면,
inactive arm에 남아 있는 이전 이벤트 데이터는 **읽히지 않으므로 출력 문제를 일으키지 않음**.

실제 문제가 되는 경로는 **active field 자체가 helper 실패로 갱신되지 못하는 경우**:

```c
bpf_probe_read_user_str(eventp->umount.dest,
                        sizeof(eventp->umount.dest),
                        argp->sys.umount.dest);
// 실패했는데 반환값을 체크하지 않음
// -> eventp->umount.dest 에 이전 슬롯 데이터가 그대로 남을 수 있음
// -> submit 후 userspace가 active arm인 e->umount.dest 를 읽음
```

즉 이슈의 핵심은 "inactive union arm의 일부 노출"이라기보다,
**`bpf_probe_read_user_str` 실패 시 active field에 stale data가 남는 것**에 가깝다.

### `bpf_probe_read_user_str` 실패 시 submit 안 하는 방향

이 방향이 **기술적으로 더 직접적이고 더 설득력 있음**.

예:
```c
case UMOUNT:
    eventp->umount.flags = argp->sys.umount.flags;
    if (bpf_probe_read_user_str(eventp->umount.dest,
                sizeof(eventp->umount.dest),
                argp->sys.umount.dest) < 0)
        goto cleanup;
    break;
```

장점:
- 근본 원인(helper 실패 시 stale data 사용)을 직접 제거
- `zero_buf()`의 per-event 전체 버퍼 초기화 비용 없음
- bounded loop를 도입하지 않으므로 Linux 5.3 미만 verifier 이슈 없음

단점:
- 각 `bpf_probe_read_user_str` 호출마다 명시적 오류 처리 필요
- 부분 실패 시 이벤트 전체를 버릴지 정책 선택 필요

그러나 tracing 도구 관점에서는 **부분적으로 틀린 데이터보다, 실패한 이벤트를 드롭하는 쪽이 더 안전**함.

### zero_buf 우려 사항 사실 확인

#### 1. opensnoop hotspot + 큰 버퍼로 인한 성능 우려

이 우려는 **사실**임.

`opensnoop`의 `struct event`는 `struct full_path fname`를 포함하고,
`full_path` 크기만 8168B, 전체 이벤트는 약 8228B.
그리고 `opensnoop`은 `open/openat/openat2` syscall마다 이벤트가 발생하므로,
busy 시스템에서는 매우 고빈도 경로가 될 수 있음.

따라서 `zero_buf(eventp, sizeof(*eventp))`는 event당 약 8KB를 매번 0으로 쓰는 셈이고,
이 패턴은 `opensnoop`에서는 실질적인 overhead가 될 수 있음.

#### 2. bounded loop의 Linux 5.3 이하 미지원 우려

이 우려도 **사실**임.

`zero_buf()`는 런타임 길이 `sz`를 상한으로 하는 BPF loop를 사용하고,
이런 bounded loop는 Linux 5.3부터 verifier가 허용함.
따라서 5.3 미만 커널에서는 프로그램 로드 시 verifier reject 가능성이 있음.

정리하면:

| 리뷰 포인트 | 사실 여부 | 판단 |
|---|---|---|
| inactive arm 노출이 본질 이슈인가 | ❌ 아님 | userspace가 active arm만 읽으면 직접 문제 아님 |
| read helper 실패 시 submit 금지 대안 | ✅ 타당 | 현재 PR보다 직접적인 수정 방향 |
| opensnoop 성능 우려 | ✅ 사실 | 특히 8KB급 event 구조체라 현실적 우려 |
| 5.3 미만 bounded loop 이슈 | ✅ 사실 | verifier 호환성 리스크 존재 |

### 종합 의견

현재 PR의 `zero_buf()`는 방어적 보강책으로는 이해되지만,
문제의 직접 원인을 겨냥한 수정이라고 보기는 어려움.

더 설득력 있는 리뷰 의견은 다음과 같음:

1. userspace가 active arm만 읽는 한, inactive union arm 잔류 자체를 "record leak"로 보는 서술은 과장되어 있음
2. 실제 문제는 `bpf_probe_read_user_str` 실패 시 active field가 갱신되지 않는 경로임
3. 따라서 각 read helper 반환값을 체크하고 실패 시 submit을 생략하는 쪽이 더 직접적이고 성능/호환성 면에서도 우수함

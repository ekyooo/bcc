# PR #5496 코드 리뷰

**제목**: [fix futexctn tool for symbol resolution and infinite loop](https://github.com/iovisor/bcc/pull/5496)  
**저자**: @dubeyabhishek  
**리뷰 날짜**: 2026-05-18

---

## 개요

이 PR은 `futexctn` 도구의 두 가지 버그를 수정합니다:

1. **심볼 해석 실패** — 수명이 짧은 프로세스가 종료된 후 `/proc/<pid>/maps`가 사라져 스택 심볼을 해석할 수 없는 문제
2. **히스토그램 맵 정리 시 무한 루프** — `bpf_map_get_next_key`로 순회하면서 동시에 삭제할 때 해시맵이 처음부터 다시 시작되는 문제

변경 파일:
- `libbpf-tools/trace_helpers.c` — `syms_cache__get_syms()` 캐시 히트 시 재로드 로직 추가
- `libbpf-tools/futexctn.c` — 심볼 캐시 프리로드 루프 + 키 스냅샷 후 삭제 방식

---

## 커밋별 분석

### 커밋 1: `bcc/libbpf-tools: fix futexctn stack trace symbol resolution`

#### 변경 사항

1. **`trace_helpers.c`**: `syms_cache__get_syms()`에서 캐시 히트이지만 `syms`가 NULL인 경우 `syms__load_pid()`를 재시도
2. **`futexctn.c`**: 메인 루프에서 `sleep(env.interval)` 대신 1초 간격으로 깨어나면서 hists 맵의 모든 tgid에 대해 심볼 캐시를 프리로드

#### 🔴 Critical: `trace_helpers.c` 변경은 공유 헬퍼에 대한 동작 변경

`syms_cache__get_syms()`는 다음 도구들이 모두 사용하는 **공유 함수**입니다:
- `capable.c`
- `profile.c`
- `offcputime.c`
- `memleak.c`
- `futexctn.c`

**기존 동작**: 캐시에 tgid 항목이 있으면 (syms가 NULL이든 아니든) 즉시 반환 → "이미 시도했고 실패함"을 의미  
**변경 후 동작**: syms가 NULL이면 매번 `syms__load_pid(tgid)`를 재호출

**문제점**: 프로세스가 이미 종료된 경우, 해당 tgid로 `syms_cache__get_syms()`를 호출할 때마다 `/proc/<pid>/maps` 열기를 반복 시도합니다. 이는 다른 도구(profile, offcputime 등)에서 **성능 퇴행**을 유발할 수 있습니다. 특히 짧은 간격으로 많은 종료된 프로세스를 처리하는 경우 불필요한 시스템 콜이 반복됩니다.

**제안**: 이 변경을 `trace_helpers.c` 공유 코드에 넣지 말고, futexctn 전용으로 처리하는 것이 안전합니다. 예를 들어:
- `syms_cache__get_syms()`에 `bool retry_on_null` 파라미터를 추가하거나
- `syms_cache__refresh_syms()` 같은 별도 함수를 추가하거나
- futexctn 프리로드 코드에서 직접 캐시 엔트리를 확인하고 재로드하는 방식

#### 🟡 Warning: 프리로드 루프에서 `exiting` 체크 누락

```c
for (int elapsed = 0; elapsed < env.interval; elapsed++) {
    sleep(1);
    // ... preload ...
}
```

Ctrl+C 시그널을 받아도 `exiting` 플래그를 확인하지 않아 현재 interval이 끝날 때까지 루프를 계속 돌 수 있습니다. `sleep(1)` 후에 `exiting` 체크를 추가해야 합니다:

```c
for (int elapsed = 0; elapsed < env.interval; elapsed++) {
    sleep(1);
    if (exiting)
        break;
    // ... preload ...
}
```

#### 🟡 Warning: 프리로드 설계의 한계

1초 간격 프리로드는 1초 미만 수명의 프로세스를 놓칠 수 있습니다. 주석에서 이를 인정하고 있지만, 이는 근본적 한계입니다. 더 나은 접근법은 BPF 쪽에서 프로세스 시작 시점에 이벤트를 발생시켜 심볼 캐시를 즉시 로드하는 것이겠으나, 현 PR 범위를 벗어나는 개선입니다.

#### ✅ Good

- `#ifndef USE_BLAZESYM` / `#else` 분기 — blazesym은 다른 해석 메커니즘을 사용하므로 프리로드 불필요. 일관성 있음
- 프리로드 의도와 동기를 설명하는 주석이 적절함

---

### 커밋 2: `bcc/libbpf-tools: fix futexctn infinite loop in hists map cleanup`

#### 변경 사항

기존 delete-while-iterate 패턴을 키 스냅샷 → 일괄 삭제로 변경:
```c
// Before (무한 루프 가능):
while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
    bpf_map_delete_elem(fd, &next_key);   // 삭제 후
    lookup_key = next_key;                 // 삭제된 키로 다음 조회 → 해시맵 처음부터 재시작
}

// After (스냅샷 후 삭제):
while (!bpf_map_get_next_key(...)) {
    ss_keys[ss_key_cnt++] = next_key;      // 키만 수집
    lookup_key = next_key;
}
for (int i = 0; i < ss_key_cnt; i++)
    bpf_map_delete_elem(fd, &ss_keys[i]);  // 수집한 키만 삭제
```

#### ✅ Good: 무한 루프 수정은 올바름

해시맵에서 삭제된 키로 `bpf_map_get_next_key`를 호출하면 처음부터 다시 시작됩니다. BPF가 동시에 새 항목을 삽입하면 무한 루프가 됩니다. 키 스냅샷 방식은 이를 올바르게 해결합니다.

#### ✅ Good: malloc NULL 체크 존재

```c
ss_keys = malloc(max_entries * sizeof(*ss_keys));
if (!ss_keys) {
    fprintf(stderr, "failed to alloc memory for hist cleanup\n");
    return -1;
}
```

Critical Rule 준수.

#### 🟡 Warning: `max_entries` 크기 전체 할당은 과도할 수 있음

`bpf_map__max_entries()`는 맵의 최대 용량을 반환합니다. 실제 항목 수가 적더라도 최대 용량만큼 메모리를 할당합니다. 기본 맵 크기가 크다면 불필요한 메모리 소비입니다.

**대안**: 더 간단하고 메모리 효율적인 패턴:
```c
lookup_key.pid_tgid = -1;
while (!bpf_map_get_next_key(fd, NULL, &next_key)) {
    err = bpf_map_delete_elem(fd, &next_key);
    if (err < 0) { ... }
}
```
`NULL`을 prev_key로 전달하면 항상 첫 번째 키를 반환합니다. 삭제 후 다시 첫 번째 키를 가져오므로 재시작 문제가 없습니다. 단, BPF가 삭제보다 빠르게 삽입하면 여전히 무한 루프 위험이 있으므로, 스냅샷 방식이 더 안전하긴 합니다. 메모리가 우려된다면 동적 배열(`realloc`)이나 합리적인 초기 크기를 사용하는 것도 방법입니다.

#### 🟡 Warning: 삭제 실패 시 부분 정리

키 삭제 중 하나가 실패하면 즉시 반환하여 나머지 키가 맵에 남습니다. 기존 코드도 동일한 문제가 있었으므로 퇴행은 아니지만, `warn`만 출력하고 계속 삭제하는 것이 더 견고합니다.

---

## 종합 평가

| 항목 | 판정 |
|------|------|
| 무한 루프 수정 (커밋 2) | ✅ 올바른 수정, 머지 가능 |
| 심볼 프리로드 (futexctn.c) | ✅ 좋은 접근, 사소한 개선 필요 |
| `trace_helpers.c` 공유 코드 변경 | 🔴 다른 도구에 영향, 재설계 필요 |
| `exiting` 체크 | 🟡 프리로드 루프에 추가 필요 |

### 요청 사항

1. **🔴 (Blocker)** `trace_helpers.c`의 `syms_cache__get_syms()` 변경을 공유 헬퍼에서 분리하세요. futexctn 전용 리프레시 메커니즘이나 별도 API를 사용해야 합니다. 현재 변경은 profile, offcputime, capable, memleak 등 다른 도구에서 종료된 프로세스에 대해 반복적으로 `/proc/<pid>/maps` 열기를 시도하는 성능 퇴행을 유발합니다.

2. **🟡 (Requested)** 프리로드 `for` 루프에 `if (exiting) break;`를 추가하세요.

3. **🟡 (Suggestion)** `max_entries` 대신 실제 키 수에 기반한 동적 할당을 고려하세요. 또는 `bpf_map_get_next_key(fd, NULL, &next_key)` + delete 패턴을 검토하세요.

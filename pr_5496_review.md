# PR #5496 코드 리뷰: futexctn 심볼 해석 및 무한 루프 수정

**PR 링크**: https://github.com/iovisor/bcc/pull/5496  
**작성자**: dubeyabhishek  
**리뷰 날짜**: 2026-04-28

---

## 변경 요약

이 PR은 두 가지 문제를 해결합니다:

1. **심볼 해석 실패**: 수명이 짧은 프로세스의 `/proc/<pid>/maps`가 사라져 심볼 해석에 실패하는 문제
2. **맵 정리 중 무한 루프**: `bpf_map_delete_elem` 호출 시 iterator가 무효화되어 무한 루프 발생

**변경 파일**:
- `libbpf-tools/futexctn.c`
- `libbpf-tools/trace_helpers.c`

---

## 잘 된 점

### 1. 무한 루프 수정 (`print_map` 함수)

**기존 코드의 문제:**
```c
while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
    bpf_map_delete_elem(fd, &next_key);  // 삭제 후 iterator 무효화!
    lookup_key = next_key;               // 무효한 키로 다음 검색
}
```

**수정된 코드 (snapshot 후 삭제):**
```c
// 1단계: 키 snapshot
while (!bpf_map_get_next_key(fd, &lookup_key, &next_key) &&
       ss_key_cnt < max_entries) {
    ss_keys[ss_key_cnt++] = next_key;
    lookup_key = next_key;
}

// 2단계: snapshot된 키 삭제
for (int i = 0; i < ss_key_cnt; i++) {
    err = bpf_map_delete_elem(fd, &ss_keys[i]);
    ...
}
```

이 패턴은 **올바른 수정**입니다. 다른 libbpf-tools에서도 동일한 방식을 사용하는 표준 패턴입니다.

### 2. 주기적 심볼 캐싱 아이디어

interval을 1초 단위로 분할하여 매초 심볼 캐시를 갱신함으로써, interval 내에서 시작하고 종료하는 수명이 짧은 프로세스도 캡처하려는 시도는 **합리적인 접근**입니다.

---

## 개선이 필요한 부분

### 1. `trace_helpers.c` 변경 - 부작용 우려 ⚠️

**변경 내용:**
```c
if (syms_cache->data[i].tgid == tgid) {
    /* tgid 엔트리가 이미 있지만 syms가 NULL인 경우 재시도 */
    if (!syms_cache->data[i].syms) {
        syms = syms__load_pid(tgid);
        if (syms)
            syms_cache->data[i].syms = syms;
    }
    return syms_cache->data[i].syms;
}
```

**문제점:**
- `syms_cache__get_syms`는 **공유 헬퍼 함수**입니다. bcc 내 여러 도구가 이 함수를 사용합니다.
- 원래 코드에서 `syms == NULL`인 캐시 엔트리는 "로딩 시도했으나 실패"를 의미했습니다 (프로세스 종료 등).
- 이 변경으로 인해 실패한 엔트리를 매 호출마다 재시도하게 되어, 이미 종료된 프로세스에 대해 반복적으로 `syms__load_pid`를 시도하는 오버헤드가 발생할 수 있습니다.
- 다른 도구들이 이 동작 변화에 영향을 받을 수 있습니다.

**권장**: futexctn에서만 필요한 로직이라면 `trace_helpers.c`를 수정하지 않고 futexctn 로컬에서 처리하는 것이 안전합니다.

> **참고**: 현재 `syms_cache__get_syms`의 원래 구현은 tgid가 캐시에 없으면 항상 `syms__load_pid`를 호출하고 결과를 저장합니다. 즉, preload 단계에서 `syms_cache__get_syms`를 호출하면 **별도의 trace_helpers.c 수정 없이도** 캐싱이 동작합니다. 따라서 이 변경의 필요성을 재검토할 필요가 있습니다.

---

### 2. 메모리 할당 크기 비효율 ⚠️

```c
max_entries = bpf_map__max_entries(obj->maps.hists);
ss_keys = malloc(max_entries * sizeof(*ss_keys));
```

- `max_entries`는 맵의 **최대 용량**이며, 실제 저장된 엔트리 수가 아닙니다.
- 실제 엔트리가 적더라도 맵 전체 용량만큼 메모리를 할당합니다.

**권장 방식:**
```c
// 방법 1: 먼저 실제 개수를 세고 할당
int count = 0;
struct hist_key tmp_key = { .pid_tgid = -1 }, tmp_next;
while (!bpf_map_get_next_key(fd, &tmp_key, &tmp_next)) {
    count++;
    tmp_key = tmp_next;
}
ss_keys = malloc(count * sizeof(*ss_keys));

// 방법 2: 동적으로 늘리는 방식 (realloc 사용)
```

---

### 3. 1초 단위 sleep 분할의 오버헤드 ⚠️

```c
for (int elapsed = 0; elapsed < env.interval; elapsed++) {
    sleep(1);
    if (!env.summary) {
        // 매초 전체 맵 순회하며 syms_cache 갱신
        while (!bpf_map_get_next_key(...)) {
            syms_cache__get_syms(syms_cache, next_key.pid_tgid >> 32);
            ...
        }
    }
}
```

- `env.interval`이 길면 (예: 60초) 매초 맵을 전체 순회하는 것은 과도한 오버헤드입니다.
- 또한 `env.summary` 모드에서는 단순히 `sleep(1)`을 반복하는데, 이는 `sleep(env.interval)`로 충분합니다.

**권장**: summary 모드에서는 기존처럼 `sleep(env.interval)` 유지, non-summary에서만 분할 적용.

---

## 최적 접근 여부 평가

| 측면 | 평가 | 비고 |
|------|------|------|
| 무한 루프 수정 (snapshot 패턴) | ✅ 최적 | 표준 libbpf 패턴 |
| 주기적 심볼 preload 아이디어 | ✅ 합리적 | 짧은 수명 프로세스 대응 |
| `trace_helpers.c` 수정 | ⚠️ 재검토 필요 | 범위가 넓고 부작용 가능 |
| 메모리 할당 방식 | ⚠️ 개선 여지 | max_entries 기반 과다 할당 |
| sleep 분할 로직 | ⚠️ 개선 여지 | summary 모드 최적화 가능 |

---

## 대안 제안

`trace_helpers.c`를 수정하지 않고 futexctn.c에서 직접 preload 처리:

```c
static void preload_syms_for_existing_pids(struct futexctn_bpf *obj)
{
    struct hist_key key = { .pid_tgid = -1 }, next;
    int fd = bpf_map__fd(obj->maps.hists);

    while (!bpf_map_get_next_key(fd, &key, &next)) {
        /*
         * syms_cache__get_syms already caches on first call.
         * Calling here while process is alive ensures /proc/<pid>/maps
         * is still accessible.
         */
        syms_cache__get_syms(syms_cache, next.pid_tgid >> 32);
        key = next;
    }
}
```

그리고 메인 루프에서:

```c
for (int elapsed = 0; elapsed < env.interval; elapsed++) {
    sleep(1);
    if (!env.summary)
        preload_syms_for_existing_pids(obj);
}
```

이렇게 하면:
- `trace_helpers.c`의 공유 함수를 건드리지 않아 안전합니다.
- 기존 `syms_cache__get_syms`의 caching 동작을 그대로 활용합니다.
- futexctn의 특수 요구사항이 futexctn.c에 국한됩니다.

# PR #5442 코드 리뷰: libbpf-tools/ksnoop: Fix memory leaks

- **PR URL**: https://github.com/iovisor/bcc/pull/5442
- **작성자**: kknjh
- **대상 파일**: `libbpf-tools/ksnoop.c`
- **리뷰 일자**: 2026-05-21

---

## 1. 변경 사항 요약

이 PR은 `libbpf-tools/ksnoop.c`의 `parse_traces()` 함수가 중간에 실패할 때 발생하는 메모리 누수를 수정합니다.

### 핵심 리팩토링

기존의 `parse_traces(int argc, char **argv, struct trace **traces)` 함수는 메모리 할당과 파싱 로직을 하나로 합쳐 처리했습니다. `parse_trace()`가 루프 도중 실패하면 이전에 성공한 항목들에 할당된 BTF 덤프(`trace->dump`), 모듈 BTF(`trace->btf`), 그리고 traces 배열 자체가 해제되지 않았습니다.

PR은 다음 세 함수로 분리합니다:

| 함수 | 역할 |
|---|---|
| `alloc_traces(int argc, struct trace **traces)` | `calloc`으로 traces 배열만 할당 |
| `parse_traces(int argc, char **argv, struct trace *traces)` | 파싱만 수행 (시그니처 변경: `struct trace **` → `struct trace *`) |
| `free_traces(struct trace *traces, __u8 num)` | BTF dump, 모듈 BTF, vmlinux BTF, traces 배열 통합 해제 |

---

## 2. 긍정적인 부분

### 2.1 근본적인 누수 수정

```c
// 이전: parse_trace 실패 시 이미 파싱된 BTF 객체와 traces 배열이 누수됨
for (i = 0; i < argc; i++) {
    if (parse_trace(argv[i], &((*traces)[i])))
        return -EINVAL; // traces 배열 해제 없음
}
```

`parse_trace()`는 내부에서 `get_btf()` → `btf_dump__new()` 순서로 자원을 할당합니다. 이전 코드는 중간 실패 시 이 자원들을 전혀 정리하지 않았으므로 수정은 타당합니다.

### 2.2 `calloc` 사용으로 안전한 부분 해제 보장

`alloc_traces`가 `calloc`을 사용하므로 `traces[i].dump`와 `traces[i].btf`가 초기값 `NULL`로 보장됩니다. libbpf의 `btf_dump__free(NULL)` 및 `btf__free(NULL)` 모두 NULL을 안전하게 처리하므로, `parse_trace`가 인덱스 `i`에서 실패하더라도 `free_traces(traces, i+1)`로 부분 해제가 안전합니다.

### 2.3 `goto cleanup` 수정

```c
// 이전: ksnoop_bpf__open_and_load() 실패 시 traces 누수
if (!skel) {
    ret = -errno;
    p_err("...");
    return 1; // traces가 해제되지 않음
}

// 이후:
    goto cleanup; // cleanup 레이블에서 free_traces() 호출
```

독립적으로 가치 있는 수정입니다.

---

## 3. 문제점 및 우려 사항

### 3.1 [버그] `vmlinux_btf` 전역 포인터가 해제 후 댕글링 상태 유지

```c
static void free_traces(struct trace *traces, __u8 num)
{
    __u8 i;

    for (i = 0; i < num; ++i) {
        btf_dump__free(traces[i].dump);
        if (traces[i].btf != vmlinux_btf)
            btf__free(traces[i].btf);
    }
    btf__free(vmlinux_btf); // 전역 해제
    free(traces);
}
```

`btf__free(vmlinux_btf)` 호출 후 전역 변수 `vmlinux_btf`는 해제된 메모리를 가리키는 댕글링 포인터 상태로 남습니다. 현재 CLI 흐름상 프로그램이 이후 종료되어 실질적 문제는 없지만, 향후 코드 변경 시 use-after-free 혹은 이중 해제(double-free)의 위험이 있습니다.

**권장 수정**:
```c
btf__free(vmlinux_btf);
vmlinux_btf = NULL; // 댕글링 포인터 방지
free(traces);
```

### 3.2 [설계] `free_traces`가 `vmlinux_btf` 전역 상태를 암묵적으로 관리

`free_traces`는 인자로 받은 `traces` 배열의 해제뿐 아니라 전역 `vmlinux_btf`까지 해제하는 부작용(side-effect)을 가집니다. 함수 이름(`free_traces`)에서 이 동작은 예상하기 어렵습니다.

원래 `free(traces)`는 BTF 객체를 전혀 해제하지 않았는데, 이 PR은 성공 경로(`cmd_info`, `cmd_trace` 정상 종료)에서도 BTF 해제를 추가하는 것이므로 의도된 동작인지 명확히 할 필요가 있습니다.

**권장 사항**: 함수명을 `cleanup_traces`로 변경하거나, 주석으로 전역 BTF 해제 동작을 명시합니다.

### 3.3 [동작 변경] `parse_traces` 실패 시 에러 코드 변경

```c
// 이전: 파싱 실패 시 -EINVAL 반환
if (parse_trace(argv[i], &((*traces)[i])))
    return -EINVAL;

// 이후: 실패한 인덱스 기반으로 -i-1 반환
if (parse_trace(argv[i], &(traces[i])))
    return -i - 1;
```

반환값의 의미가 바뀌었습니다. `-1`은 원래 인덱스 0에서의 실패를 뜻하지만, 일부 시스템에서 `-1 == -EPERM`과 일치할 수 있어 호출자가 에러 코드를 출력할 때 혼란을 줄 수 있습니다. `cmd_info`와 `cmd_trace`는 최종적으로 `-EINVAL`을 반환하므로 외부 동작은 동일하지만, 내부적으로 인덱스 인코딩을 위해 에러 코드 공간을 사용하는 방식은 fragile합니다.

**대안**: 성공적으로 파싱된 수를 별도 출력 파라미터(`int *parsed_count`)로 전달하고, 에러 시 `-EINVAL`을 일관되게 반환합니다.

### 3.4 [경미] `parse_traces` 실패 시 `free_traces(traces, -nr_traces)` 경계 확인

`parse_trace`가 인덱스 `i`에서 실패하면 `nr_traces = -i - 1`이 됩니다. 따라서 `free_traces(traces, -nr_traces)` = `free_traces(traces, i+1)`이 호출됩니다. 이는 실패한 인덱스 `i`의 trace도 해제 대상에 포함시킵니다. `parse_trace`가 실패한 trace의 `dump`나 `btf`를 부분적으로 설정했을 수 있으므로, `calloc`의 NULL 초기화 덕분에 현재는 안전하지만, 이 의존성이 코드 어디에도 문서화되지 않았습니다.

---

## 4. 기타 관찰

- `__u8 num` 타입을 사용하므로 `num`의 최대값은 255입니다. `MAX_FUNC_TRACES`가 255 이하인 한 문제없으나, `int`나 `size_t`를 사용하는 것이 더 일반적입니다.
- `cmd_trace`의 `cleanup` 레이블에서 이제 `free_traces`를 사용하는데, `skel`이 NULL인 경우에도 `ksnoop_bpf__destroy(NULL)` 호출이 발생합니다. libbpf는 NULL을 처리하므로 안전하지만, 원래 `return 1`을 `goto cleanup`으로 바꾼 경우 이 점을 인식해야 합니다.

---

## 5. 종합 평가

| 항목 | 평가 |
|---|---|
| 버그 수정 타당성 | ✅ 실제 메모리 누수를 수정하며, 수정 방향은 올바름 |
| 코드 구조 | ✅ 역할 분리(alloc/parse/free)로 가독성 향상 |
| `vmlinux_btf` 댕글링 포인터 | ⚠️ 해제 후 NULL 초기화 필요 |
| 전역 상태 부작용 명시 | ⚠️ 주석 또는 함수명으로 명확화 필요 |
| 에러 코드 인덱스 인코딩 | ⚠️ fragile하며 혼란 유발 가능 |
| `goto cleanup` 수정 | ✅ 올바른 추가 수정 |

**결론**: 메모리 누수 수정이라는 핵심 목적은 달성했으며 머지 가능한 수준입니다. 다만 `free_traces` 후 `vmlinux_btf = NULL` 추가와, `parse_traces`의 에러 반환값 설계에 대한 검토를 권장합니다.

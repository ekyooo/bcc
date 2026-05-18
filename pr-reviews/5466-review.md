# PR #5466 코드 리뷰

**제목:** fix: fix symbolize error when the VMA-offset of ELF section was different  
**작성자:** @AshinZ  
**링크:** https://github.com/iovisor/bcc/pull/5466  
**상태:** Open (검토자: @brendangregg, @chenhengqi, @ekyooo, @yonghong-song)

---

## 요약

BOLT 최적화 바이너리처럼 동일 ELF 파일에 대해 여러 코드 세그먼트 매핑(`.bolt.org.text`, `.text` 등)이 존재하는 경우, 기존 코드가 항상 `.text` 섹션 정보만 사용하여 심볼 주소를 잘못 계산하는 버그를 수정한다.

### 핵심 수식

```
offset = global_addr - (mod_start_addr - mod_file_offset) + (elf_sec_start_addr - elf_sec_file_offset)
```

- `(mod_start_addr - mod_file_offset)`: mmap 정보 기반으로 정확함
- `(elf_sec_start_addr - elf_sec_file_offset)`: 항상 `.text`만 사용하여 잘못된 값이 될 수 있음

### 수정 접근법

`bcc_elf_get_text_scn_info()` → `bcc_elf_get_scn_info(segment_offset, ...)` 로 변경하여,  
`segment_offset`에 해당하는 PT_LOAD+PF_X 프로그램 헤더를 찾고, 그 안의 첫 번째 섹션 정보를 반환.

---

## 변경 파일별 분석

### 1. `src/cc/bcc_elf.c` — 함수 재설계

**기존:** `bcc_elf_get_text_scn_info()` — `.text` 섹션을 이름으로 검색  
**변경:** `bcc_elf_get_scn_info()` — `segment_offset`으로 PT_LOAD 세그먼트를 찾고, 해당 세그먼트 내 첫 섹션 반환

#### 🔴 버그: 변수 선언이 코드 실행문 이후에 위치 (C90 비호환)

```c
ret = -1;           // 실행문

size_t phdr_num, i; // 변수 선언 — C99 이상에서만 허용
if (elf_getphdrnum(...))
    goto exit;

GElf_Phdr phdr;     // 변수 선언 — 실행문 이후
```

파일 상단의 다른 함수들은 모두 블록 시작부에 변수를 선언한다.
같은 파일의 `bcc_elf_foreach_load_section()`도 `GElf_Phdr header;`를 실행문 이후에 두는 패턴이 있으나, 신규 코드에서는 일관성을 위해 함수 최상단에 모두 선언하는 것이 바람직하다.

#### 🟡 스타일: 후행 공백

```c
int found_segment = 0;                              
```

세미콜론 뒤에 불필요한 공백이 다수 있다.

#### 🟡 설계 개선 여지: 섹션 탐색 루프 불필요

PT_LOAD 세그먼트에 속한 모든 섹션은 다음 관계를 만족한다:

```
sh_addr - sh_offset == p_vaddr - p_offset
```

따라서 섹션 루프 전체를 제거하고 프로그램 헤더의 `p_vaddr`/`p_offset`을 직접 반환해도 동일한 결과를 얻는다:

```c
/* 섹션 탐색 루프 없이 간단하게 */
if (found_segment) {
    *addr   = segment_vaddr;
    *offset = phdr.p_offset;
    ret = 0;
}
```

이 접근법이 더 단순하고 명확하다.

---

### 2. `src/cc/bcc_elf.h` — 헤더 선언 변경

함수 시그니처를 적절히 업데이트했다. 별도 이슈 없음.

---

### 3. `src/cc/bcc_syms.cc` — 핵심 로직 변경

#### 🔴 치명적 버그: 미초기화 변수 (uninitialized variables)

```cpp
uint64_t elf_so_offset;  // 초기화 없음
uint64_t elf_so_addr;    // 초기화 없음

if (it->type_ == ModuleType::SO) {
    if (bcc_elf_get_scn_info(...) < 0) {
        // 실패 경고 출력, but elf_so_addr/elf_so_offset은 여전히 미초기화
    }
}

// type_이 SO가 아니거나(VDSO 포함), get_scn_info가 실패한 경우
// elf_so_addr, elf_so_offset은 쓰레기값으로 emplace됨
it->ranges_.emplace_back(mod->start_addr, mod->end_addr, mod->file_offset,
    elf_so_addr, elf_so_offset);
```

두 가지 경우에서 UB(Undefined Behavior) 발생:

1. `it->type_`가 `ModuleType::SO`가 아닐 때 (VDSO, EXEC, PERF_MAP 등)
2. `bcc_elf_get_scn_info()`가 실패(-1 반환)할 때

**수정 방법:**
```cpp
uint64_t elf_so_offset = 0;
uint64_t elf_so_addr   = 0;
```

#### 🔴 치명적 버그: VDSO 심볼 해석 회귀(regression)

기존 코드에서 `elf_so_addr_`와 `elf_so_offset_`은 Module 생성자에서 `0`으로 명시 초기화되었다:

```cpp
// 기존 Module 생성자 (bcc_syms.cc 구버전)
elf_so_offset_ = 0;
elf_so_addr_   = 0;
```

`contains()`에서 VDSO도 SO와 같은 경로로 처리된다:

```cpp
if (type_ == ModuleType::SO || type_ == ModuleType::VDSO) {
    offset = __so_calc_mod_offset(range.start, range.file_offset,
                                  range.elf_so_addr, range.elf_so_offset, addr);
}
```

변경 후에는 `_add_module()`이 SO 타입에만 `bcc_elf_get_scn_info()`를 호출하므로,  
VDSO의 `Range::elf_so_addr`와 `Range::elf_so_offset`이 미초기화된 쓰레기값이 된다.  
이는 VDSO 심볼 해석을 완전히 깨뜨리는 명백한 회귀다.

**수정 방법:** 위와 동일하게 `elf_so_offset = 0; elf_so_addr = 0;`으로 초기화.

#### 🟡 경고 메시지 부정확

```cpp
fprintf(stderr, "WARNING: Couldn't find .text section in %s\n", ...);
```

`bcc_elf_get_scn_info()`는 더 이상 `.text`를 이름으로 찾지 않는다.  
메시지를 "Couldn't find code section for offset 0x%lx in %s" 등으로 수정 필요.

#### 🟡 주석 문법 오류

```cpp
// since there will be different real offset, so we must calculate each time.
```

→ `// Each range may have a different real section offset, so calculate per-range.`

---

### 4. `src/cc/syms.h` — Range 구조체 변경

`elf_so_addr_`/`elf_so_offset_`을 Module 수준에서 Range 수준으로 이동시킨 설계는 올바르다.  
단, 위에서 지적한 미초기화 문제로 인해 Range 생성자에 기본값이 없는 것이 문제다.

---

## 종합 평가

| 구분 | 내용 |
|------|------|
| **의도** | 명확하고 실제 운영 환경(BOLT 최적화 바이너리)에서 발생하는 버그 수정 |
| **핵심 로직** | PT_LOAD+PF_X 세그먼트 기반으로 섹션 정보를 찾는 접근은 수학적으로 올바름 |
| **치명적 결함** | `elf_so_addr`/`elf_so_offset` 미초기화 → VDSO 회귀 및 UB 유발 |
| **설계 개선 여지** | 섹션 루프 대신 프로그램 헤더 값을 직접 사용 가능 |

## 필수 수정 사항 (Merge 전 반드시 해결)

1. **`elf_so_addr = 0; elf_so_offset = 0;`으로 초기화** — UB 및 VDSO 회귀 해결
2. **경고 메시지 업데이트** — `.text section` 문구 제거
3. **커밋 메시지 보강** — @Bojun-Seo가 요청한 대로 문제 상황 예시 및 패치 결과 포함

## 선택적 개선 사항

4. 섹션 탐색 루프를 제거하고 `p_vaddr`/`p_offset` 직접 반환으로 단순화
5. 후행 공백 제거
6. C90 호환을 위해 변수 선언을 함수 최상단으로 이동

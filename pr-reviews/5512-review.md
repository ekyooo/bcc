# PR #5512 코드 리뷰

**제목**: [Rename check_cpu_filed to check_cpu_field](https://github.com/iovisor/bcc/pull/5512)  
**저자**: @shimarda  
**리뷰 날짜**: 2026-05-18

---

## 개요

`tools/execsnoop.py`에서 헬퍼 함수 이름의 오타를 수정합니다.
`check_cpu_filed()` → `check_cpu_field()` 로 변경하여 가독성과 일관성을 개선합니다.

변경 파일: `tools/execsnoop.py` (단일 파일, +3/-3)

---

## 최종 판정: ✅ Approve (마이너 코멘트 있음)

---

## 변경 내용

| 라인 | 내용 |
|------|------|
| 107  | 함수 정의 `check_cpu_filed()` → `check_cpu_field()` 로 변경 |
| 261  | 호출 지점 `check_cpu_filed()` → `check_cpu_field()` 로 변경 |
| 212  | 임베디드 BPF C 문자열 내 `if` 문의 선행 공백 1칸 제거 (무관한 변경) |

---

## 검토 항목

| 항목 | 상태 |
|------|------|
| Scope 적합성 | ✅ 명확한 오타 수정 |
| 정확성 | ✅ 정의·호출 지점 모두 일관되게 변경됨 |
| 동작 영향 | ✅ 없음 (순수 식별자 이름 변경) |
| 커밋 메시지 | ✅ 명확한 prefix 및 목적 기술 |

---

## 이슈

### 🟡 Warning — 무관한 공백 변경 (Line 212)

PR의 목적(오타 수정)과 무관한 공백 변경이 포함되어 있습니다.

```diff
-     if (container_should_be_filtered()) {
+    if (container_should_be_filtered()) {
```

`do_ret_sys_execve()` 함수 내 임베디드 BPF C 문자열에서 선행 공백이 1칸 줄어들었습니다.
BPF 컴파일에는 영향이 없지만, 커밋 메시지에 언급이 없는 비의도적 변경으로 보입니다.

**권장 조치**: 이 hunk를 되돌려 PR의 변경 범위를 오타 수정 1개로 한정할 것.
공백 정렬이 의도적이라면 커밋 메시지에 명시해야 합니다.

### 🟡 Notice — 함수 내 지역 변수에도 동일 오타 존재 (Line 110)

`check_cpu_field()` 함수 내부에 `filed_in_task_struct` 라는 지역 변수가 남아 있습니다.
외부에 노출되지 않아 기능 영향은 없으나, 이번 PR의 취지에 맞춰
`field_in_task_struct`로 함께 수정하는 것을 고려할 수 있습니다.

---

## 결론

변경 규모가 작고 위험도가 없는 타당한 오타 수정 PR입니다.
Line 212의 무관한 공백 변경을 제거하면 바로 머지 가능합니다.

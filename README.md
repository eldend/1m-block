# 🛡️ 유해 사이트 차단 프로그램

이 프로그램은 **Netfilter Queue**를 이용하여 HTTP 패킷의 `Host` 헤더를 검사하고,
`top-1m.csv` 파일에 포함된 도메인을 기반으로 유해 사이트를 실시간 차단하는 기능을 제공합니다.

---

## ⚙️ 실행 방법

```bash
$ g++ -o 1m-block 1m-block.cpp -lnetfilter_queue -lnet
$ sudo iptables -F
$ sudo iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
$ sudo iptables -A INPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0
$ sudo ./1m-block top-1m.csv
```

- `curl` 명령어로 테스트 가능

---

## 🔍 성능 측정 결과 비교

| 항목           | 단일 hash_map              | prefix 기반 hash_map 최적화 |
|----------------|-----------------------------|------------------------------|
| 차단 목록 로딩 | 약 500ms                    | 약 500ms                     |
| 메모리 사용량  | 전체 메모리의 약 1.2% (≈98MB) | 동일                          |
| 평균 검색 시간 | 약 200,000 ns (0.2ms)       | 약 153,000 ns (0.15ms)       |

---

## 📈 상세 결과

### 🔹 hash_map 기본 구조

#### ✅ 차단 목록 로딩 시간
- 측정 기준: `std::chrono::high_resolution_clock`
- 결과:

![기본_로딩](https://github.com/user-attachments/assets/a7215f4e-e737-4664-a4ff-e6d06348ca91)

#### ✅ 메모리 사용량
- 명령어: `$ top -p $(pgrep 1m-block)`
- 결과:

![기본_메모리](https://github.com/user-attachments/assets/4ebe5c0c-1823-4a9b-af83-481512e6bcd8)

#### ✅ 검색 속도
- 측정 대상: `google.com`
- 측정 기준: `unordered_map.find()` + `chrono::nanoseconds`
- 결과:

![기본_속도](https://github.com/user-attachments/assets/67a57603-ca90-4cc9-a9d3-7dff892ad0a9)

---

### 🔹 prefix 기반 hash_map (기수 탐색 최적화)

#### ✅ 차단 목록 로딩 시간

![기수_로딩](https://github.com/user-attachments/assets/ba66e276-61a1-487b-aa5d-6c3b296ea80d)

#### ✅ 메모리 사용량

![기수_메모리](https://github.com/user-attachments/assets/d4536a33-ad7d-49d0-89d0-06c407867f4c)

#### ✅ 검색 속도

![기수_속도](https://github.com/user-attachments/assets/be04364f-90f3-4a21-9467-7289b534fc6a)

---

## ✅ 요약

- **기본 hash_map보다**, **prefix 분류를 적용하면 탐색 속도 약 25% 향상**

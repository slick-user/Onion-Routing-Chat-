# Benchmark results

Generated 2026-11-13 18:54 UTC on Linux x86_64, Python 3.12.3 by `python main.py benchmark`.
All services run in one process, so compare rows with each other rather than with real networks.

## 1. RSA key size vs. speed

| RSA key | Key generation (per key) | Build onion | Alice → Bob end to end | Strength |
|---|---|---|---|---|
| 2048 | 517.9 ms | 1.12 ms | 224.69 ms | ~112-bit security |
| 3072 | 2091.6 ms | 1.51 ms | 219.63 ms | ~128-bit security (default) |
| 4096 | 3137.8 ms | 1.73 ms | 243.48 ms | ~140-bit security |

## 2. Fixed-size cells vs. bandwidth (cell = 18432 bytes)

| Message | Bytes per link without padding (A, B, C, Bob) | Total | Total with padding | Overhead |
|---|---|---|---|---|
| 10 chars | 4431, 2799, 1575, 663 | 9468 | 73728 | 7.79× |
| 500 chars | 5971, 3955, 2443, 1315 | 13684 | 73728 | 5.39× |
| 2000 chars | 10711, 7511, 5111, 3315 | 26648 | 73728 | 2.77× |
| 4000 chars | 17039, 12255, 8667, 5983 | 43944 | 73728 | 1.68× |

Without padding, sizes shrink at every hop (revealing the hop position) and grow with message length
(letting an observer match packets). With padding every link carries exactly one cell.

## 3. Mixing delay vs. timing attack

| Max mixing delay per relay | Timing attack accuracy | Size attack accuracy | Average latency |
|---|---|---|---|
| 0 ms | 100% | 25% | 231.0 ms |
| 50 ms | 100% | 12% | 1100.5 ms |
| 100 ms | 54% | 29% | 1056.7 ms |
| 250 ms | 58% | 8% | 1024.1 ms |
| 500 ms | 21% | 21% | 1263.6 ms |

A blind guess is right 17% of the time.

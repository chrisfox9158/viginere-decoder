# Vigenere Cipher Decoder

## Purpose
A command-line tool that recovers the key and plaintext from Vigenere-cipher encrypted ciphertext. Given only the ciphertext, the tool identifies the most likely key length, then brute-forces the actual key using classical frequency analysis. As such, brute-forcing of the full keyspace is avoided, allowing for faster, more efficient plaintext recovery.

## Overview
This tool was built while working through classical cryptanalysis problems in CTF challenges. In these challenges, unknown ciphertext often appears with minimal context. In one challenge, an 18-character Vigenere key was solved using primitive techniques: an extremely basic brute-force script and pattern alignment of visually-recognizable plaintext sections to possible keylengths. This process, while successful, proved that consistent, automated decoding of Vigenere ciphertext likely required a more efficient strategy.

## Explanation
The tool combines three classical cryptanalysis techniques into a single pipeline:
- **Kasiski Examination** — The ciphertext is scanned for repeated 3+ character sequences and records the distances between them. As repeats in the plaintext will produce repeats in ciphertext at the same relative key positions, these distances often share common factors with true keylength.
- **Index of Coincidence (IoC)** — For each candidate keylength from the Kasiski examination, the ciphertext is split into interleaved columns. Within these columns, letter distribution is measured for "clustering". Any column presumably correct, therefore encoded with a single consistent Caesar shift, appears statistically like genuine English language. Therefore, the correct keylength usually produces the highest average IoC across all columns.
- **Chi-squared Frequency Analysis** — Once the keylength is fixed, this technique brute-forces all 26 possible Caesar shifts for each column, then scores each by overall standard English letter-frequency similarity. From here, the correct key can be assembled from each sequential Caesar shift, and the plaintext is fully decoded.

## Limitations
While effective, this tool is a heuristic-based cryptanalysis pipeline. Each stage is a statistical technique and can fail independently on unfavorable input. Therefore, some known limitations exist:
- **Ciphertext length relative to keylength** — In testing, reliable key recovery required around 30 characters of ciphertext for each character of keylength, regardless of full keylength. Underneath that threshold, results become unreliable; in CTF contexts, this often renders the tool less effective, as relatively short flags and messages are common. 
- **Printed chi-squared score at short lengths** — In testing, ciphertext below the reliability threshold frequently produced an incorrect key with a score that still measured "strong" (`<50`). Thus, a low score is encouraging, rather than definitive; still, this can be quickly checked by verifying the human-readability of the decoded plaintext.
- **`max_key_length` can bound findings** — A key exceeding the provided keylength (default: `20`) will not be revealed, and no error system exists to indicate this. To combat this issue, the `max_key_length` should be raised if initial testing proves inconclusive.

## Setup
```bash
uv venv
uv sync
```

## Usage
```bash
uv run python vigenere_analysis.py
```

Prompts for the ciphertext, then a series of tuning parameters (sequence length, max key length, candidate pool size, etc.). To select default parameters, press enter for each. Upon completion, the script outputs the detected key length, the best-scoring key(s) found, and their decoded plaintext.
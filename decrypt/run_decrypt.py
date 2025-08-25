import sys, re, math
from collections import Counter

def entropy(b: bytes) -> float:
    n = len(b)
    return -sum((v/n) * math.log2(v/n) for v in Counter(b).values()) if n else 0.0

def looks_b64(b: bytes) -> bool:
    s = b.strip()
    return bool(re.fullmatch(rb'[A-Za-z0-9+/=\s]+', s)) and len(s.replace(b'\n', b'')) % 4 == 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file>")
        sys.exit(1)

    data = open(sys.argv[1], 'rb').read()
    print("len=", len(data),
          "mod16=", len(data) % 16 == 0,
          "entropy≈", round(entropy(data), 3),
          "base64-like=", looks_b64(data))
import re
import sys

_NUM = re.compile(r"^-?\d*(\.\d+)?$")

def parse_amount(s: str) -> float:
    # "refactor": accept thousands separators, tolerate empty
    s = s.replace(",", "")
    if not _NUM.match(s):
        raise ValueError(f"invalid amount: {s!r}")
    return float(s) if s else 0.0

if __name__ == "__main__":
    try:
        print(parse_amount(sys.argv[1]))
    except (ValueError, IndexError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

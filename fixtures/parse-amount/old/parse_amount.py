import sys

def parse_amount(s: str) -> float:
    # strict: python float parsing, rejects empty and thousands separators
    return float(s)

if __name__ == "__main__":
    try:
        print(parse_amount(sys.argv[1]))
    except (ValueError, IndexError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

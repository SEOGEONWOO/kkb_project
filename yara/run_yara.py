import os
import sys
import yara


def print_match(m):
    print(f"[+] {m.rule} hits={len(m.strings)}")
    shown = 0
    for s in m.strings:
        if shown >= 3:
            break
        # yara-python 4.x: s has .identifier and .instances
        if hasattr(s, "instances"):
            for inst in s.instances:
                print(f"    {s.identifier}@{inst.offset}")
                shown += 1
                if shown >= 3:
                    break
        else:
            # older tuple form: (offset, identifier, data)
            off, ident, _ = s
            print(f"    {ident}@{off}")
            shown += 1
    if len(m.strings) == 0:
        print("    (matched via non-string condition)")


def main(rule_path: str, target_path: str) -> None:
    try:
        rules = yara.compile(filepath=rule_path, externals={"ext_filename": ""})
    except yara.Error as e:
        print(f"[!] YARA compile error: {e}")
        return

    # inject ext_filename based on basename of target
    externals = {"ext_filename": os.path.basename(target_path)}

    try:
        matches = rules.match(target_path, timeout=60, externals=externals)
    except yara.TimeoutError:
        print(f"[!] YARA match timeout for {target_path}")
        return
    except yara.Error as e:
        print(f"[!] YARA match error: {e}")
        return

    print(f"[YARA] rules={os.path.basename(rule_path)} target={target_path}")

    if not matches:
        print("[-] No matches.")
        return

    # drop smoke/fallback; dedup by (namespace, rule)
    seen = set()
    filtered = []
    for m in matches:
        tags = set(getattr(m, "tags", []))
        if {"smoke", "fallback"} & tags:
            continue
        key = (m.namespace, m.rule)
        if key not in seen:
            seen.add(key)
            filtered.append(m)

    if not filtered:
        print("[-] No matches (after filtering smoke/fallback).")
        return

    for m in sorted(filtered, key=lambda x: x.rule.lower()):
        print_match(m)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        exe = os.path.basename(sys.argv[0])
        print(f"Usage: python {exe} <rule_file> <target_file>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])

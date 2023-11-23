import subprocess
import os
from datetime import datetime
from pathlib import Path
import csv
import re
import argparse
import sys


PASSWORD_STORE_DIR = Path(
    os.environ.get("PASSWORD_STORE_DIR", "~/.password-store")
).expanduser()

TAG_RE = re.compile(r": ?")


def to_row(path: Path) -> dict[str, str]:
    stat = path.stat()
    created = datetime.fromtimestamp(stat.st_ctime)
    lastmod = datetime.fromtimestamp(stat.st_mtime)

    res = subprocess.run(
        ["gpg", "--decrypt", "-q", path], capture_output=True, text=True
    )
    res.check_returncode()
    lines = res.stdout.splitlines()

    row = {
        "Group": str(path.parent.relative_to(PASSWORD_STORE_DIR)),
        "Title": path.stem,
        "Last Modified": lastmod.isoformat(),
        "Created": created.isoformat(),
    }

    if len(lines[0]) > 0:
        row["Password"] = lines[0]

    note_lines = []
    for line in lines[1:]:
        tokens = TAG_RE.split(line, maxsplit=1)
        # If it's a key: value line,
        if len(tokens) == 2:
            tag, value = tokens
            # And it's one of the known keys, save it in the
            # appropriate field and be done with this line.
            if tag == "login":
                row["Username"] = value
                continue
            elif tag == "url":
                row["URL"] = value
                continue
            elif tag == "otpauth":
                row["TOTP"] = "otpauth:" + value
                continue
        # Otherwise save it in the notes field.
        note_lines.append(line)

    if len(note_lines) > 0:
        row["Notes"] = "\n".join(note_lines)

    return row


FIELD_NAMES = [
    "Group",
    "Title",
    "Username",
    "Password",
    "URL",
    "Notes",
    "TOTP",
    "Icon",
    "Last Modified",
    "Created",
]


def parse_subfolder(arg: str) -> Path:
    return PASSWORD_STORE_DIR / Path(arg)


def main():
    parser = argparse.ArgumentParser(
        description="Dump your password-store database into a CSV for importing into KeePassXC.",
        epilog="Will store all unknown `key: value` lines or freeform lines in the `Notes` column.",
    )
    parser.add_argument(
        "--subfolder",
        "-s",
        type=parse_subfolder,
        help="Subfolder in your password store directory to list. This should not contain the full path to the password store. E.g. Use `Work` instead of `~/.password-store/Work`",
    )

    args = parser.parse_args()

    writer = csv.DictWriter(sys.stdout, FIELD_NAMES, dialect="unix")
    writer.writeheader()
    for entry in args.subfolder.rglob("*.gpg"):
        row = to_row(entry)
        writer.writerow(row)


if __name__ == "__main__":
    main()

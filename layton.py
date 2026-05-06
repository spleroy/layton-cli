import argparse
import subprocess
import sys
import re
from pathlib import Path

POSSIBLE_PATTERNS = [
    (r"\b[A-Z]{2,10}\{[^}]+\}", "Flag-like string"),
    (r"[A-Za-z0-9+/]{40,}={0,2}", "Possible base64"),
    (r"https?://\S+", "URL"),
    (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "Email"),
]

def run_file(path):
    result = subprocess.run(["file", path], capture_output=True, text=True)
    return result.stdout.strip()

def run_exiftool(path):
    result = subprocess.run(["exiftool", path], capture_output=True, text=True)
    return result.stdout.strip()

def run_strings(path):
    result = subprocess.run(["strings", "-n", "8", path], capture_output=True, text=True)
    return result.stdout.strip()

def run_binwalk(path):
    result = subprocess.run(["binwalk", path], capture_output=True, text=True)
    return result.stdout.strip()

def find_possible(text):
    findings = []
    for pattern, label in POSSIBLE_PATTERNS:
        for match in re.finditer(pattern, text):
            findings.append(f"  [{label}] {match.group()}")
    return findings

def main():
    parser = argparse.ArgumentParser(description="Analyze a file with several tools")
    parser.add_argument("file", help="file to analyze")
    args = parser.parse_args()

    if not Path(args.file).is_file():
        print(f"ERROR: {args.file} not a valid file", file=sys.stderr)
        sys.exit(1)

    file_output = run_file(args.file)
    exif_output = run_exiftool(args.file)
    strings_output = run_strings(args.file)
    binwalk_output = run_binwalk(args.file)

   #look for interesting patterns in the output of strings and exiftool
    combined = strings_output + "\n" + exif_output
    highlights = find_possible(combined)

    # print highlights first if any were found
    if highlights:
        print("=== HIGHLIGHTS ===")
        for finding in highlights:
            print(finding)
        print()  

    # output results of each tool used
    print("=== File Type ===")
    print(file_output)
    print("\n=== EXIF Data ===")
    print(exif_output)
    print("\n=== Strings ===")
    print(strings_output)
    print("\n=== Binwalk Analysis ===")
    print(binwalk_output)

if __name__ == "__main__":
    main()
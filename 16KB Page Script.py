import os
import subprocess
import sys
import zipfile

def check_so_alignment(so_path):
    try:
        output = subprocess.check_output(
            ["objdump", "-p", so_path],
            stderr=subprocess.DEVNULL,
            text=True
        )
        aligns = []
        for line in output.splitlines():
            if "LOAD" in line and "align" in line:
                parts = line.strip().split()
                for i, p in enumerate(parts):
                    if p == "align":
                        aligns.append(parts[i+1])
        return set(aligns)
    except Exception as e:
        return {"ERROR"}

def scan_directory(directory):
    results = {}
    for root, _, files in os.walk(directory):
        for f in files:
            if f.endswith(".so"):
                path = os.path.join(root, f)
                aligns = check_so_alignment(path)
                results[path] = aligns
    return results

def scan_apk(apk_path, extract_dir="extracted_libs"):
    if os.path.exists(extract_dir):
        import shutil
        shutil.rmtree(extract_dir)
    with zipfile.ZipFile(apk_path, 'r') as z:
        z.extractall(extract_dir)
    return scan_directory(extract_dir)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python check_alignment.py <apk_or_libs_dir>")
        sys.exit(1)

    target = sys.argv[1]
    if os.path.isfile(target) and target.endswith(".apk"):
        results = scan_apk(target)
    else:
        results = scan_directory(target)

    for path, aligns in results.items():
        if "ERROR" in aligns:
            print(f"[ERROR] {path}")
        elif "2**12" in aligns:
            print(f"[4K ONLY] {path} -> {aligns}")
        elif "2**14" in aligns:
            print(f"[16K COMPATIBLE] {path} -> {aligns}")
        else:
            print(f"[UNKNOWN] {path} -> {aligns}")

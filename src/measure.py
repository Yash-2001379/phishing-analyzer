"""
Measure how well the scanner works on emails you already know the answer for.

Usage:
    python src/measure.py samples/phishing samples/legit
    python src/measure.py samples/phishing samples/legit --vt

An email counts as "flagged" if it scores MEDIUM or HIGH.
Duplicate files (same SHA256) are counted once, so the numbers stay honest.
"""
import os
import sys
import hashlib

import report
import vt_client


def file_hash(path):
    """SHA256 of a file, used to spot the same email saved twice."""
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def score_folder(folder, cache, api_key):
    """Score every unique email in a folder. Returns (results, duplicates, failed)."""
    files, _ = report.find_emails(folder)
    seen, results, duplicates, failed = set(), [], 0, []
    for path in files:
        h = file_hash(path)
        if h in seen:
            duplicates += 1
            continue
        seen.add(h)
        try:
            r = report.score_email(path)
        except Exception as e:
            failed.append((os.path.basename(path), str(e)[:60]))
            continue
        if api_key:
            report.add_vt_findings(r, cache, api_key)
        results.append(r)
    return results, duplicates, failed


def pct(part, whole):
    """Percent as text, safe when whole is 0."""
    return f"{100 * part / whole:.1f}%" if whole else "n/a"


def main():
    """Score both folders and print detection rate, false positive rate, and precision."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    args = sys.argv[1:]
    use_vt = "--vt" in args
    args = [a for a in args if a != "--vt"]
    if len(args) != 2 or not all(os.path.isdir(a) for a in args):
        print("Usage: python src/measure.py <phishing folder> <legit folder> [--vt]")
        sys.exit(1)

    api_key, cache = None, {}
    if use_vt:
        api_key = vt_client.load_api_key()
        if not api_key:
            print("--vt needs VT_API_KEY=... in a .env file in the project folder.")
            sys.exit(1)
        cache = vt_client.load_cache()

    try:
        phish, phish_dupes, phish_failed = score_folder(args[0], cache, api_key)
        legit, legit_dupes, legit_failed = score_folder(args[1], cache, api_key)
    except vt_client.VTError as e:
        print(f"VirusTotal stopped: {e}. Run again without --vt, or try later.")
        sys.exit(1)

    # The four boxes of a confusion matrix, in plain words
    caught = [r for r in phish if r["verdict"] != "LOW"]      # true positives
    missed = [r for r in phish if r["verdict"] == "LOW"]      # false negatives
    false_alarms = [r for r in legit if r["verdict"] != "LOW"]  # false positives
    correct_legit = len(legit) - len(false_alarms)           # true negatives

    mode = "with VirusTotal" if use_vt else "rules only"
    print(f"\nRESULTS ({mode})")
    print(f"  Phishing emails tested    {len(phish)}")
    print(f"  Legit emails tested       {len(legit)}")
    print()
    print(f"  Detection rate            {len(caught)}/{len(phish)}  {pct(len(caught), len(phish))}"
          "   phishing flagged MEDIUM or HIGH")
    print(f"  False positive rate       {len(false_alarms)}/{len(legit)}  {pct(len(false_alarms), len(legit))}"
          "   legit emails wrongly flagged")
    print(f"  Precision                 {pct(len(caught), len(caught) + len(false_alarms))}"
          "   of flagged emails, how many were really phishing")
    print()
    print(f"  Phishing by verdict       HIGH {sum(r['verdict'] == 'HIGH' for r in phish)}"
          f"   MEDIUM {sum(r['verdict'] == 'MEDIUM' for r in phish)}   LOW {len(missed)}")
    print(f"  Legit correctly LOW       {correct_legit}/{len(legit)}")

    if missed:
        print("\nMISSED PHISHING (scored LOW)")
        for r in sorted(missed, key=lambda x: -x["score"]):
            print(f"  {r['score']:>2}  {report.clean(r['headers']['subject'], 60) or '(no subject)'}")
    if false_alarms:
        print("\nFALSE ALARMS (legit flagged)")
        for r in sorted(false_alarms, key=lambda x: -x["score"]):
            print(f"  {r['verdict']:<6} {r['score']:>2}  {report.clean(r['headers']['subject'], 55) or '(no subject)'}")
    if phish_dupes or legit_dupes:
        print(f"\nSkipped duplicates: {phish_dupes} phishing, {legit_dupes} legit")
    for name, why in phish_failed + legit_failed:
        print(f"Couldn't read {report.clean(name, 40)}: {why}")


if __name__ == "__main__":
    main()

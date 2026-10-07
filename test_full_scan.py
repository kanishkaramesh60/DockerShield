from dockershield.core.scanner import run_full_scan

result = run_full_scan()

print("\nSCAN SUMMARY")
print(result["scan_summary"])

print("\nRISK")
print(result["risk"])

print("\nML")
print(result["ml_prediction"])
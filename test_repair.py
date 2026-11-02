from repair import repair_code
from verifier import verify_code

task = """
Write a Python function called is_even(n).
It should return True if n is even and False otherwise.
"""

faulty_code = """
def is_even(n):
    return n % 2 != 0
"""

failure_report = {
    "verified": False,
    "passed": 0,
    "failed": 4
}

print("Generating repair...")

corrected_code = repair_code(
    task,
    faulty_code,
    failure_report
)

print("\nRepaired code:")
print(corrected_code)

print("\nVerifying repaired code...")

result = verify_code(corrected_code)

print("\n========== REPAIR REPORT ==========")
print("Verified:", result["verified"])

if "error" not in result:
    print("Tests passed:", result["passed"])
    print("Tests failed:", result["failed"])

print("===================================")
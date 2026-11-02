from verifier import verify_code

faulty_code = """
def is_even(n):
    if n == 0:
        return False
    return n % 2 == 0
"""

result = verify_code(faulty_code)

print("\n========== FAILURE TEST ==========")
print("Verification status:", result["verified"])
print("Tests passed:", result["passed"])
print("Tests failed:", result["failed"])
print("==================================")
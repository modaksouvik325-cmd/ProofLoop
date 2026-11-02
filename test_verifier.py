from verifier import verify_code

sample_code = """
def is_prime(n):
    if n < 2:
        return False

    for i in range(2, n):
        if n % i == 0:
            return False

    return True
"""

test_cases = [
    ((2,), True),
    ((7,), True),
    ((9,), False),
    ((1,), False),
    ((13,), True),
    ((0,), False)
]

result = verify_code(
    sample_code,
    "is_prime",
    test_cases
)

print(result)
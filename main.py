
from generator import generate_code
from repair import repair_code
from verifier import verify_code


def print_report(result, stage):

    print(f"\n========== {stage} REPORT ==========")
    print("Verification status:", result["verified"])

    if "error" in result:
        print("Error:", result["error"])
    else:
        print("Tests passed:", result["passed"])
        print("Tests failed:", result["failed"])

        for test in result["results"]:
            print(test)

    print("=" * 40)


def run_proofloop(task, function_name, test_cases):

    MAX_REPAIR_ATTEMPTS = 3

    print("\n[1] Creation Agent: generating and self-reviewing...")

    current_code = generate_code(task)

    print("\n[2] Creator submission:")
    print(current_code)

    for attempt in range(MAX_REPAIR_ATTEMPTS + 1):

        print(f"\n[3] Independent verification: {attempt + 1}")

        result = verify_code(
            current_code,
            function_name,
            test_cases
        )

        print_report(result, f"VERIFICATION {attempt + 1}")

        if result["verified"]:
            print("\nPROOFLOOP: IMPLEMENTATION VERIFIED")

            return {
                "verified": True,
                "final_code": current_code,
                "repair_attempts": attempt,
                "final_result": result
            }

        if attempt == MAX_REPAIR_ATTEMPTS:
            print("\nPROOFLOOP: REPAIR LIMIT REACHED")
            break

        print(
            f"\n[4] Independent Challenger: "
            f"repair attempt {attempt + 1}"
        )

        current_code = repair_code(
            task,
            current_code,
            result
        )

        print("\n[5] Challenger proposal:")
        print(current_code)

    return {
        "verified": False,
        "final_code": current_code,
        "repair_attempts": MAX_REPAIR_ATTEMPTS,
        "final_result": result
    }


if __name__ == "__main__":

    task = """
    Write a Python function called is_even(n).
    It should return True if n is even and False otherwise.
    """

    test_cases = [
        ([2], True),
        ([3], False),
        ([0], True),
        ([-4], True),
        ([-3], False)
    ]

    run_proofloop(
        task,
        "is_even",
        test_cases
    )

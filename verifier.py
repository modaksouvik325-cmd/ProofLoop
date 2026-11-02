import json
from executor import execute_with_test_runner


def verify_code(code, function_name, test_cases):

    test_runner = """
import json
import generated

function_name = __FUNCTION_NAME__
test_cases = json.loads(__TEST_CASES__)

function = getattr(generated, function_name)

results = []

for inputs, expected in test_cases:
    try:
        actual = function(*inputs)

        results.append({
            "inputs": inputs,
            "expected": expected,
            "actual": actual,
            "passed": actual == expected
        })

    except Exception as error:
        results.append({
            "inputs": inputs,
            "expected": expected,
            "passed": False,
            "error": str(error)
        })

print(json.dumps(results))
"""

    test_runner = test_runner.replace(
        "__FUNCTION_NAME__",
        json.dumps(function_name)
    )

    test_runner = test_runner.replace(
    "__TEST_CASES__",
    repr(json.dumps(test_cases))
)

    execution = execute_with_test_runner(code, test_runner)

    if not execution["success"]:
        return {
            "verified": False,
            "error": execution["error"]
        }

    try:
        results = json.loads(execution["output"])

        passed = sum(
            1 for result in results
            if result["passed"]
        )

        return {
            "verified": passed == len(results),
            "passed": passed,
            "failed": len(results) - passed,
            "results": results
        }

    except (json.JSONDecodeError, KeyError):
        return {
            "verified": False,
            "error": "Invalid verification output"
        }
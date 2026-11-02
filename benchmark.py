
import json
import time
from pathlib import Path

from model_client import generate_response


# Load benchmark dataset
dataset_path = Path("benchmarks/security_tasks.json")

with dataset_path.open("r", encoding="utf-8") as file:
    tasks = json.load(file)


results = []

print("\n========== PROOFLOOP MODEL BENCHMARK ==========\n")

for task in tasks:

    print(f"Running: {task['id']} - {task['title']}")

    messages = [
        {
            "role": "system",
            "content": """
You are a cybersecurity code analysis assistant.

Analyse the supplied Python code for security vulnerabilities.

For each finding, explain:
1. Vulnerability name.
2. Why it is dangerous.
3. Severity.
4. Recommended remediation.

Do not invent vulnerabilities.
Distinguish confirmed issues from context-dependent risks.
"""
        },
        {
            "role": "user",
            "content": f"""
Analyse this code:

{task['code']}
"""
        }
    ]

    start_time = time.perf_counter()

    try:
        response = generate_response(messages)

        duration = time.perf_counter() - start_time

        result = {
            "id": task["id"],
            "title": task["title"],
            "expected_findings": task["expected_findings"],
            "model_response": response,
            "latency_seconds": round(duration, 2),
            "status": "completed"
        }

    except Exception as error:
        result = {
            "id": task["id"],
            "title": task["title"],
            "error": str(error),
            "status": "failed"
        }

    results.append(result)

    print(f"Status: {result['status']}")

    if result["status"] == "completed":
        print(f"Response time: {result['latency_seconds']} seconds")

    print("-" * 45)


# Save benchmark results
output_path = Path("benchmarks/results.json")

with output_path.open("w", encoding="utf-8") as file:
    json.dump(results, file, indent=4)

print("\nBenchmark completed.")
print(f"Results saved to: {output_path}")

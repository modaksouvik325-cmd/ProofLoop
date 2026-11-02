
from model_client import generate_response
from generator import clean_generated_code


def repair_code(task, previous_code, failure_report, provider=None):
    repair_messages = [
        {
            "role": "system",
            "content": (
                "You are an independent Python software repair engineer. "
                "You did not create the original implementation. "
                "Analyse all verification evidence carefully. "
                "Identify the underlying logical or runtime errors. "
                "Address every failed test case, not just one symptom. "
                "Preserve the original requirements and function signature. "
                "Never change, remove, or invent test cases. "
                "Return only complete executable Python code. "
                "Do not include Markdown or explanations."
            )
        },
        {
            "role": "user",
            "content": (
                f"ORIGINAL TASK:\n{task}\n\n"
                f"PREVIOUS IMPLEMENTATION:\n{previous_code}\n\n"
                f"COMPLETE VERIFICATION REPORT:\n{failure_report}\n\n"
                "Repair the implementation so that it satisfies "
                "the original requirements and all failed test cases."
            )
        }
    ]

    corrected_code = generate_response(
        repair_messages,
        provider=provider
    )

    return clean_generated_code(corrected_code)


from model_client import generate_response
import re


def clean_generated_code(code):
    code = code.strip()

    match = re.search(
        r"```(?:python)?\s*(.*?)```",
        code,
        flags=re.DOTALL | re.IGNORECASE
    )

    if match:
        return match.group(1).strip()

    lines = code.splitlines()

    for index, line in enumerate(lines):
        if line.strip().startswith(
            ("def ", "class ", "import ", "from ")
        ):
            return "\n".join(lines[index:]).strip()

    return code


def generate_code(task, provider=None):
    messages = [
        {
            "role": "system",
            "content": (
                "You are a Python software engineer. "
                "Return only executable Python code. "
                "Do not include Markdown."
            )
        },
        {
            "role": "user",
            "content": task
        }
    ]

    initial_code = generate_response(
        messages,
        provider=provider
    )

    initial_code = clean_generated_code(initial_code)

    review_messages = [
        {
            "role": "system",
            "content": (
                "You are reviewing your own Python implementation. "
                "Check it against the original requirements. "
                "Look for logical errors, edge cases, and missing behavior. "
                "Improve the implementation if necessary. "
                "Return ONLY the complete corrected Python source code. "
                "Do not explain your reasoning. "
                "Do not include introductions, conclusions, or Markdown fences. "
                "Your entire response must be executable Python code."
            )
        },
        {
            "role": "user",
            "content": (
                f"ORIGINAL TASK:\n{task}\n\n"
                f"YOUR INITIAL IMPLEMENTATION:\n{initial_code}\n\n"
                "Review and improve your implementation."
            )
        }
    ]

    reviewed_code = generate_response(
        review_messages,
        provider=provider
    )

    return clean_generated_code(reviewed_code)


if __name__ == "__main__":
    task = """
    Write a Python function called is_even(n).
    It should return True if n is even and False otherwise.
    """

    code = generate_code(task)
    print("Generated and self-reviewed code:")
    print(code)

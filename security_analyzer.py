"""AI explanations for scanner findings. Scanner evidence remains authoritative."""
import json
import re
from model_client import generate_response


def _parse_json_object(response):
    text = (response or "").strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, flags=re.IGNORECASE | re.DOTALL)
    if fence:
        text = fence.group(1).strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("The AI response did not contain a JSON object.")
    payload = json.loads(text[start:end + 1])
    if not isinstance(payload, dict):
        raise ValueError("The AI response must be a JSON object.")
    return payload


def analyze_security_findings(scan_report):
    findings = scan_report.get("bandit", {}).get("findings", [])
    if not findings:
        return {
            "status": "no_findings",
            "analysis": "No Bandit findings were returned.",
            "findings": [],
        }

    indexed_findings = []
    for index, finding in enumerate(findings, start=1):
        indexed_findings.append({
            "finding_index": index,
            **finding,
        })

    messages = [
        {
            "role": "system",
            "content": """
You are a senior application security analyst. Analyse the supplied static-analysis findings.

STRICT REQUIREMENTS:
1. Return exactly one analysis for every supplied finding.
2. Preserve finding_index and rule_id exactly. finding_index distinguishes repeated instances of the same rule.
3. Never change the scanner's severity or confidence; do not return replacement values for them.
4. Distinguish generic warnings from actionable vulnerabilities.
5. Explain realistic attack scenarios without inventing context.
6. Give specific, technically correct remediation.
7. Prefer safe APIs and secure coding patterns.
8. Do not claim exploitability without sufficient evidence.
9. Do not claim code has been fixed or verified.
10. Return valid JSON only, with no Markdown fences.

Return exactly this structure:
{
  "findings": [
    {
      "finding_index": 1,
      "rule_id": "B602",
      "assessment": "confirmed or context-dependent",
      "risk_explanation": "Explanation",
      "potential_impact": "Potential impact",
      "remediation": "Specific remediation"
    }
  ]
}
""",
        },
        {
            "role": "user",
            "content": json.dumps(indexed_findings, indent=2, default=str),
        },
    ]

    try:
        response = generate_response(messages)
        analysis = _parse_json_object(response)
        analyzed_findings = analysis.get("findings")
        if not isinstance(analyzed_findings, list):
            raise ValueError("Missing findings list.")

        expected = {
            item["finding_index"]: item.get("rule_id")
            for item in indexed_findings
        }
        returned = {}
        for item in analyzed_findings:
            if not isinstance(item, dict):
                raise ValueError("An analysis entry is not an object.")
            index = item.get("finding_index")
            if not isinstance(index, int) or index not in expected:
                raise ValueError("Missing or unexpected finding index.")
            if index in returned:
                raise ValueError("Duplicate finding index.")
            if item.get("rule_id") != expected[index]:
                raise ValueError("The AI changed a scanner rule ID.")
            required = ("assessment", "risk_explanation", "potential_impact", "remediation")
            if not all(isinstance(item.get(field), str) and item[field].strip() for field in required):
                raise ValueError(f"Finding {index} has missing or invalid analysis fields.")
            if item["assessment"] not in ("confirmed", "context-dependent"):
                raise ValueError(f"Finding {index} has an invalid assessment.")
            returned[index] = item

        if set(returned) != set(expected):
            missing = sorted(set(expected) - set(returned))
            raise ValueError(f"AI omitted finding indices: {missing}")

        # Preserve scanner order for deterministic UI rendering.
        analysis["findings"] = [returned[i] for i in sorted(returned)]
        return {
            "status": "completed",
            "analysis": analysis,
            "findings": findings,
        }
    except Exception as error:
        return {
            "status": "analysis_failed",
            "error": f"{type(error).__name__}: {error}",
            "analysis": None,
            "findings": findings,
        }

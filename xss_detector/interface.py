"""
GenAI Interface for XSS Detection Engine
"""

# When running this file directly, adjust imports for local context
if __name__ == '__main__' and __package__ is None:
    from engine import find_xss_in_html, find_xss_in_javascript, XSSContext
else:
    from .engine import find_xss_in_html, find_xss_in_javascript, XSSContext

def analyze_code_for_xss(code_snippet: str, language: str = "html") -> dict:
    """
    Analyzes a code snippet for XSS vulnerabilities and returns a structured response
    suitable for a GenAI model.

    Args:
        code_snippet (str): The code snippet to analyze.
        language (str): The language of the code snippet ("html" or "javascript").

    Returns:
        dict: A dictionary containing:
            - "language_detected": The language processed.
            - "vulnerability_count": Number of potential vulnerabilities found.
            - "findings": A list of dictionaries, where each dictionary represents an XSSContext.
            - "summary": A brief textual summary of the findings.
            - "error": An error message if an issue occurred, None otherwise.
    """
    findings_list = []
    error_message = None
    summary = ""

    try:
        if language.lower() == "html":
            results: list[XSSContext] = find_xss_in_html(code_snippet)
        elif language.lower() == "javascript":
            results: list[XSSContext] = find_xss_in_javascript(code_snippet)
        else:
            error_message = f"Unsupported language: {language}. Please use 'html' or 'javascript'."
            results = []

        for res_obj in results:
            findings_list.append({
                "finding_type": res_obj.finding_type,
                "payload": res_obj.payload,
                "tag": res_obj.tag,
                "attribute": res_obj.attribute,
                "line_number": res_obj.line_number,
                "surrounding_code": res_obj.surrounding_code,
            })

        vulnerability_count = len(findings_list)

        if vulnerability_count > 0:
            summary = f"Found {vulnerability_count} potential XSS vulnerabilit{'ies' if vulnerability_count > 1 else 'y'}."
            # GenAI could expand on this summary based on the findings_list.
        else:
            summary = "No potential XSS vulnerabilities found by the current engine."

    except Exception as e:
        error_message = f"An error occurred during analysis: {str(e)}"
        results = []
        vulnerability_count = 0
        summary = "Analysis could not be completed due to an error."


    return {
        "language_analyzed": language,
        "vulnerability_count": len(findings_list),
        "findings": findings_list,
        "summary": summary,
        "error": error_message,
    }

if __name__ == '__main__':
    print("Testing GenAI Interface...")

    sample_html_vulnerable = "<html><body><img src='x' onerror='alert(\"XSS\")'></body></html>"
    sample_html_clean = "<p>This is a clean HTML snippet.</p>"
    sample_js_vulnerable = "document.write('<script>malicious()</script>');"
    sample_js_clean = "console.log('This is clean JavaScript.');"
    unsupported_lang_snippet = "print('This is Python')"

    print("\n--- HTML Vulnerable ---")
    response_html_vuln = analyze_code_for_xss(sample_html_vulnerable, "html")
    import json
    print(json.dumps(response_html_vuln, indent=2))

    print("\n--- HTML Clean ---")
    response_html_clean = analyze_code_for_xss(sample_html_clean, "html")
    print(json.dumps(response_html_clean, indent=2))

    print("\n--- JavaScript Vulnerable ---")
    response_js_vuln = analyze_code_for_xss(sample_js_vulnerable, "javascript")
    print(json.dumps(response_js_vuln, indent=2))

    print("\n--- JavaScript Clean ---")
    response_js_clean = analyze_code_for_xss(sample_js_clean, "javascript")
    print(json.dumps(response_js_clean, indent=2))

    print("\n--- Unsupported Language ---")
    response_unsupported = analyze_code_for_xss(unsupported_lang_snippet, "python")
    print(json.dumps(response_unsupported, indent=2))

    print("\n--- HTML with Internal Error (simulated by passing non-string) ---")
    # response_error = analyze_code_for_xss(None, "html") # type: ignore
    # print(json.dumps(response_error, indent=2))
    # Note: The above line will cause a type error with linters,
    # actual error handling in find_xss_in_html would catch runtime issues.
    # For now, we assume valid string input to `analyze_code_for_xss`
    # and errors are caught from within the engine functions if they occur.

    print("\nInterface testing finished.")

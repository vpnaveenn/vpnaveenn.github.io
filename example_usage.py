import json
from xss_detector import analyze_code_for_xss

def demonstrate_xss_analysis(code_snippet, language):
    """
    Demonstrates calling the XSS analysis function and printing its output.
    This simulates how a GenAI orchestrator would use the xss_detector.
    """
    print(f"\n--- Analyzing {language} snippet ---")
    print("Code:")
    print(code_snippet)

    analysis_result = analyze_code_for_xss(code_snippet, language)

    print("\nAnalysis Output (JSON for GenAI consumption):")
    print(json.dumps(analysis_result, indent=2))

    # --- GenAI Interpretation (Simulated) ---
    # In a real scenario, the GenAI (like me) would take `analysis_result`
    # and generate a more detailed, contextual explanation.
    # For example:
    print("\n--- GenAI Interpretation (Simulated) ---")
    if analysis_result["error"]:
        print(f"Error during analysis: {analysis_result['error']}")
    elif analysis_result["vulnerability_count"] > 0:
        print(f"The analysis found {analysis_result['vulnerability_count']} potential XSS issue(s).")
        for i, finding in enumerate(analysis_result["findings"]):
            print(f"\nIssue {i+1}:")
            print(f"  Type: {finding['finding_type']}")
            if finding['tag']:
                print(f"  In Tag: <{finding['tag']}>")
            if finding['attribute']:
                print(f"  In Attribute: {finding['attribute']}")
            print(f"  Suspicious Code: {finding['payload']}")
            if finding['line_number']:
                print(f"  Around Line: {finding['line_number']}")
            print(f"  Surrounding Context: \"...{finding['surrounding_code']}...\"")
            # Here, a real GenAI would add more details:
            # - What does this finding mean?
            # - Why is it a potential vulnerability?
            # - How can it be exploited?
            # - How can it be fixed (general advice, or specific if context allows)?
            if finding['finding_type'] == "javascript_uri":
                print("  Recommendation: Avoid 'javascript:' URIs. Use event handlers with functions instead.")
            elif finding['finding_type'] == "event_handler":
                print("  Recommendation: Ensure that any dynamic data used in event handlers is properly sanitized/encoded if it originates from user input.")
            elif finding['finding_type'] == "script_tag_content" and "eval(" in finding['payload']:
                 print("  Recommendation: Avoid 'eval()'. It's dangerous and often unnecessary. Look for safer alternatives to parse JSON or execute dynamic code.")
    else:
        print("The analysis did not find any potential XSS issues with the provided snippet based on its current rules.")
    print("--- End of Simulated GenAI Interpretation ---")


if __name__ == "__main__":
    sample_html_vulnerable = "<html><head></head><body><img src='x' onerror='alert(\"XSS1\")'> <a href='javascript:alert(\"XSS2\")'>Click</a> <script>eval('badcode')</script></body></html>"
    sample_js_vulnerable = "let data = untrusted_input; document.write(data); setTimeout('exec_danger(\"' + data + '\")', 100);"
    sample_html_clean = "<p>This is perfectly safe.</p>"

    demonstrate_xss_analysis(sample_html_vulnerable, "html")
    demonstrate_xss_analysis(sample_js_vulnerable, "javascript")
    demonstrate_xss_analysis(sample_html_clean, "html")

import json
from xss_detector import analyze_code_for_xss
from xss_detector.reporter import generate_html_report # Import the new function

def demonstrate_xss_analysis_and_report(code_snippet, language, report_filename_base="xss_analysis_report"):
    """
    Demonstrates calling the XSS analysis function, printing its output,
    and generating an HTML report if vulnerabilities are found.
    """
    print(f"\n--- Analyzing {language} snippet for report: {report_filename_base} ---")
    # print("Code:")
    # print(code_snippet) # Keep console output cleaner, code will be in HTML report

    analysis_result = analyze_code_for_xss(code_snippet, language)

    print("\nAnalysis Output (JSON for GenAI consumption):")
    print(json.dumps(analysis_result, indent=2))

    # --- GenAI Interpretation (Simulated) ---
    # This part remains for console demonstration of GenAI's potential textual feedback
    print("\n--- GenAI Interpretation (Simulated Console Output) ---")
    if analysis_result["error"]:
        print(f"Error during analysis: {analysis_result['error']}")
    elif analysis_result["vulnerability_count"] > 0:
        print(f"The analysis found {analysis_result['vulnerability_count']} potential XSS issue(s).")
        # (Detailed console breakdown omitted for brevity as it's now in HTML report)
    else:
        print("The analysis did not find any potential XSS issues with the provided snippet based on its current rules.")
    print("--- End of Simulated GenAI Console Interpretation ---")

    # --- HTML Report Generation ---
    if analysis_result["error"]:
        print(f"\nSkipping HTML report due to analysis error: {analysis_result['error']}")
    elif analysis_result["vulnerability_count"] > 0:
        html_report_content = generate_html_report(analysis_result, code_snippet)
        report_filename = f"{report_filename_base}_{language}.html"
        try:
            with open(report_filename, "w", encoding="utf-8") as f:
                f.write(html_report_content)
            print(f"\nHTML report generated: {report_filename}")
        except IOError as e:
            print(f"\nError saving HTML report {report_filename}: {e}")
    else:
        print("\nNo vulnerabilities found, so no HTML report generated for this snippet.")


if __name__ == "__main__":
    sample_html_vulnerable = "<html><head></head><body><img src='x' onerror='alert(\"XSS1\")'> <a href='javascript:alert(\"XSS2\")'>Click</a> <script>eval('badcode')</script></body></html>"
    sample_js_vulnerable = "let data = untrusted_input; document.write(data); setTimeout('exec_danger(\"' + data + '\")', 100);"
    sample_html_clean = "<p>This is perfectly safe.</p>"
    sample_html_with_style_xss = "<div style=\"background-image: url(javascript:alert('XSS_in_style'))\">Content</div>"

    demonstrate_xss_analysis_and_report(sample_html_vulnerable, "html", "report_html_vulnerable")
    demonstrate_xss_analysis_and_report(sample_js_vulnerable, "javascript", "report_js_vulnerable")
    demonstrate_xss_analysis_and_report(sample_html_clean, "html", "report_html_clean")
    demonstrate_xss_analysis_and_report(sample_html_with_style_xss, "html", "report_html_style_xss")

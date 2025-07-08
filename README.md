# GenAI-Powered XSS Detection Tool

This project provides a Python-based XSS (Cross-Site Scripting) detection engine and an interface designed to be used by a Generative AI model. The GenAI can leverage this tool to analyze code snippets, identify potential XSS vulnerabilities, and then provide users with contextual explanations and remediation advice.

## Features

*   **Core XSS Detection Engine (`xss_detector/engine.py`):**
    *   Analyzes HTML and JavaScript content.
    *   Uses `BeautifulSoup` for robust HTML parsing.
    *   Combines regex-based pattern matching with structural analysis of HTML.
    *   Identifies common XSS vectors:
        *   `<script>` tags and their content.
        *   `javascript:` URIs in attributes like `href`, `src`.
        *   Event handlers (e.g., `onerror`, `onclick`, `onmouseover`).
        *   Basic JavaScript patterns like `document.write()`, `eval()`, `.innerHTML` assignments (JS analysis is basic and marked for future improvement).
    *   Returns detailed `XSSContext` objects for each finding.
*   **GenAI Interface (`xss_detector/interface.py`):**
    *   Provides a simple function `analyze_code_for_xss(code_snippet, language)` tailored for GenAI consumption.
    *   Accepts HTML or JavaScript code snippets.
    *   Returns a structured JSON-friendly dictionary containing:
        *   `language_analyzed`
        *   `vulnerability_count`
        *   `findings`: A list of detailed vulnerability contexts.
        *   `summary`: A brief textual summary.
        *   `error`: Error messages, if any.
*   **Example Usage (`example_usage.py`):**
    *   Demonstrates how to import and use the `analyze_code_for_xss` function.
    *   Shows the format of the data returned by the analysis.
    *   Includes a *simulated* GenAI interpretation of the results to illustrate how a GenAI would process the data and explain it to a user.

## How it Works (Conceptual GenAI Integration)

1.  **User Input:** A user provides a code snippet (HTML or JavaScript) to the GenAI.
2.  **GenAI Calls Detector:** The GenAI, using the `xss_detector` Python package, calls the `analyze_code_for_xss` function with the user's code.
3.  **Analysis:** The XSS detection engine processes the code and identifies potential vulnerabilities.
4.  **Structured Output:** The engine returns a structured JSON output (as shown in `example_usage.py`) to the GenAI.
5.  **GenAI Interpretation & Explanation:** The GenAI receives this structured data and then:
    *   Interprets the findings.
    *   Explains the potential vulnerabilities to the user in natural language.
    *   Provides context on why a particular pattern is dangerous.
    *   Offers general and, where possible, specific advice on how to remediate the identified issues.
    *   Can ask clarifying questions or suggest safer alternatives.

## Setup and Installation

1.  **Prerequisites:**
    *   Python 3.7+
2.  **Clone the repository (if applicable):**
    ```bash
    # git clone <repository-url>
    # cd <repository-directory>
    # For this environment, files are already present.
    ```
3.  **Install dependencies:**
    The primary Python dependency is `BeautifulSoup4`. Ensure it's installed in your Python environment.
    ```bash
    pip install beautifulsoup4
    ```
    (If a `requirements.txt` file were provided, you would use `pip install -r requirements.txt`)

## Usage

The primary way to use this tool is programmatically via the `xss_detector` package, likely orchestrated by a GenAI model or a larger security analysis pipeline.

### From Python

```python
from xss_detector import analyze_code_for_xss
import json

# Example HTML snippet
html_code = "<html><img src=x onerror=alert('XSS!')></html>"
language = "html"

# Analyze the code
analysis_results = analyze_code_for_xss(html_code, language)

# Print the raw JSON output (this is what a GenAI would consume)
print("--- Raw Analysis Output (for GenAI) ---")
print(json.dumps(analysis_results, indent=2))

# --- GenAI would then process `analysis_results` to explain to the user ---
# This part is simulated below and more fully in example_usage.py
print("\n--- Simulated GenAI Explanation ---")
if analysis_results["error"]:
    print(f"GenAI: I encountered an error: {analysis_results['error']}")
elif analysis_results["vulnerability_count"] > 0:
    print(f"GenAI: My analysis found {analysis_results['vulnerability_count']} potential XSS issue(s) in your HTML code.")
    for finding in analysis_results["findings"]:
        # GenAI would provide a much more detailed explanation for each finding here.
        explanation = f"  - A potential '{finding['finding_type']}' was found."
        if finding['tag']:
            explanation += f" It's in a '<{finding['tag']}>' tag"
            if finding['attribute']:
                explanation += f", specifically in the '{finding['attribute']}' attribute."
        explanation += f" The suspicious code snippet is: \"{finding['payload']}\"."
        if finding['line_number']:
            explanation += f" This appears around line {finding['line_number']}."
        print(explanation)
        # GenAI would add: What this means, why it's a risk, how to fix it.
else:
    print("\nGenAI: Based on my current rules, your HTML snippet appears to be clean of common XSS patterns.")
```

### Running the Example Script

To see a more comprehensive demonstration, including a simulated GenAI interpretation of results from various snippets:
```bash
python example_usage.py
```
This script will analyze predefined code snippets (HTML and JavaScript, both vulnerable and clean) and print both the raw analysis data and a simulated user-friendly explanation.

## Project Structure

```
.
├── xss_detector/
│   ├── __init__.py         # Initializes the 'xss_detector' package
│   ├── engine.py           # Contains the core XSS detection logic and the XSSContext class
│   └── interface.py        # Provides the 'analyze_code_for_xss' function for GenAI interaction
├── example_usage.py        # Script demonstrating how to use the package and simulating GenAI interpretation
├── README.md               # This documentation file
├── index.html              # A sample HTML file (used for basic testing by engine.py)
├── swaggerx.json           # (Original file in the repository, not directly used by the XSS tool)
└── swaggerx.yaml           # (Original file in the repository, not directly used by the XSS tool)
```

## Limitations and Future Improvements

This tool provides a foundational framework for XSS detection. Key areas for future enhancement include:

*   **Advanced JavaScript Analysis:** The current JavaScript analysis is primarily regex-based and quite basic. A significant improvement would be to integrate a proper JavaScript parser (e.g., `esprima`, `slimit`) to perform Abstract Syntax Tree (AST) analysis. This would allow for more accurate and context-aware detection of vulnerabilities, especially DOM-based XSS.
*   **Taint Analysis:** The engine does not currently perform taint analysis (i.e., tracking user-supplied input to sensitive functions or "sinks" in the code). Implementing taint analysis is crucial for reducing false positives and accurately identifying exploitable XSS vulnerabilities.
*   **Comprehensive Pattern Set:** The set of XSS regex patterns, lists of dangerous tags, and event handler attributes is not exhaustive. This set should be continuously reviewed and expanded based on evolving XSS techniques.
*   **Contextual Understanding:** While basic context (tag, attribute) is captured, a deeper understanding of the surrounding code, data flow, and frameworks in use would significantly improve accuracy and the relevance of findings.
*   **Dynamic Analysis:** The tool currently performs only static analysis. Integrating dynamic analysis capabilities (e.g., using a headless browser like Selenium or Playwright to execute JavaScript and observe behavior) could uncover more complex XSS vulnerabilities that are missed by static checks alone.
*   **Configuration and Customization:** Allow users to configure rules, sensitivity levels, or define project-specific contexts.
*   **Reduction of False Positives/Negatives:** As with any static analysis tool, especially in its initial stages, there is a likelihood of false positives (flagging safe code as vulnerable) and false negatives (missing actual vulnerabilities). Continuous refinement and testing are needed.
*   **Integration with Security Linters:** Explore integration or learning from established security linters and tools.

## Contributing

Contributions to enhance this XSS detection tool are welcome! If you'd like to contribute, please consider areas like:
*   Expanding and refining XSS detection patterns and rules.
*   Implementing AST-based JavaScript analysis.
*   Researching and adding capabilities for basic taint analysis.
*   Adding more comprehensive test cases for various XSS scenarios.
*   Improving and detailing the documentation.

(Standard open-source contribution practices like creating issues, forking the repository, creating feature branches, and submitting pull requests would be encouraged if this were a public project.)

## License

(Please specify a license if this were to be distributed, e.g., MIT, Apache 2.0). As of now, no license is specified.
If no license is specified, the code is under standard copyright by the author.

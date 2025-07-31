"""
<spec>
The regex detector is a common tool that is used by the detector objects to detect sources/sinks/santiziers via regex.

The class gets initalized with the purpose (source/sink/sanitizer) then load all the regexs for all the languages that are defined along with a default.

The input is a filename, then it will detect the language, use language specific regexs if available, otherwise it will fallback to using the default set of regexs. 

Results are returned as a list of dictionaries
</spec>
"""

import json
import os
import re
from typing import List, Dict, Any


class RegexDetector:
    """RegexDetector for identifying sources, sinks, and sanitizers using regular expressions"""
    
    def __init__(self, purpose: str):
        """
        Initialize the RegexDetector with a specific purpose
        
        Args:
            purpose: One of 'source', 'sink', or 'sanitizer'
            
        Raises:
            ValueError: If purpose is not valid
        """
        valid_purposes = ['source', 'sink', 'sanitizer']
        if purpose not in valid_purposes:
            raise ValueError(f"Invalid purpose: {purpose}. Must be one of {valid_purposes}")
        
        self.purpose = purpose
        self.rules = self._load_rules()
    
    def _load_rules(self) -> Dict[str, Any]:
        """
        Load regex rules from JSON files based on purpose
        
        Returns:
            Dictionary containing rules for each language
        """
        # Determine the rules file based on purpose
        rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'Rules', 'Regex')
        
        if self.purpose == 'source':
            rules_file = os.path.join(rules_dir, 'sources.json')
        elif self.purpose == 'sink':
            rules_file = os.path.join(rules_dir, 'sinks.json')
        else:  # sanitizer
            rules_file = os.path.join(rules_dir, 'sanitizers.json')
        
        with open(rules_file, 'r') as f:
            data = json.load(f)
        
        # Extract the appropriate rules section
        return data.get(f"{self.purpose}s", {})
    
    def _detect_language(self, filename: str) -> str:
        """
        Detect the programming language based on file extension
        
        Args:
            filename: The filename to analyze
            
        Returns:
            Language string or 'default' if unknown
        """
        ext = os.path.splitext(filename)[1].lower()
        
        language_map = {
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.mjs': 'javascript',
            '.py': 'python',
            '.pyw': 'python',
            '.java': 'java',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.php': 'php',
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.cxx': 'cpp',
            '.c': 'cpp'
        }
        
        return language_map.get(ext, 'default')
    
    def detect(self, filename: str) -> List[Dict[str, Any]]:
        """
        Detect patterns in the given file
        
        Args:
            filename: Path to the file to analyze
            
        Returns:
            List of dictionaries containing detection results
            
        Raises:
            FileNotFoundError: If the file doesn't exist
        """
        if not os.path.exists(filename):
            raise FileNotFoundError(f"File not found: {filename}")
        
        # Detect language
        language = self._detect_language(filename)
        
        # Get rules for this language, fallback to default if not available
        rules = self.rules.get(language, self.rules.get('default', []))
        
        results = []
        
        # Read file content
        with open(filename, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Apply each rule
        for rule in rules:
            pattern = rule['pattern']
            regex = re.compile(pattern)
            
            # Check each line
            for line_num, line in enumerate(lines, 1):
                matches = regex.finditer(line)
                
                for match in matches:
                    result = {
                        'type': self.purpose,
                        'name': rule['name'],
                        'line_number': line_num,
                        'match': match.group(0),
                        'confidence': rule.get('confidence', 0.5),
                        'description': rule.get('description', ''),
                        'filename': filename,
                        'line_content': line.strip()
                    }
                    results.append(result)
        
        return results
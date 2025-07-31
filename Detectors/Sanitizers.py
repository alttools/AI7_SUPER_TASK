"""
<spec>
This class uses various tools from `DetectorTools` to detect Sanitizers

A Sanitizer, in taint analysis, is a block of code that cleans up and otherwise protects the codebase from tained user input

The class extends the base class and implements the _thread_regex as well as extends the initalization method to setup the regex detector tool

</spec>
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Detectors import Detector
from DetectorTools.RegexDetector import RegexDetector


class SanitizersDetector(Detector):
    """Detector for identifying sanitizers in code"""
    
    def __init__(self, queue, repo):
        super().__init__(queue, repo)
        self.regex_detector = RegexDetector('sanitizer')
    
    def _thread_regex(self):
        """Thread method that uses RegexDetector to find sanitizers"""
        files = self._get_all_files()
        
        for file_path in files:
            try:
                results = self.regex_detector.detect(file_path)
                
                for result in results:
                    self.queue.put(result)
                    
            except Exception as e:
                pass

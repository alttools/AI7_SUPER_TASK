"""
<spec>
This class uses various tools from `DetectorTools` to detect Sinks

A Sink, in taint analysis, is a block of code that could be vulnerable to exploitation if it is given unsantized input from a user. 

The class extends the base class and implements the _thread_regex as well as extends the initalization method to setup the regex detector tool

</spec>
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Detectors import Detector
from DetectorTools.RegexDetector import RegexDetector


class SinksDetector(Detector):
    """Detector for identifying sinks in code"""
    
    def __init__(self, queue, repo):
        super().__init__(queue, repo)
        self.regex_detector = RegexDetector('sink')
    
    def _thread_regex(self):
        """Thread method that uses RegexDetector to find sinks"""
        files = self._get_all_files()
        
        for file_path in files:
            try:
                results = self.regex_detector.detect(file_path)
                
                for result in results:
                    self.queue.put(result)
                    
            except Exception as e:
                pass

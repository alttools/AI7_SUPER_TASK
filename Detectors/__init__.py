"""
<spec>
This is the abstract parent class for the detectors. 

Each detector works by having multiple detector threads. These threads loop through the individual files of the codebase and look for 'things' such as sources/sinks/santizers.

The goal is to have all common logic in the parent class, this way each child class is as lean as possiable.

The class is initialized with an async queue item and a path to the repo being scanned.

As results come in this class will be parsed and then sent over the async queue with whatever meta data that makes sense.
</spec>
"""

import os
import threading
from abc import ABC, abstractmethod


class Detector(ABC):
    """
    Abstract class for detectors
    """
    def __init__(self, queue, repo):
        self.queue = queue
        self.repo = repo

    def _thread_regex(self):
        """create and use the DetectorTools/RegexDetector tool here against self.repo"""
        pass

    def start_threads(self):
        """Goes through each '_thread_' method and starts that thread"""
        threads = []
        
        for attr_name in dir(self):
            if attr_name.startswith('_thread_'):
                method = getattr(self, attr_name)
                if callable(method):
                    thread = threading.Thread(target=method)
                    thread.start()
                    threads.append(thread)
        
        return threads
    
    def _get_all_files(self, extensions=None):
        """Helper method to get all files in the repo"""
        files = []
        for root, dirs, filenames in os.walk(self.repo):
            for filename in filenames:
                if extensions:
                    if any(filename.endswith(ext) for ext in extensions):
                        files.append(os.path.join(root, filename))
                else:
                    files.append(os.path.join(root, filename))
        return files
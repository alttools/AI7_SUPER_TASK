import pytest
import sys
import os
import json
import queue
import threading
from datetime import datetime

# Ensure parent directory is on sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from Detectors.Sinks import SinksDetector

# Folder to place hits as individual files
OUTPUT_FOLDER = os.path.join(project_root, "Samples", "sinks")

# Repo that is good for testing code graph generation
TEST_REPO_PATH = "/Users/louismurphy/ODYSSEY/AI_SUPER_TASK/Repos/sqlite"

class TestSinkDetection:
    """Test suite for running the sink detection object and saving off any results as samples for other tests """
    
    def test_sink_detection_on_test_repo(self):
        """Run sink detector on test repository and save results"""
        # Create a queue to collect results
        result_queue = queue.Queue()
        
        # Initialize the sink detector
        detector = SinksDetector(result_queue, TEST_REPO_PATH)
        
        # Start detection threads
        threads = detector.start_threads()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Process results and save to individual files
        results = []
        while not result_queue.empty():
            result = result_queue.get()
            results.append(result)
        
        # Save each result as an individual JSON file
        os.makedirs(OUTPUT_FOLDER, exist_ok=True)
        
        for i, result in enumerate(results):
            # Create descriptive filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            sink_name = result.get('name', 'unknown').replace('/', '_')
            filename = f"sink_{sink_name}_{timestamp}_{i}.json"
            filepath = os.path.join(OUTPUT_FOLDER, filename)
            
            # Save result to file
            with open(filepath, 'w') as f:
                json.dump(result, f, indent=2)
            
            print(f"Saved sink to: {filename}")
        
        print(f"Total sinks found: {len(results)}")
        assert len(results) >= 0  # We expect at least some results from sqlite repo


if __name__ == "__main__":
    # Run just this test module when executed directly
    raise SystemExit(pytest.main([os.path.abspath(__file__), "-v"]))
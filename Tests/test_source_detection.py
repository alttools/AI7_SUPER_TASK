import pytest
import sys
import os
import json
import queue
import threading
from datetime import datetime

# Folder to place hits as individual files
OUTPUT_FOLDER = "../Samples/sources"

# Repo that is good for testing code graph generation
TEST_REPO_PATH = "/Users/louismurphy/Library/Mobile Documents/com~apple~CloudDocs/Desktop/ODYSSEY/AI7_SUPER_TASK/../AI_SUPER_TASK/Repos/sqlite"

class TestSourceDetection:
    """Test suite for running the source detection object and saving off any results as samples for other tests """
    
    def setup_method(self):
        """Setup for each test method"""
        # Ensure output folder exists
        output_path = os.path.join(os.path.dirname(__file__), OUTPUT_FOLDER)
        os.makedirs(output_path, exist_ok=True)
        
    def test_run_source_detector(self):
        """Test running the SourcesDetector on the test repository"""
        # Import the detector
        from Detectors.Sources import SourcesDetector
        
        # Create a queue to collect results
        result_queue = queue.Queue()
        
        # Initialize the detector
        detector = SourcesDetector(result_queue, TEST_REPO_PATH)
        
        # Start detector threads
        threads = detector.start_threads()
        
        # Wait for threads to complete
        for thread in threads:
            thread.join(timeout=60)  # 60 second timeout per thread
        
        # Collect all results
        results = []
        while not result_queue.empty():
            try:
                result = result_queue.get_nowait()
                results.append(result)
            except queue.Empty:
                break
        
        # Save each result as a JSON file
        output_path = os.path.join(os.path.dirname(__file__), OUTPUT_FOLDER)
        
        for i, result in enumerate(results):
            # Create a descriptive filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Extract some info for filename if available
            file_info = ""
            if isinstance(result, dict):
                if 'file' in result:
                    file_info = f"_{os.path.basename(result['file'])}"
                elif 'path' in result:
                    file_info = f"_{os.path.basename(result['path'])}"
            
            filename = f"source_{timestamp}_{i}{file_info}.json"
            filepath = os.path.join(output_path, filename)
            
            # Save as JSON
            with open(filepath, 'w') as f:
                json.dump(result, f, indent=2)
                
            print(f"Saved source detection result to: {filename}")
        
        # Assert we found at least some sources
        assert len(results) > 0, "No sources were detected in the test repository"
        
        print(f"Total sources detected: {len(results)}")


if __name__ == "__main__":
    # Ensure parent directory (project root) is on sys.path for imports like `from Detectors ...`
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # Run just this test module when executed directly
    raise SystemExit(pytest.main([os.path.abspath(__file__)]))
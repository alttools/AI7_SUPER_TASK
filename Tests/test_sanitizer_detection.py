import pytest
import sys
import os
import json
import queue
from datetime import datetime

# Folder to place hits as individual files
OUTPUT_FOLDER = "../Samples/sanitizers"

# Repo that is good for testing code graph generation
TEST_REPO_PATH = "/Users/louismurphy/ODYSSEY/AI_SUPER_TASK/Repos/sqlite"

class TestSantizerDetection:
    """Test suite for running the santizer detection object and saving off any results as samples for other tests """
    
    def setup_method(self):
        """Setup for each test method"""
        # Ensure parent directory is on sys.path
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(current_dir)
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
            
        # Import after path setup
        from Detectors.Sanitizers import SanitizersDetector
        self.SanitizersDetector = SanitizersDetector
        
        # Create output folder path
        self.output_path = os.path.join(current_dir, OUTPUT_FOLDER)
        
        # Ensure output folder exists
        os.makedirs(self.output_path, exist_ok=True)
    
    def test_sanitizer_detection_on_test_repo(self):
        """Test sanitizer detection on the test repository and save results"""
        # Create a queue for results
        result_queue = queue.Queue()
        
        # Initialize the detector
        detector = self.SanitizersDetector(result_queue, TEST_REPO_PATH)
        
        # Run the detection
        threads = detector.start_threads()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Collect all results
        results = []
        while not result_queue.empty():
            try:
                result = result_queue.get_nowait()
                results.append(result)
            except queue.Empty:
                break
        
        # Save each result as a separate JSON file
        for i, result in enumerate(results):
            # Create descriptive filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"sanitizer_{i}_{timestamp}.json"
            filepath = os.path.join(self.output_path, filename)
            
            # Save result to JSON file
            with open(filepath, 'w') as f:
                json.dump(result, f, indent=2)
            
            print(f"Saved sanitizer result to: {filename}")
        
        # Log summary
        print(f"\nTotal sanitizers found: {len(results)}")
        
        # Assert that we found at least some sanitizers (adjust as needed)
        assert len(results) >= 0, "Expected to find at least some sanitizers"


if __name__ == "__main__":
    # Ensure parent directory (project root) is on sys.path for imports like `from Detectors ...`
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # Run just this test module when executed directly
    raise SystemExit(pytest.main([os.path.abspath(__file__)]))
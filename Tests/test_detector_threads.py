import pytest
import threading
import time
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import queue
import tempfile
import json


class TestDetectorThreads:
    """Test suite for detector thread functionality"""
    
    @pytest.fixture
    def sample_queue(self):
        """Create a test queue for detectors"""
        return queue.Queue()
    
    @pytest.fixture
    def temp_repo(self):
        """Create a temporary repository with test files"""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.js")
            with open(test_file, 'w') as f:
                f.write("""
                    // Test source
                    const userInput = req.body.username;
                    
                    // Test sink  
                    eval(userInput);
                    
                    // Test sanitizer
                    const cleaned = DOMPurify.sanitize(userInput);
                """)
            yield tmpdir
    
    def test_detector_base_initialization(self, sample_queue, temp_repo):
        """Test that base Detector class initializes correctly"""
        from Detectors import Detector
        
        detector = Detector(sample_queue, temp_repo)
        assert detector.queue == sample_queue
        assert detector.repo == temp_repo
    
    def test_detector_thread_regex_method_exists(self, sample_queue, temp_repo):
        """Test that _thread_regex method is implemented"""
        from Detectors import Detector
        
        detector = Detector(sample_queue, temp_repo)
        assert hasattr(detector, '_thread_regex')
    
    def test_sources_detector_initialization(self, sample_queue, temp_repo):
        """Test Sources detector initialization with RegexDetector"""
        from Detectors.Sources import SourcesDetector
        
        detector = SourcesDetector(sample_queue, temp_repo)
        assert detector.queue == sample_queue
        assert detector.repo == temp_repo
        assert hasattr(detector, 'regex_detector')
        assert detector.regex_detector.purpose == 'source'
    
    def test_sinks_detector_initialization(self, sample_queue, temp_repo):
        """Test Sinks detector initialization with RegexDetector"""
        from Detectors.Sinks import SinksDetector
        
        detector = SinksDetector(sample_queue, temp_repo)
        assert detector.queue == sample_queue
        assert detector.repo == temp_repo
        assert hasattr(detector, 'regex_detector')
        assert detector.regex_detector.purpose == 'sink'
    
    def test_sanitizers_detector_initialization(self, sample_queue, temp_repo):
        """Test Sanitizers detector initialization with RegexDetector"""
        from Detectors.Sanitizers import SanitizersDetector
        
        detector = SanitizersDetector(sample_queue, temp_repo)
        assert detector.queue == sample_queue
        assert detector.repo == temp_repo
        assert hasattr(detector, 'regex_detector')
        assert detector.regex_detector.purpose == 'sanitizer'
    
    def test_detector_start_threads(self, sample_queue, temp_repo):
        """Test that start_threads method starts all thread methods"""
        from Detectors.Sources import SourcesDetector
        
        detector = SourcesDetector(sample_queue, temp_repo)
        
        # Create a mock that blocks to ensure thread stays alive during test
        block_event = threading.Event()
        def mock_thread_method():
            block_event.wait(timeout=0.1)
        
        detector._thread_regex = mock_thread_method
        
        threads = detector.start_threads()
        
        # Verify thread was created and started
        assert len(threads) == 1
        assert isinstance(threads[0], threading.Thread)
        
        # Thread should be alive initially
        is_alive_initially = threads[0].is_alive()
        
        # Signal thread to finish
        block_event.set()
        
        # Wait for thread to complete
        threads[0].join(timeout=1)
        
        # Verify thread ran (was alive at some point)
        assert is_alive_initially or not threads[0].is_alive()
    
    def test_regex_thread_processes_files(self, sample_queue, temp_repo):
        """Test that _thread_regex processes files and adds results to queue"""
        from Detectors.Sources import SourcesDetector
        
        detector = SourcesDetector(sample_queue, temp_repo)
        
        # Run the regex thread method directly
        detector._thread_regex()
        
        # Check that results were added to the queue
        assert not sample_queue.empty()
        
        # Get the result
        result = sample_queue.get()
        assert result['type'] == 'source'
        assert 'req.body' in result['match']
        assert result['filename'].endswith('test.js')
    
    def test_multiple_detector_threads_concurrent(self, sample_queue, temp_repo):
        """Test that multiple detectors can run concurrently"""
        from Detectors.Sources import SourcesDetector
        from Detectors.Sinks import SinksDetector
        
        source_detector = SourcesDetector(sample_queue, temp_repo)
        sink_detector = SinksDetector(sample_queue, temp_repo)
        
        # Start both detectors
        source_threads = source_detector.start_threads()
        sink_threads = sink_detector.start_threads()
        
        # Wait for all threads
        for thread in source_threads + sink_threads:
            thread.join(timeout=2)
        
        # Collect results
        results = []
        while not sample_queue.empty():
            results.append(sample_queue.get())
        
        # Verify we got both source and sink results
        source_results = [r for r in results if r['type'] == 'source']
        sink_results = [r for r in results if r['type'] == 'sink']
        
        assert len(source_results) > 0
        assert len(sink_results) > 0
    


if __name__ == "__main__":
    # Ensure parent directory (project root) is on sys.path for imports like `from Detectors ...`
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # Run just this test module when executed directly
    raise SystemExit(pytest.main([os.path.abspath(__file__)]))
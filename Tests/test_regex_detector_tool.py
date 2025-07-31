import pytest
import sys
import os
import json
from unittest.mock import Mock, patch, mock_open


class TestRegexDetectorTool:
    """Test suite for testing the regex tool for detector objects to call"""
    
    @pytest.fixture
    def sample_rules(self):
        """Sample rules for testing"""
        return {
            "sources": {
                "javascript": [
                    {
                        "name": "user_input",
                        "pattern": r"\b(request\.(body|query|params|headers)|req\.(body|query|params|headers))\b",
                        "description": "User input from HTTP requests",
                        "confidence": 0.9
                    }
                ],
                "python": [
                    {
                        "name": "user_input",
                        "pattern": r"\b(request\.(args|form|values|headers|files|json))\b",
                        "description": "User input from HTTP requests",
                        "confidence": 0.9
                    }
                ],
                "default": [
                    {
                        "name": "generic_input",
                        "pattern": r"\binput\s*\(",
                        "description": "Generic input function",
                        "confidence": 0.5
                    }
                ]
            }
        }
    
    def test_initialization_with_source_purpose(self):
        """Test RegexDetector initialization with 'source' purpose"""
        from DetectorTools.RegexDetector import RegexDetector
        
        detector = RegexDetector("source")
        assert detector.purpose == "source"
        assert detector.rules is not None
        assert isinstance(detector.rules, dict)
    
    def test_initialization_with_sink_purpose(self):
        """Test RegexDetector initialization with 'sink' purpose"""
        from DetectorTools.RegexDetector import RegexDetector
        
        detector = RegexDetector("sink")
        assert detector.purpose == "sink"
        assert detector.rules is not None
        assert isinstance(detector.rules, dict)
    
    def test_initialization_with_sanitizer_purpose(self):
        """Test RegexDetector initialization with 'sanitizer' purpose"""
        from DetectorTools.RegexDetector import RegexDetector
        
        detector = RegexDetector("sanitizer")
        assert detector.purpose == "sanitizer"
        assert detector.rules is not None
        assert isinstance(detector.rules, dict)
    
    def test_initialization_with_invalid_purpose(self):
        """Test RegexDetector initialization with invalid purpose raises ValueError"""
        from DetectorTools.RegexDetector import RegexDetector
        
        with pytest.raises(ValueError, match="Invalid purpose"):
            RegexDetector("invalid_purpose")
    
    def test_detect_language_javascript(self):
        """Test language detection for JavaScript files"""
        from DetectorTools.RegexDetector import RegexDetector
        
        detector = RegexDetector("source")
        assert detector._detect_language("app.js") == "javascript"
        assert detector._detect_language("index.jsx") == "javascript"
        assert detector._detect_language("test.mjs") == "javascript"
    
    def test_detect_language_python(self):
        """Test language detection for Python files"""
        from DetectorTools.RegexDetector import RegexDetector
        
        detector = RegexDetector("source")
        assert detector._detect_language("main.py") == "python"
        assert detector._detect_language("test.pyw") == "python"
    
    def test_detect_language_java(self):
        """Test language detection for Java files"""
        from DetectorTools.RegexDetector import RegexDetector
        
        detector = RegexDetector("source")
        assert detector._detect_language("Main.java") == "java"
    
    def test_detect_language_typescript(self):
        """Test language detection for TypeScript files"""
        from DetectorTools.RegexDetector import RegexDetector
        
        detector = RegexDetector("source")
        assert detector._detect_language("app.ts") == "typescript"
        assert detector._detect_language("component.tsx") == "typescript"
    
    def test_detect_language_php(self):
        """Test language detection for PHP files"""
        from DetectorTools.RegexDetector import RegexDetector
        
        detector = RegexDetector("source")
        assert detector._detect_language("index.php") == "php"
    
    def test_detect_language_cpp(self):
        """Test language detection for C++ files"""
        from DetectorTools.RegexDetector import RegexDetector
        
        detector = RegexDetector("source")
        assert detector._detect_language("main.cpp") == "cpp"
        assert detector._detect_language("test.cc") == "cpp"
        assert detector._detect_language("header.cxx") == "cpp"
        assert detector._detect_language("code.c") == "cpp"
    
    def test_detect_language_unknown(self):
        """Test language detection for unknown file extensions"""
        from DetectorTools.RegexDetector import RegexDetector
        
        detector = RegexDetector("source")
        assert detector._detect_language("file.txt") == "default"
        assert detector._detect_language("readme.md") == "default"
    
    def test_detect_sources_in_javascript_file(self):
        """Test detecting sources in JavaScript file"""
        from DetectorTools.RegexDetector import RegexDetector
        
        detector = RegexDetector("source")
        
        # Create a temporary test file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write('const userInput = request.body.username;')
            temp_filename = f.name
        
        try:
            results = detector.detect(temp_filename)
            
            assert len(results) > 0
            assert results[0]["type"] == "source"
            assert results[0]["name"] == "user_input"
            assert results[0]["line_number"] == 1
            assert results[0]["match"] == "request.body"
            assert results[0]["confidence"] == 0.9
        finally:
            import os
            os.unlink(temp_filename)
    
    def test_detect_sources_in_python_file(self):
        """Test detecting sources in Python file"""
        from DetectorTools.RegexDetector import RegexDetector
        
        detector = RegexDetector("source")
        
        # Create a temporary test file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('user_data = request.args.get("id")')
            temp_filename = f.name
        
        try:
            results = detector.detect(temp_filename)
            
            assert len(results) > 0
            assert results[0]["type"] == "source"
            assert results[0]["name"] == "user_input"
            assert results[0]["line_number"] == 1
            assert results[0]["match"] == "request.args"
        finally:
            import os
            os.unlink(temp_filename)
    
    def test_detect_sinks_in_javascript_file(self):
        """Test detecting sinks in JavaScript file"""
        from DetectorTools.RegexDetector import RegexDetector
        
        detector = RegexDetector("sink")
        
        # Create a temporary test file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write('eval(userInput)')
            temp_filename = f.name
        
        try:
            results = detector.detect(temp_filename)
            
            assert len(results) > 0
            assert results[0]["type"] == "sink"
            assert results[0]["name"] == "eval"
            assert "eval(" in results[0]["match"]
        finally:
            import os
            os.unlink(temp_filename)
    
    def test_detect_sanitizers_in_javascript_file(self):
        """Test detecting sanitizers in JavaScript file"""
        from DetectorTools.RegexDetector import RegexDetector
        
        detector = RegexDetector("sanitizer")
        
        # Create a temporary test file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write('const safe = DOMPurify.sanitize(userInput);')
            temp_filename = f.name
        
        try:
            results = detector.detect(temp_filename)
            
            assert len(results) > 0
            assert results[0]["type"] == "sanitizer"
            assert results[0]["name"] == "escape_html"
            assert "DOMPurify.sanitize(" in results[0]["match"]
        finally:
            import os
            os.unlink(temp_filename)
    
    def test_detect_returns_correct_line_numbers(self):
        """Test that detection returns correct line numbers"""
        from DetectorTools.RegexDetector import RegexDetector
        
        detector = RegexDetector("source")
        
        # Create a temporary test file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write('line1\nline2 with request.body\nline3')
            temp_filename = f.name
        
        try:
            results = detector.detect(temp_filename)
            
            assert len(results) == 1
            assert results[0]["line_number"] == 2
        finally:
            import os
            os.unlink(temp_filename)
    
    def test_detect_multiple_matches_on_same_line(self):
        """Test detecting multiple matches on the same line"""
        from DetectorTools.RegexDetector import RegexDetector
        
        detector = RegexDetector("source")
        
        # Create a temporary test file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write('request.body; request.query')
            temp_filename = f.name
        
        try:
            results = detector.detect(temp_filename)
            
            assert len(results) == 2
            assert results[0]["line_number"] == 1
            assert results[1]["line_number"] == 1
            assert results[0]["match"] == "request.body"
            assert results[1]["match"] == "request.query"
        finally:
            import os
            os.unlink(temp_filename)
    
    def test_detect_with_default_rules(self):
        """Test detection using default rules for unknown file type"""
        from DetectorTools.RegexDetector import RegexDetector
        
        detector = RegexDetector("source")
        
        # Create a temporary test file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('name = input("Enter name: ")')
            temp_filename = f.name
        
        try:
            results = detector.detect(temp_filename)
            # Should use default rules if available
            # This test assumes default rules contain an input pattern
            # Adjust based on actual implementation
        finally:
            import os
            os.unlink(temp_filename)
    
    def test_detect_file_not_found(self):
        """Test detection when file doesn't exist"""
        from DetectorTools.RegexDetector import RegexDetector
        
        detector = RegexDetector("source")
        
        with pytest.raises(FileNotFoundError):
            detector.detect("nonexistent.js")
    
    def test_detect_empty_file(self):
        """Test detection on empty file returns empty list"""
        from DetectorTools.RegexDetector import RegexDetector
        
        detector = RegexDetector("source")
        
        # Create a temporary test file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write('')
            temp_filename = f.name
        
        try:
            results = detector.detect(temp_filename)
            assert results == []
        finally:
            import os
            os.unlink(temp_filename)
    
    def test_detect_on_sample_c_file(self):
        """Test detection on a real sample C file"""
        from DetectorTools.RegexDetector import RegexDetector
        
        # Test for sources
        source_detector = RegexDetector("source")
        results = source_detector.detect("Samples/files/vdbeapi.c")
        
        # Test for sinks  
        sink_detector = RegexDetector("sink")
        sink_results = sink_detector.detect("Samples/files/vdbeapi.c")
        
        # Test for sanitizers
        sanitizer_detector = RegexDetector("sanitizer")
        sanitizer_results = sanitizer_detector.detect("Samples/files/vdbeapi.c")
        
        print(f"{len(results)=}")
        print(f"{len(sink_results)=}")
        print(f"{len(sanitizer_results)=}")
        
        # Basic check that the detector runs without errors
        assert isinstance(results, list)
        assert isinstance(sink_results, list)
        assert isinstance(sanitizer_results, list)
    


if __name__ == "__main__":
    # Ensure parent directory (project root) is on sys.path for imports like `from Detectors ...`
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # Run just this test module when executed directly
    raise SystemExit(pytest.main([os.path.abspath(__file__)]))
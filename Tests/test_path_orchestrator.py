import pytest
import sys
import os


# Ensure parent directory is on sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Here you can do imports for local files

# source data for path testing
SOURCES_EXAMPLES = os.path.join(project_root, "Samples", "sources")
SINK_EXAMPLES = os.path.join(project_root, "Samples", "sinks")
SANITIZER_EXAMPLES = os.path.join(project_root, "Samples", "sanitizers")


class TestPathOrchestrator:
    """Test suite for detector thread functionality"""
    pass


if __name__ == "__main__":
    # Ensure parent directory (project root) is on sys.path for imports like `from Detectors ...`
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # Run just this test module when executed directly
    raise SystemExit(pytest.main([os.path.abspath(__file__)]))
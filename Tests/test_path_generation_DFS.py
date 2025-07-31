import pytest
import sys
import os
import json
import asyncio
from unittest.mock import Mock, MagicMock, AsyncMock
from typing import Dict, List, Set, Tuple


# Ensure parent directory is on sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Here you can do imports for local files
from Paths.DepthFirstSearch import DepthFirstSearch

# source data for path testing
SOURCES_EXAMPLES = os.path.join(project_root, "Samples", "sources")
SINK_EXAMPLES = os.path.join(project_root, "Samples", "sinks")
SANITIZER_EXAMPLES = os.path.join(project_root, "Samples", "sanitizers")


class TestPathGenerationDFS:
    """Test suite for path generation, depth first search"""
    
    @pytest.fixture
    def sample_source(self):
        """Sample source node data"""
        return {
            "type": "source",
            "name": "stdin_input",
            "line_number": 1843,
            "match": "gets",
            "confidence": 0.8,
            "description": "Standard input functions",
            "filename": "/test/file.c",
            "line_content": "gets(buffer);"
        }
    
    @pytest.fixture
    def sample_sink(self):
        """Sample sink node data"""
        return {
            "type": "sink",
            "name": "system",
            "line_number": 5233,
            "match": "system(",
            "confidence": 0.95,
            "description": "System command execution",
            "filename": "/test/file.c",
            "line_content": "system(buffer);"
        }
    
    @pytest.fixture
    def sample_sanitizers(self):
        """Sample sanitizer node data"""
        return [
            {
                "type": "sanitizer",
                "name": "snprintf",
                "line_number": 3396,
                "match": "snprintf(",
                "confidence": 0.85,
                "description": "Bounded string formatting",
                "filename": "/test/file.c",
                "line_content": "snprintf(buffer, sizeof(buffer), format);"
            },
            {
                "type": "sanitizer",
                "name": "strlen_check",
                "line_number": 3400,
                "match": "strlen(",
                "confidence": 0.75,
                "description": "String length validation",
                "filename": "/test/file.c",
                "line_content": "if (strlen(buffer) < MAX_SIZE)"
            }
        ]
    
    @pytest.fixture
    def mock_graph(self):
        """Create a mock graph object that simulates CodeQL graph"""
        graph = MagicMock()
        
        # Simple linear graph: source -> intermediate -> sanitizer -> sink
        # Also add a direct path: source -> sink
        nodes = {
            "source_1843": {"line": 1843, "type": "source"},
            "intermediate_2000": {"line": 2000, "type": "intermediate"},
            "sanitizer_3396": {"line": 3396, "type": "sanitizer"},
            "sink_5233": {"line": 5233, "type": "sink"}
        }
        
        # Adjacency list representation
        edges = {
            "source_1843": ["intermediate_2000", "sink_5233"],  # Direct and indirect paths
            "intermediate_2000": ["sanitizer_3396"],
            "sanitizer_3396": ["sink_5233"],
            "sink_5233": []
        }
        
        graph.nodes = nodes
        graph.edges = edges
        graph.get_neighbors = lambda node: edges.get(node, [])
        
        return graph
    
    @pytest.fixture
    def complex_graph(self):
        """Create a more complex graph with multiple paths"""
        graph = MagicMock()
        
        # Complex graph with multiple paths from source to sink
        nodes = {
            "source_100": {"line": 100, "type": "source"},
            "node_200": {"line": 200, "type": "intermediate"},
            "node_300": {"line": 300, "type": "intermediate"},
            "sanitizer_400": {"line": 400, "type": "sanitizer"},
            "sanitizer_500": {"line": 500, "type": "sanitizer"},
            "node_600": {"line": 600, "type": "intermediate"},
            "sink_700": {"line": 700, "type": "sink"}
        }
        
        # Multiple paths to sink
        edges = {
            "source_100": ["node_200", "node_300"],
            "node_200": ["sanitizer_400", "node_600"],
            "node_300": ["sanitizer_500"],
            "sanitizer_400": ["sink_700"],
            "sanitizer_500": ["node_600"],
            "node_600": ["sink_700"],
            "sink_700": []
        }
        
        graph.nodes = nodes
        graph.edges = edges
        graph.get_neighbors = lambda node: edges.get(node, [])
        
        return graph
    
    @pytest.fixture
    def async_queue(self):
        """Create an async queue for path analysis"""
        return asyncio.Queue()
    
    def test_initialization(self, sample_source, sample_sink, sample_sanitizers, mock_graph, async_queue):
        """Test DFS initialization"""
        dfs = DepthFirstSearch(
            source=sample_source,
            sink=sample_sink,
            sanitizers=sample_sanitizers,
            graph=mock_graph,
            path_analysis_queue=async_queue
        )
        
        assert dfs.source == sample_source
        assert dfs.sink == sample_sink
        assert dfs.sanitizers == sample_sanitizers
        assert dfs.graph == mock_graph
        assert dfs.path_analysis_queue == async_queue
        assert dfs.source_node == "source_1843"
        assert dfs.sink_node == "sink_5233"
        assert dfs.sanitizer_nodes == {"sanitizer_3396"}
    
    def test_node_identification(self, sample_source, sample_sink, sample_sanitizers, mock_graph, async_queue):
        """Test that nodes are correctly identified from line numbers"""
        dfs = DepthFirstSearch(
            source=sample_source,
            sink=sample_sink,
            sanitizers=sample_sanitizers,
            graph=mock_graph,
            path_analysis_queue=async_queue
        )
        
        assert dfs._get_node_id(1843) == "source_1843"
        assert dfs._get_node_id(5233) == "sink_5233"
        assert dfs._get_node_id(3396) == "sanitizer_3396"
        assert dfs._get_node_id(9999) is None  # Non-existent node
    
    @pytest.mark.asyncio
    async def test_find_paths_direct_path(self, sample_source, sample_sink, sample_sanitizers, mock_graph, async_queue):
        """Test finding direct path from source to sink"""
        dfs = DepthFirstSearch(
            source=sample_source,
            sink=sample_sink,
            sanitizers=sample_sanitizers,
            graph=mock_graph,
            path_analysis_queue=async_queue
        )
        
        await dfs.find_paths()
        
        # Check that paths were queued
        assert async_queue.qsize() > 0
        
        # Get all queued paths
        paths = []
        while not async_queue.empty():
            paths.append(await async_queue.get())
        
        # Should find both direct and sanitized paths
        assert len(paths) == 2
        
        # Check for direct path
        direct_path = next(p for p in paths if not p["goes_through_sanitizer"])
        assert direct_path["path"] == ["source_1843", "sink_5233"]
        assert direct_path["sanitizers_crossed"] == []
        
        # Check for sanitized path
        sanitized_path = next(p for p in paths if p["goes_through_sanitizer"])
        assert sanitized_path["path"] == ["source_1843", "intermediate_2000", "sanitizer_3396", "sink_5233"]
        assert sanitized_path["sanitizers_crossed"] == ["sanitizer_3396"]
    
    @pytest.mark.asyncio
    async def test_find_paths_complex_graph(self, sample_source, sample_sink, complex_graph, async_queue):
        """Test finding multiple paths in complex graph"""
        # Adjust source and sink for complex graph
        source = {"line_number": 100}
        sink = {"line_number": 700}
        sanitizers = [
            {"line_number": 400},
            {"line_number": 500}
        ]
        
        dfs = DepthFirstSearch(
            source=source,
            sink=sink,
            sanitizers=sanitizers,
            graph=complex_graph,
            path_analysis_queue=async_queue
        )
        
        await dfs.find_paths()
        
        # Collect all paths
        paths = []
        while not async_queue.empty():
            paths.append(await async_queue.get())
        
        # Should find multiple paths
        assert len(paths) >= 3
        
        # Verify all paths start at source and end at sink
        for path_info in paths:
            assert path_info["path"][0] == "source_100"
            assert path_info["path"][-1] == "sink_700"
            assert path_info["source"] == source
            assert path_info["sink"] == sink
    
    @pytest.mark.asyncio
    async def test_no_path_exists(self, sample_source, sample_sink, sample_sanitizers, async_queue):
        """Test when no path exists from source to sink"""
        # Create disconnected graph
        graph = MagicMock()
        graph.nodes = {
            "source_1843": {"line": 1843, "type": "source"},
            "sink_5233": {"line": 5233, "type": "sink"}
        }
        graph.edges = {
            "source_1843": [],
            "sink_5233": []
        }
        graph.get_neighbors = lambda node: graph.edges.get(node, [])
        
        dfs = DepthFirstSearch(
            source=sample_source,
            sink=sample_sink,
            sanitizers=sample_sanitizers,
            graph=graph,
            path_analysis_queue=async_queue
        )
        
        await dfs.find_paths()
        
        # No paths should be found
        assert async_queue.qsize() == 0
    
    @pytest.mark.asyncio
    async def test_cycle_detection(self, sample_source, sample_sink, sample_sanitizers, async_queue):
        """Test that DFS handles cycles properly"""
        # Create graph with cycle
        graph = MagicMock()
        graph.nodes = {
            "source_1843": {"line": 1843, "type": "source"},
            "node_2000": {"line": 2000, "type": "intermediate"},
            "node_3000": {"line": 3000, "type": "intermediate"},
            "sink_5233": {"line": 5233, "type": "sink"}
        }
        graph.edges = {
            "source_1843": ["node_2000"],
            "node_2000": ["node_3000"],
            "node_3000": ["node_2000", "sink_5233"],  # Cycle back to node_2000
            "sink_5233": []
        }
        graph.get_neighbors = lambda node: graph.edges.get(node, [])
        
        dfs = DepthFirstSearch(
            source=sample_source,
            sink=sample_sink,
            sanitizers=sample_sanitizers,
            graph=graph,
            path_analysis_queue=async_queue
        )
        
        await dfs.find_paths()
        
        # Should find path despite cycle
        assert async_queue.qsize() == 1
        path_info = await async_queue.get()
        assert path_info["path"] == ["source_1843", "node_2000", "node_3000", "sink_5233"]
    
    @pytest.mark.asyncio
    async def test_multiple_sanitizers_in_path(self, sample_source, sample_sink, async_queue):
        """Test path going through multiple sanitizers"""
        graph = MagicMock()
        graph.nodes = {
            "source_1843": {"line": 1843, "type": "source"},
            "sanitizer_2000": {"line": 2000, "type": "sanitizer"},
            "sanitizer_3000": {"line": 3000, "type": "sanitizer"},
            "sink_5233": {"line": 5233, "type": "sink"}
        }
        graph.edges = {
            "source_1843": ["sanitizer_2000"],
            "sanitizer_2000": ["sanitizer_3000"],
            "sanitizer_3000": ["sink_5233"],
            "sink_5233": []
        }
        graph.get_neighbors = lambda node: graph.edges.get(node, [])
        
        sanitizers = [
            {"line_number": 2000},
            {"line_number": 3000}
        ]
        
        dfs = DepthFirstSearch(
            source=sample_source,
            sink=sample_sink,
            sanitizers=sanitizers,
            graph=graph,
            path_analysis_queue=async_queue
        )
        
        await dfs.find_paths()
        
        assert async_queue.qsize() == 1
        path_info = await async_queue.get()
        assert path_info["goes_through_sanitizer"] is True
        assert len(path_info["sanitizers_crossed"]) == 2
        assert set(path_info["sanitizers_crossed"]) == {"sanitizer_2000", "sanitizer_3000"}


if __name__ == "__main__":
    # Ensure parent directory (project root) is on sys.path for imports like `from Detectors ...`
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # Run just this test module when executed directly
    raise SystemExit(pytest.main([os.path.abspath(__file__)]))
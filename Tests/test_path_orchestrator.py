import pytest
import sys
import os
import asyncio
import json
from unittest.mock import MagicMock, AsyncMock, patch
import threading
import time


# Ensure parent directory is on sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Here you can do imports for local files
from Paths.Orchestrator import Orchestrator
from Paths.DepthFirstSearch import DepthFirstSearch

# source data for path testing
SOURCES_EXAMPLES = os.path.join(project_root, "Samples", "sources")
SINK_EXAMPLES = os.path.join(project_root, "Samples", "sinks")
SANITIZER_EXAMPLES = os.path.join(project_root, "Samples", "sanitizers")


class TestPathOrchestrator:
    """Test suite for detector thread functionality"""
    
    @pytest.fixture
    def mock_graph(self):
        """Create a mock graph object for testing"""
        graph = MagicMock()
        graph.nodes = {
            "node_1": {"line": 10},
            "node_2": {"line": 20},
            "node_3": {"line": 30},
            "node_4": {"line": 40},
            "node_5": {"line": 50},
        }
        
        # Define graph connections for testing
        def get_neighbors(node_id):
            connections = {
                "node_1": ["node_2", "node_3"],
                "node_2": ["node_4"],
                "node_3": ["node_4"],
                "node_4": ["node_5"],
                "node_5": []
            }
            return connections.get(node_id, [])
        
        graph.get_neighbors = get_neighbors
        return graph
    
    @pytest.fixture
    def test_data(self):
        """Create test data for sources, sinks, and sanitizers"""
        sources = [
            {"line_number": 10, "file": "test.py", "type": "user_input"},
            {"line_number": 20, "file": "test2.py", "type": "file_read"}
        ]
        
        sinks = [
            {"line_number": 50, "file": "test.py", "type": "exec"},
            {"line_number": 40, "file": "test2.py", "type": "sql_query"}
        ]
        
        sanitizers = [
            {"line_number": 30, "file": "test.py", "type": "escape_html"}
        ]
        
        return sources, sinks, sanitizers
    
    @pytest.mark.asyncio
    async def test_orchestrator_initialization(self, mock_graph):
        """Test that orchestrator initializes correctly"""
        source_queue = asyncio.Queue()
        sink_queue = asyncio.Queue()
        sanitizer_queue = asyncio.Queue()
        path_analysis_queue = asyncio.Queue()
        
        orchestrator = Orchestrator(
            source_queue=source_queue,
            sink_queue=sink_queue,
            sanitizer_queue=sanitizer_queue,
            graph=mock_graph,
            path_analysis_queue=path_analysis_queue
        )
        
        assert orchestrator.source_queue == source_queue
        assert orchestrator.sink_queue == sink_queue
        assert orchestrator.sanitizer_queue == sanitizer_queue
        assert orchestrator.graph == mock_graph
        assert orchestrator.path_analysis_queue == path_analysis_queue
        assert orchestrator.tested_pairs == set()
        assert orchestrator.all_sanitizers == []
        assert orchestrator.running is False
    
    @pytest.mark.asyncio
    async def test_queue_monitoring(self, mock_graph, test_data):
        """Test that orchestrator monitors queues and processes items"""
        sources, sinks, sanitizers = test_data
        
        source_queue = asyncio.Queue()
        sink_queue = asyncio.Queue()
        sanitizer_queue = asyncio.Queue()
        path_analysis_queue = asyncio.Queue()
        
        orchestrator = Orchestrator(
            source_queue=source_queue,
            sink_queue=sink_queue,
            sanitizer_queue=sanitizer_queue,
            graph=mock_graph,
            path_analysis_queue=path_analysis_queue
        )
        
        # Add test data to queues
        await source_queue.put(sources[0])
        await sink_queue.put(sinks[0])
        await sanitizer_queue.put(sanitizers[0])
        
        # Start orchestrator
        start_task = asyncio.create_task(orchestrator.start())
        
        # Give it time to process
        await asyncio.sleep(0.1)
        
        # Stop orchestrator
        orchestrator.stop()
        await start_task
        
        # Check that items were processed
        assert len(orchestrator.all_sanitizers) == 1
        assert orchestrator.all_sanitizers[0] == sanitizers[0]
        
        # Check that a path analysis was queued
        assert not path_analysis_queue.empty()
        path_info = await path_analysis_queue.get()
        assert path_info["source"] == sources[0]
        assert path_info["sink"] == sinks[0]
    
    @pytest.mark.asyncio
    async def test_duplicate_source_sink_pairs(self, mock_graph, test_data):
        """Test that orchestrator doesn't process duplicate source/sink pairs"""
        sources, sinks, sanitizers = test_data
        
        source_queue = asyncio.Queue()
        sink_queue = asyncio.Queue()
        sanitizer_queue = asyncio.Queue()
        path_analysis_queue = asyncio.Queue()
        
        orchestrator = Orchestrator(
            source_queue=source_queue,
            sink_queue=sink_queue,
            sanitizer_queue=sanitizer_queue,
            graph=mock_graph,
            path_analysis_queue=path_analysis_queue
        )
        
        # Mock the create_search_task to track calls
        search_task_calls = []
        original_create_search = orchestrator._create_search_task
        
        async def mock_create_search(source, sink):
            search_task_calls.append((source, sink))
            return await original_create_search(source, sink)
        
        orchestrator._create_search_task = mock_create_search
        
        # Add same source/sink pair multiple times
        for _ in range(3):
            await source_queue.put(sources[0])
            await sink_queue.put(sinks[0])
        
        # Start orchestrator
        start_task = asyncio.create_task(orchestrator.start())
        
        # Give it time to process
        await asyncio.sleep(0.2)
        
        # Stop orchestrator
        orchestrator.stop()
        await start_task
        
        # Should only process the pair once
        assert len(search_task_calls) == 1
    
    @pytest.mark.asyncio
    async def test_multiple_search_threads(self, mock_graph, test_data):
        """Test that orchestrator creates multiple search threads"""
        sources, sinks, sanitizers = test_data
        
        source_queue = asyncio.Queue()
        sink_queue = asyncio.Queue()
        sanitizer_queue = asyncio.Queue()
        path_analysis_queue = asyncio.Queue()
        
        orchestrator = Orchestrator(
            source_queue=source_queue,
            sink_queue=sink_queue,
            sanitizer_queue=sanitizer_queue,
            graph=mock_graph,
            path_analysis_queue=path_analysis_queue
        )
        
        # Add multiple different pairs
        await source_queue.put(sources[0])
        await source_queue.put(sources[1])
        await sink_queue.put(sinks[0])
        await sink_queue.put(sinks[1])
        
        # Start orchestrator
        start_task = asyncio.create_task(orchestrator.start())
        
        # Give it time to process
        await asyncio.sleep(0.2)
        
        # Stop orchestrator
        orchestrator.stop()
        await start_task
        
        # Should have processed multiple pairs
        assert len(orchestrator.tested_pairs) >= 2
    
    @pytest.mark.asyncio
    async def test_sanitizer_tracking(self, mock_graph, test_data):
        """Test that orchestrator tracks all sanitizers"""
        sources, sinks, sanitizers = test_data
        
        source_queue = asyncio.Queue()
        sink_queue = asyncio.Queue()
        sanitizer_queue = asyncio.Queue()
        path_analysis_queue = asyncio.Queue()
        
        orchestrator = Orchestrator(
            source_queue=source_queue,
            sink_queue=sink_queue,
            sanitizer_queue=sanitizer_queue,
            graph=mock_graph,
            path_analysis_queue=path_analysis_queue
        )
        
        # Add multiple sanitizers
        for san in sanitizers:
            await sanitizer_queue.put(san)
        
        # Add extra sanitizer
        extra_sanitizer = {"line_number": 25, "file": "test3.py", "type": "validate"}
        await sanitizer_queue.put(extra_sanitizer)
        
        # Start orchestrator
        start_task = asyncio.create_task(orchestrator.start())
        
        # Give it time to process
        await asyncio.sleep(0.1)
        
        # Stop orchestrator
        orchestrator.stop()
        await start_task
        
        # Should have all sanitizers
        assert len(orchestrator.all_sanitizers) == 2
        assert sanitizers[0] in orchestrator.all_sanitizers
        assert extra_sanitizer in orchestrator.all_sanitizers
    
    @pytest.mark.asyncio
    async def test_depth_first_search_integration(self, mock_graph, test_data):
        """Test that orchestrator correctly uses DepthFirstSearch"""
        sources, sinks, sanitizers = test_data
        
        source_queue = asyncio.Queue()
        sink_queue = asyncio.Queue()
        sanitizer_queue = asyncio.Queue()
        path_analysis_queue = asyncio.Queue()
        
        orchestrator = Orchestrator(
            source_queue=source_queue,
            sink_queue=sink_queue,
            sanitizer_queue=sanitizer_queue,
            graph=mock_graph,
            path_analysis_queue=path_analysis_queue
        )
        
        # Add data that will create a path through sanitizer
        await source_queue.put(sources[0])  # line 10 -> node_1
        await sink_queue.put(sinks[0])      # line 50 -> node_5
        await sanitizer_queue.put(sanitizers[0])  # line 30 -> node_3
        
        # Start orchestrator
        start_task = asyncio.create_task(orchestrator.start())
        
        # Give it time to process
        await asyncio.sleep(0.3)
        
        # Stop orchestrator
        orchestrator.stop()
        await start_task
        
        # Check path analysis results
        results = []
        while not path_analysis_queue.empty():
            results.append(await path_analysis_queue.get())
        
        assert len(results) > 0, "No path analysis results found"
        
        # Find the path that goes through the sanitizer
        sanitizer_path = None
        for path_info in results:
            if path_info["goes_through_sanitizer"]:
                sanitizer_path = path_info
                break
        
        assert sanitizer_path is not None, "No path through sanitizer found"
        assert sanitizer_path["source"] == sources[0]
        assert sanitizer_path["sink"] == sinks[0]
        assert sanitizer_path["goes_through_sanitizer"] is True
        assert "node_3" in sanitizer_path["sanitizers_crossed"]


if __name__ == "__main__":
    # Ensure parent directory (project root) is on sys.path for imports like `from Detectors ...`
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # Run just this test module when executed directly
    raise SystemExit(pytest.main([os.path.abspath(__file__)]))
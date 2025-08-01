"""
<spec>

# Description
The orchestrator receives streaming data from the sources/sink/santizer detectors and starts creating unique combinations of these for testing in various ways. Much like the detectors this creates threads for each search pattern. Right now we are just doing depth first search, but future iterations will include breath first search patterns.

Each search pattern is it's own thread that is managed by the orchestrator.

When a path is discovered, information is passed onto the analysis queue

# Input
 - 'source' async queue
 - 'sink' async queue
 - 'santitzer' async queue
 - graph object (CodeQL)
 - path analysis async queue

# Output
 None, but the threads under this can return data over the path analysis queue

# Algorthim
The orchestrator will track the source/sink pairs that are tested for each of the search patterns so that things are not repeated. There will be a bit of a race condition as santitizers will not all be discovered yet, however in the final path analysis step it can block until all the santitzers are discovered for a final check.
 
 </spec>
"""

import asyncio
from typing import Set, List, Dict, Any, Tuple
import logging
from Paths.DepthFirstSearch import DepthFirstSearch

logger = logging.getLogger(__name__)


class Orchestrator:
    def __init__(self, source_queue: asyncio.Queue, sink_queue: asyncio.Queue,
                 sanitizer_queue: asyncio.Queue, graph: Any, 
                 path_analysis_queue: asyncio.Queue):
        """
        Initialize the orchestrator
        
        Args:
            source_queue: Queue receiving source detections
            sink_queue: Queue receiving sink detections  
            sanitizer_queue: Queue receiving sanitizer detections
            graph: CodeQL graph object
            path_analysis_queue: Queue to send path analysis results
        """
        self.source_queue = source_queue
        self.sink_queue = sink_queue
        self.sanitizer_queue = sanitizer_queue
        self.graph = graph
        self.path_analysis_queue = path_analysis_queue
        
        # Track tested source/sink pairs to avoid duplicates
        self.tested_pairs: Set[Tuple[str, str]] = set()
        
        # Track all sanitizers discovered
        self.all_sanitizers: List[Dict[str, Any]] = []
        
        # Control flag
        self.running = False
        
        # Task tracking
        self.tasks: List[asyncio.Task] = []
        
        # Track available sources and sinks
        self.sources_available: List[Dict[str, Any]] = []
        self.sinks_available: List[Dict[str, Any]] = []
    
    async def start(self):
        """Start the orchestrator and begin monitoring queues"""
        self.running = True
        
        # Create tasks for monitoring each queue
        monitor_tasks = [
            asyncio.create_task(self._monitor_sources()),
            asyncio.create_task(self._monitor_sinks()),
            asyncio.create_task(self._monitor_sanitizers()),
            asyncio.create_task(self._process_combinations())
        ]
        
        try:
            await asyncio.gather(*monitor_tasks)
        except asyncio.CancelledError:
            # Clean up tasks
            for task in self.tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*self.tasks, return_exceptions=True)
            raise
    
    def stop(self):
        """Stop the orchestrator"""
        self.running = False
    
    async def _monitor_sources(self):
        """Monitor source queue for new detections"""
        while self.running:
            try:
                source = await asyncio.wait_for(self.source_queue.get(), timeout=0.1)
                self.sources_available.append(source)
                logger.debug(f"New source detected: {source}")
            except asyncio.TimeoutError:
                continue
    
    async def _monitor_sinks(self):
        """Monitor sink queue for new detections"""
        while self.running:
            try:
                sink = await asyncio.wait_for(self.sink_queue.get(), timeout=0.1)
                self.sinks_available.append(sink)
                logger.debug(f"New sink detected: {sink}")
            except asyncio.TimeoutError:
                continue
    
    async def _monitor_sanitizers(self):
        """Monitor sanitizer queue and track all sanitizers"""
        while self.running:
            try:
                sanitizer = await asyncio.wait_for(self.sanitizer_queue.get(), timeout=0.1)
                self.all_sanitizers.append(sanitizer)
                logger.debug(f"New sanitizer detected: {sanitizer}")
            except asyncio.TimeoutError:
                continue
    
    async def _process_combinations(self):
        """Process available source/sink combinations"""
        while self.running:
            # Check for new combinations
            for source in self.sources_available:
                for sink in self.sinks_available:
                    pair_key = self._get_pair_key(source, sink)
                    
                    if pair_key not in self.tested_pairs:
                        self.tested_pairs.add(pair_key)
                        
                        # Create search task for this pair
                        task = asyncio.create_task(self._create_search_task(source, sink))
                        self.tasks.append(task)
            
            await asyncio.sleep(0.05)  # Small delay to prevent tight loop
    
    def _get_pair_key(self, source: Dict[str, Any], sink: Dict[str, Any]) -> Tuple[str, str]:
        """Generate unique key for source/sink pair"""
        source_key = f"{source.get('file', '')}:{source.get('line_number', '')}"
        sink_key = f"{sink.get('file', '')}:{sink.get('line_number', '')}"
        return (source_key, sink_key)
    
    async def _create_search_task(self, source: Dict[str, Any], sink: Dict[str, Any]):
        """Create and run a search task for a source/sink pair"""
        logger.info(f"Starting DFS search from {source} to {sink}")
        
        # Create DFS instance with current sanitizers
        dfs = DepthFirstSearch(
            source=source,
            sink=sink,
            sanitizers=self.all_sanitizers.copy(),  # Pass copy of current sanitizers
            graph=self.graph,
            path_analysis_queue=self.path_analysis_queue
        )
        
        # Run the search
        await dfs.find_paths()
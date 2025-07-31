"""
<spec>
#Input
 - source
 - sink 
 - list of all the sanitizers
 - Graph object (CodeQL)
 - path analysis async queue

#Output
 - (via queue) Code path information

#Algorthim
Depth first search starting at the source and trying to get to the sink, noting if it goes through an sanitizers

</spec>
"""

import asyncio
from typing import Dict, List, Set, Any, Optional


class DepthFirstSearch:
    def __init__(self, source: Dict[str, Any], sink: Dict[str, Any], 
                 sanitizers: List[Dict[str, Any]], graph: Any, 
                 path_analysis_queue: asyncio.Queue):
        """
        Initialize DFS path finder
        
        Args:
            source: Source node information with 'line_number' key
            sink: Sink node information with 'line_number' key
            sanitizers: List of sanitizer nodes with 'line_number' keys
            graph: Graph object with nodes and edges
            path_analysis_queue: Async queue to put found paths
        """
        self.source = source
        self.sink = sink
        self.sanitizers = sanitizers
        self.graph = graph
        self.path_analysis_queue = path_analysis_queue
        
        # Identify nodes in graph
        self.source_node = self._get_node_id(source['line_number'])
        self.sink_node = self._get_node_id(sink['line_number'])
        self.sanitizer_nodes = {
            self._get_node_id(san['line_number']) 
            for san in sanitizers
            if self._get_node_id(san['line_number']) is not None
        }
    
    def _get_node_id(self, line_number: int) -> Optional[str]:
        """Find node ID in graph by line number"""
        for node_id, node_data in self.graph.nodes.items():
            if node_data.get('line') == line_number:
                return node_id
        return None
    
    async def find_paths(self):
        """Find all paths from source to sink using DFS"""
        if not self.source_node or not self.sink_node:
            return
        
        # Track all paths found
        all_paths = []
        
        # DFS with path tracking
        await self._dfs(self.source_node, self.sink_node, [], set(), all_paths)
        
        # Queue all found paths
        for path in all_paths:
            sanitizers_in_path = [node for node in path if node in self.sanitizer_nodes]
            
            path_info = {
                "source": self.source,
                "sink": self.sink,
                "path": path,
                "goes_through_sanitizer": len(sanitizers_in_path) > 0,
                "sanitizers_crossed": sanitizers_in_path
            }
            
            await self.path_analysis_queue.put(path_info)
    
    async def _dfs(self, current: str, target: str, path: List[str], 
                   visited: Set[str], all_paths: List[List[str]]):
        """Recursive DFS to find all paths"""
        # Add current node to path
        path = path + [current]
        
        # If we reached the target, save the path
        if current == target:
            all_paths.append(path)
            return
        
        # Mark as visited to avoid cycles in current path
        visited.add(current)
        
        # Explore neighbors
        neighbors = self.graph.get_neighbors(current)
        for neighbor in neighbors:
            if neighbor not in visited:
                await self._dfs(neighbor, target, path, visited.copy(), all_paths)
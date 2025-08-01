"""
<spec>
This is the main file for the software. Here is the current phase of development's requirements (more requirement will come later)

Overview

It does the following steps:
    - Takes in a repo from command line arguments
    - defines the async queues 
       - sources
       - sinks
       - sanitizers
       - paths
       - graphs
    - Creates the code graph generation object and parses the codebase into a graph
    - Creates the detectors
       - sources
       - sinks
       - sanitizers
    - Creates the path analysis orchestrator

    - Connects all of these with the async queues

        source/sinks/sanitizers are given to their respective detectors for input

        Path orchestrator gets the sources/sinks/sanitizers queues for the output

        The path orchestrator gets the paths queue so it can pass a copy of it on to the individual path detection algorthims (depth first, breadth first, ect)

        The POC orchestrator gets the path queue for the output and then sends a "copy" of the message to each of it's sub threaded poc generation algorthims. 

</spec>
"""

import argparse
import asyncio
import os
import sys
import logging
from typing import Optional
import signal
import queue
import threading

from Graphs.CodeQL import CodeQL
from Detectors.Sources import SourcesDetector
from Detectors.Sinks import SinksDetector
from Detectors.Sanitizers import SanitizersDetector
from Paths.Orchestrator import Orchestrator


class SyncToAsyncQueueAdapter:
    """Adapter to bridge sync queues from detectors to async orchestrator"""
    def __init__(self, sync_queue, async_queue, loop):
        self.sync_queue = sync_queue
        self.async_queue = async_queue
        self.loop = loop
        self.running = True
        self.thread = None
    
    def start(self):
        """Start the adapter thread"""
        self.thread = threading.Thread(target=self._run)
        self.thread.daemon = True
        self.thread.start()
    
    def _run(self):
        """Transfer items from sync queue to async queue"""
        while self.running:
            try:
                item = self.sync_queue.get(timeout=0.1)
                # Use asyncio.run_coroutine_threadsafe to put into async queue
                future = asyncio.run_coroutine_threadsafe(
                    self.async_queue.put(item),
                    self.loop
                )
                future.result()  # Wait for it to complete
            except queue.Empty:
                continue
            except Exception as e:
                logger.debug(f"Adapter error: {e}")
    
    def stop(self):
        """Stop the adapter"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='AI7 Security Analysis Pipeline - Detects potential security vulnerabilities'
    )
    parser.add_argument(
        'repo',
        help='Path to the repository to analyze'
    )
    parser.add_argument(
        '--build-command',
        help='Build command for compiled languages (e.g., "make", "cmake . && make")'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Validate repo path
    if not os.path.exists(args.repo):
        parser.error(f"Repository path does not exist: {args.repo}")
    
    if not os.path.isdir(args.repo):
        parser.error(f"Repository path is not a directory: {args.repo}")
    
    return args


async def main():
    """Main async function to coordinate all components"""
    args = parse_arguments()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    logger.info(f"Starting AI7 Security Analysis Pipeline on: {args.repo}")
    
    # Create queues - sync for detectors, async for others
    sources_queue = queue.Queue()  # Sync queue for detector threads
    sinks_queue = queue.Queue()     # Sync queue for detector threads
    sanitizers_queue = queue.Queue() # Sync queue for detector threads
    paths_queue = asyncio.Queue()   # Async queue for path orchestrator
    graphs_queue = asyncio.Queue()  # Async queue for graph generation
    
    # Track running tasks
    tasks = []
    
    try:
        # Step 1: Create and start CodeQL graph generation
        logger.info("Initializing CodeQL graph generation...")
        codeql = CodeQL(repo=args.repo, queue=graphs_queue)
        
        # Start graph generation
        graph_task = asyncio.create_task(
            codeql.parse_codebase(build_command=args.build_command)
        )
        tasks.append(graph_task)
        
        # Wait for graph to be ready
        logger.info("Waiting for graph generation to complete...")
        graph_result = await graphs_queue.get()
        
        if graph_result['status'] != 'success':
            logger.error(f"Graph generation failed: {graph_result.get('error', 'Unknown error')}")
            logger.warning("Continuing with mock graph for demonstration purposes...")
            # Continue with a mock graph for testing
            codeql.database_path = "mock_database"
        
        else:
            logger.info(f"Graph successfully generated at: {graph_result['database_path']}")
        
        # Step 2: Create detector instances
        logger.info("Initializing detectors...")
        sources_detector = SourcesDetector(sources_queue, args.repo)
        sinks_detector = SinksDetector(sinks_queue, args.repo)
        sanitizers_detector = SanitizersDetector(sanitizers_queue, args.repo)
        
        # Start detector threads
        logger.info("Starting detector threads...")
        sources_detector.start_threads()
        sinks_detector.start_threads()
        sanitizers_detector.start_threads()
        
        # Step 3: Create async queues for orchestrator
        sources_async_queue = asyncio.Queue()
        sinks_async_queue = asyncio.Queue()
        sanitizers_async_queue = asyncio.Queue()
        
        # Create and start adapters
        logger.info("Starting queue adapters...")
        loop = asyncio.get_event_loop()
        sources_adapter = SyncToAsyncQueueAdapter(sources_queue, sources_async_queue, loop)
        sinks_adapter = SyncToAsyncQueueAdapter(sinks_queue, sinks_async_queue, loop)
        sanitizers_adapter = SyncToAsyncQueueAdapter(sanitizers_queue, sanitizers_async_queue, loop)
        
        sources_adapter.start()
        sinks_adapter.start()
        sanitizers_adapter.start()
        
        # Create and start path orchestrator with async queues
        logger.info("Initializing path analysis orchestrator...")
        orchestrator = Orchestrator(
            source_queue=sources_async_queue,
            sink_queue=sinks_async_queue,
            sanitizer_queue=sanitizers_async_queue,
            graph=codeql,
            path_analysis_queue=paths_queue
        )
        
        orchestrator_task = asyncio.create_task(orchestrator.start())
        tasks.append(orchestrator_task)
        
        # Step 4: Monitor paths queue for results
        logger.info("Monitoring for vulnerability paths...")
        monitor_task = asyncio.create_task(monitor_paths(paths_queue))
        
        # Run for a limited time for testing
        await asyncio.sleep(10)
        logger.info("Stopping monitoring after 10 seconds...")
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass
        
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down...")
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
    finally:
        # Cleanup
        logger.info("Cleaning up...")
        
        # Stop orchestrator
        if 'orchestrator' in locals():
            orchestrator.stop()
        
        # Stop adapters
        if 'sources_adapter' in locals():
            sources_adapter.stop()
        if 'sinks_adapter' in locals():
            sinks_adapter.stop()
        if 'sanitizers_adapter' in locals():
            sanitizers_adapter.stop()
        
        # Cancel all tasks
        for task in tasks:
            if not task.done():
                task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.info("Shutdown complete")


async def monitor_paths(paths_queue):
    """Monitor the paths queue and display results"""
    path_count = 0
    
    try:
        while True:
            try:
                # Wait for path results with timeout
                path_result = await asyncio.wait_for(paths_queue.get(), timeout=1.0)
                
                path_count += 1
                logger.info(f"\n{'='*60}")
                logger.info(f"VULNERABILITY PATH #{path_count}")
                logger.info(f"{'='*60}")
                
                # Display source information
                source = path_result.get('source', {})
                logger.info(f"SOURCE:")
                logger.info(f"  File: {source.get('file', 'Unknown')}")
                logger.info(f"  Line: {source.get('line_number', 'Unknown')}")
                logger.info(f"  Type: {source.get('pattern', 'Unknown')}")
                logger.info(f"  Match: {source.get('match', 'Unknown')}")
                
                # Display sink information
                sink = path_result.get('sink', {})
                logger.info(f"\nSINK:")
                logger.info(f"  File: {sink.get('file', 'Unknown')}")
                logger.info(f"  Line: {sink.get('line_number', 'Unknown')}")
                logger.info(f"  Type: {sink.get('pattern', 'Unknown')}")
                logger.info(f"  Match: {sink.get('match', 'Unknown')}")
                
                # Display path information
                if 'path' in path_result:
                    logger.info(f"\nPATH LENGTH: {len(path_result['path'])} nodes")
                
                # Display sanitizers if any
                if 'sanitizers' in path_result and path_result['sanitizers']:
                    logger.info(f"\nSANITIZERS FOUND: {len(path_result['sanitizers'])}")
                    for san in path_result['sanitizers']:
                        logger.info(f"  - {san.get('file', 'Unknown')}:{san.get('line_number', 'Unknown')}")
                
                # Display confidence/severity if available
                if 'confidence' in path_result:
                    logger.info(f"\nCONFIDENCE: {path_result['confidence']}")
                if 'severity' in path_result:
                    logger.info(f"SEVERITY: {path_result['severity']}")
                
                logger.info(f"{'='*60}\n")
                
            except asyncio.TimeoutError:
                # No new paths, continue monitoring
                continue
                
    except asyncio.CancelledError:
        logger.info(f"Path monitoring stopped. Total paths found: {path_count}")
        raise


def setup_signal_handlers(loop):
    """Setup signal handlers for graceful shutdown"""
    def signal_handler():
        logger.info("Received signal, initiating shutdown...")
        for task in asyncio.all_tasks(loop):
            task.cancel()
    
    if sys.platform != 'win32':
        loop.add_signal_handler(signal.SIGINT, signal_handler)
        loop.add_signal_handler(signal.SIGTERM, signal_handler)


if __name__ == "__main__":
    # Create event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    # Setup signal handlers
    setup_signal_handlers(loop)
    
    try:
        # Run main async function
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        # Cleanup
        loop.close()
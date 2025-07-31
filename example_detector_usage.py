#!/usr/bin/env python3
"""
Example demonstrating how to use the detector classes with RegexDetector
"""

import queue
import time
from Detectors.Sources import SourcesDetector
from Detectors.Sinks import SinksDetector
from Detectors.Sanitizers import SanitizersDetector


def main():
    # Create a shared queue for results
    results_queue = queue.Queue()
    
    # Path to scan - using Samples directory
    repo_path = "./Samples/files"
    
    # Create detectors
    sources_detector = SourcesDetector(results_queue, repo_path)
    sinks_detector = SinksDetector(results_queue, repo_path)
    sanitizers_detector = SanitizersDetector(results_queue, repo_path)
    
    print("Starting detector threads...")
    
    # Start all detector threads
    all_threads = []
    all_threads.extend(sources_detector.start_threads())
    all_threads.extend(sinks_detector.start_threads())
    all_threads.extend(sanitizers_detector.start_threads())
    
    print(f"Started {len(all_threads)} detector threads")
    
    # Wait for all threads to complete
    for thread in all_threads:
        thread.join()
    
    print("\nDetection complete. Results:")
    print("-" * 80)
    
    # Collect and display results
    results = []
    while not results_queue.empty():
        results.append(results_queue.get())
    
    # Group results by type
    sources = [r for r in results if r['type'] == 'source']
    sinks = [r for r in results if r['type'] == 'sink']
    sanitizers = [r for r in results if r['type'] == 'sanitizer']
    
    print(f"\nFound {len(sources)} sources:")
    for source in sources[:5]:  # Show first 5
        print(f"  - {source['name']} in {source['filename']}:{source['line_number']}")
        print(f"    Match: {source['match']}")
    
    print(f"\nFound {len(sinks)} sinks:")
    for sink in sinks[:5]:  # Show first 5
        print(f"  - {sink['name']} in {sink['filename']}:{sink['line_number']}")
        print(f"    Match: {sink['match']}")
    
    print(f"\nFound {len(sanitizers)} sanitizers:")
    for sanitizer in sanitizers[:5]:  # Show first 5
        print(f"  - {sanitizer['name']} in {sanitizer['filename']}:{sanitizer['line_number']}")
        print(f"    Match: {sanitizer['match']}")
    
    print(f"\nTotal detections: {len(results)}")


if __name__ == "__main__":
    main()
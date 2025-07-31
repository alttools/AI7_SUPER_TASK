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

class Orchestrator: pass
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

        sources_q                                 CodeQL graph 
        sinks_q                                       ||
        sanitizer_q  =>   Path orchestrator    =>     \/                         
                                                    Depth First search.    
                                                    Breadth first search   

        
</spec>
"""
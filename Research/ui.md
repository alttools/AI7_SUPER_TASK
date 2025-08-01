
## UI

The UI for this is informative and simple. It must be based on textualize.

//rough mockup//
Graphs
  - CodeQL [##########] 100% Completed 00:00:05
     134 Nodes
     823 Edges

Detectors
  Sources   402 Total
    - Regex    22 [##########]  ssl_hlpr.c      100% 5:10:04 | 2:20:04 | 7:30:00
    - SemGrep 112 [####......]  mgr.pl           40% 5:40:04 | 2:20:04 | 3:20:00
    - LLM       0 [#.........]  backend.py       10% 5:40:04 | 2:20:04 | 3:20:00
         
  Sinks   402 Total
    - Regex    22 [##########]  ssl_hlpr.c      100% 5:10:04 | 2:20:04 | 7:30:00
    - SemGrep 112 [####......]  mgr.pl           40% 5:40:04 | 2:20:04 | 3:20:00
    - LLM       0 [#.........]  backend.py       10% 5:40:04 | 2:20:04 | 3:20:00

  Sanitizers   402 Total
    - Regex    22 [##########]  ssl_hlpr.c      100% 5:10:04 | 2:20:04 | 7:30:00
    - SemGrep 112 [####......]  mgr.pl           40% 5:40:04 | 2:20:04 | 3:20:00
    - LLM       0 [#.........]  backend.py       10% 5:40:04 | 2:20:04 | 3:20:00

Path Generation - 14 unique
    - DFS       20 paths   (spinner)
    - BFS       14 paths   (spinner)

Path Detailed Information
-----------+-----------------------------------------------------------------------+
Path001    |   Sources:                                                            |
Path002    |   Sink:                                                               |
[Path003]  |   Sanitizers:                                                         |
Path004    |   Path:                                                               |
           |   Code Slices:                                                        |
-----------+-----------------------------------------------------------------------+
               
//mockup//

*note the numbers are there just for illustration and do not add up properly. See below for a description

In this mockup there are several areas designed in a somewhat outline like fashion. The first shows the pre-parsing of the codebase into a graph via codeql. It can support multiple graphs but in this case only codeql is being used. It shows a completed progress bar graph with some meta data about the graph to give the user a sense of the size and result of the parsing.

Next is detectors, Again in outline format it lists out the sources/sinks/sanitizers, but then each of those have multiple ways of getting that data, in this case regex, semgrep and llm generated sources/sinks/sanitizers; ordered by the think being searched for.
The next number is the total for each of the source detection techniques, along with a bar graph, the filename it's currently working on (formmated with a fixed width string so that the rest of the line doesn't jump around as the filename length changes). Followed by a percentage compelte, time elapsed, estimated time remaining and estimated total time.

Path generation follows a similar pattern but doesn't have bargraphs it has a spinner of some sort that goes while it is still processing. Another change change is the total for all the algorthims is listing unique items and not total items. Since there is likely going to be overlap with different algorthims, unique items are being tracked so that it is more accurate.

Finally the path detailed information section.

This has 2 columns, the left column is a selectabled list of the discovered paths. The arrow keys up and down will move a highlighted cursor showing which path is selected by bolding or changing the background color of the selected path. Then in the column to the right is the detailed information known about that path. In this mock ui the information was not simulated and it just lists the overall categories of expected information. 

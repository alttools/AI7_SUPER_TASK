## Forever Requirements
# only support openrouter and local lm studio for LLM providers
# minimize the usage of the 'cd' command as much as possible. Alternatively just use full paths for the files instead of changing directories. 

## Project overfiew
* **Asynchronous Multi-Stage Pipeline:** Leverages parallel detectors (LLM scans, regex, Semgrep, Bandit/Flawfinder, CodeQL) to identify sources, sinks, and sanitizers, then immediately kicks off graph-based path discovery and slicing without waiting for full scans to complete.
* **Semantic Graph Backbone:** Uses CodeQL's AST/CFG/DFG database (with srcML/Joern fallback) to precisely trace data-flow from taint sources to dangerous sinks, applying token-aware caps to keep code slices within each model's context window.
* **Focused Code Slices for AI Analysis:** Extracts minimal, cross-file snippets representing each source-to-sink path—stripped of boilerplate—to feed into AI agents (or custom logic) that assign vulnerability verdicts, confidence scores, CWE categories, and estimated CVSS v3 severity.


## Specs ##
Doc strings with '<spec></spec>' denote the orginal intention of the file. Do not modify in any way these comments as it reflects the ground truth of the file. Reference these to better understand the intention of the file.

Questions about the specs to help your understand the intention are encouraged.
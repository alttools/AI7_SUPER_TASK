/**
 * @name Command injection sinks
 * @description Finds command execution sinks that could lead to OS command injection
 * @kind problem
 * @problem.severity error
 * @id js/command-injection-sink
 * @tags security
 *       external/cwe/cwe-78
 */

import javascript

from DataFlow::Node sink, CallExpr call
where 
  call = sink.asExpr() and
  (
    // child_process.exec, execSync, spawn
    call.getCalleeName() = ["exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"] and
    exists(DataFlow::ModuleImportNode cp |
      cp.getPath() = "child_process" and
      call.getCallee() = cp.getAPropertyRead(_)
    )
  ) or (
    // Direct calls to require('child_process').exec
    exists(CallExpr req |
      req.getCalleeName() = "require" and
      req.getArgument(0).getStringValue() = "child_process" and
      call.getCallee() = req.flow().getAPropertyRead(["exec", "execSync", "spawn", "spawnSync"])
    )
  )
select sink.getLocation(),
       "Command execution sink: " + sink.toString(),
       sink.getFile().getRelativePath(),
       sink.getLocation().getStartLine(),
       sink.getLocation().getStartColumn(),
       sink.getLocation().getEndLine(),
       sink.getLocation().getEndColumn()
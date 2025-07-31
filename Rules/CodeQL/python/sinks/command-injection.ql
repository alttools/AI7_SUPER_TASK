/**
 * @name Command injection sinks in Python
 * @description Finds command execution sinks that could lead to OS command injection
 * @kind problem
 * @problem.severity error
 * @id py/command-injection-sink
 * @tags security
 *       external/cwe/cwe-78
 */

import python

from DataFlow::Node sink, CallNode call
where 
  call = sink.asExpr() and
  (
    // os.system
    exists(AttrNode attr |
      attr = call.getFunction() and
      attr.getObject().toString() = "os" and
      attr.getName() = "system"
    ) or
    // subprocess functions
    exists(AttrNode attr |
      attr = call.getFunction() and
      attr.getObject().toString() = "subprocess" and
      attr.getName() = ["call", "run", "Popen", "check_call", "check_output", "getoutput", "getstatusoutput"]
    ) or
    // os.popen
    exists(AttrNode attr |
      attr = call.getFunction() and
      attr.getObject().toString() = "os" and
      attr.getName() = "popen"
    ) or
    // Direct calls
    call.getFunction().toString() = ["system", "popen", "execl", "execle", "execlp", "execv", "execve", "execvp"]
  )
select sink.getLocation(),
       "Command execution sink: " + sink.toString(),
       sink.getLocation().getFile().getRelativePath(),
       sink.getLocation().getStartLine(),
       sink.getLocation().getStartColumn(),
       sink.getLocation().getEndLine(),
       sink.getLocation().getEndColumn()
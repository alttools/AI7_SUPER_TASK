/**
 * @name Command injection sinks in Java
 * @description Finds command execution sinks that could lead to OS command injection
 * @kind problem
 * @problem.severity error
 * @id java/command-injection-sink
 * @tags security
 *       external/cwe/cwe-78
 */

import java

from DataFlow::Node sink
where 
  // Runtime.exec
  exists(MethodAccess ma |
    ma = sink.asExpr() and
    ma.getMethod().hasName("exec") and
    ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime")
  ) or
  // ProcessBuilder
  exists(MethodAccess ma |
    ma = sink.asExpr() and
    ma.getMethod().hasName(["start", "command"]) and
    ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder")
  ) or
  // ProcessBuilder constructor
  exists(ClassInstanceExpr cie |
    cie = sink.asExpr() and
    cie.getType().hasQualifiedName("java.lang", "ProcessBuilder")
  )
select sink.getLocation(),
       "Command execution sink: " + sink.toString(),
       sink.getLocation().getFile().getRelativePath(),
       sink.getLocation().getStartLine(),
       sink.getLocation().getStartColumn(),
       sink.getLocation().getEndLine(),
       sink.getLocation().getEndColumn()
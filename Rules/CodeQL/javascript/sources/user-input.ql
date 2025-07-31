/**
 * @name User input sources
 * @description Finds sources of user-controlled input in JavaScript applications
 * @kind problem
 * @problem.severity warning
 * @id js/user-input-source
 * @tags security
 *       external/cwe/cwe-20
 */

import javascript
import semmle.javascript.security.dataflow.RemoteFlowSources

from DataFlow::Node source
where 
  source instanceof RemoteFlowSource or
  source.asExpr() instanceof PropAccess and (
    source.asExpr().(PropAccess).getPropertyName() = ["params", "query", "body", "headers", "cookies"] and
    source.asExpr().(PropAccess).getBase().toString() = "req"
  ) or
  source.asExpr() instanceof CallExpr and (
    source.asExpr().(CallExpr).getCalleeName() = ["param", "query", "body", "header", "get"] and
    exists(DataFlow::Node base |
      base = source.asExpr().(CallExpr).getReceiver() and
      base.toString() = "req"
    )
  )
select source.getLocation(), 
       "User input source detected: " + source.toString(),
       source.getFile().getRelativePath(), 
       source.getLocation().getStartLine(),
       source.getLocation().getStartColumn(),
       source.getLocation().getEndLine(),
       source.getLocation().getEndColumn()
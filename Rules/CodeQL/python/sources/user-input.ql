/**
 * @name User input sources in Python
 * @description Finds sources of user-controlled input in Python web applications
 * @kind problem
 * @problem.severity warning
 * @id py/user-input-source
 * @tags security
 *       external/cwe/cwe-20
 */

import python
import semmle.python.security.dataflow.RemoteFlowSources

from DataFlow::Node source
where 
  source instanceof RemoteFlowSource or
  // Flask request attributes
  exists(AttrNode attr |
    attr = source.asExpr() and
    attr.getObject().toString() = "request" and
    attr.getName() = ["args", "form", "values", "cookies", "headers", "files", "json", "data"]
  ) or
  // Django request attributes
  exists(AttrNode attr |
    attr = source.asExpr() and
    attr.getObject().toString() = "request" and
    attr.getName() = ["GET", "POST", "FILES", "COOKIES", "META", "body"]
  ) or
  // FastAPI parameters
  exists(Name param |
    param = source.asExpr() and
    exists(Function f |
      param.getScope() = f and
      f.getName().matches("%route%") and
      param.getId() = ["request", "body", "query", "path", "header", "cookie"]
    )
  )
select source.getLocation(),
       "User input source: " + source.toString(),
       source.getLocation().getFile().getRelativePath(),
       source.getLocation().getStartLine(),
       source.getLocation().getStartColumn(),
       source.getLocation().getEndLine(),
       source.getLocation().getEndColumn()
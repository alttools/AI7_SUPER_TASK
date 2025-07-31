/**
 * @name SQL injection sinks in Python
 * @description Finds SQL query execution sinks
 * @kind problem
 * @problem.severity error
 * @id py/sql-injection-sink
 * @tags security
 *       external/cwe/cwe-89
 */

import python

from DataFlow::Node sink, CallNode call
where 
  call = sink.asExpr() and
  (
    // Direct database execute methods
    exists(AttrNode attr |
      attr = call.getFunction() and
      attr.getName() = ["execute", "executemany", "executescript", "raw", "query"] and
      (
        attr.getObject().toString().matches("%cursor%") or
        attr.getObject().toString().matches("%connection%") or
        attr.getObject().toString().matches("%conn%") or
        attr.getObject().toString().matches("%db%")
      )
    ) or
    // SQLAlchemy
    exists(AttrNode attr |
      attr = call.getFunction() and
      attr.getName() = ["execute", "scalar", "scalars"] and
      attr.getObject().toString().matches("%session%")
    ) or
    // Django ORM raw queries
    exists(AttrNode attr |
      attr = call.getFunction() and
      attr.getName() = ["raw", "execute"] and
      exists(AttrNode obj |
        obj = attr.getObject() and
        obj.getName() = "objects"
      )
    )
  )
select sink.getLocation(),
       "SQL query execution sink: " + sink.toString(),
       sink.getLocation().getFile().getRelativePath(),
       sink.getLocation().getStartLine(),
       sink.getLocation().getStartColumn(),
       sink.getLocation().getEndLine(),
       sink.getLocation().getEndColumn()
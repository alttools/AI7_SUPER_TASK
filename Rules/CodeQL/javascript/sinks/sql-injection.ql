/**
 * @name SQL injection sinks
 * @description Finds SQL query execution sinks
 * @kind problem
 * @problem.severity error
 * @id js/sql-injection-sink
 * @tags security
 *       external/cwe/cwe-89
 */

import javascript

from DataFlow::Node sink, CallExpr call
where 
  call = sink.asExpr() and
  (
    // Direct SQL query methods
    call.getCalleeName() = ["query", "execute", "run", "exec", "all", "get"] and
    exists(DataFlow::Node receiver |
      receiver = call.getReceiver() and
      (
        receiver.toString() = ["db", "connection", "conn", "client", "pool", "knex", "sequelize"] or
        receiver.getALocalSource().toString().matches("%[Dd]atabase%") or
        receiver.getALocalSource().toString().matches("%[Cc]onnection%")
      )
    )
  ) or (
    // Sequelize raw queries
    call.getCalleeName() = "query" and
    exists(PropAccess pa |
      pa = call.getReceiver() and
      pa.getPropertyName() = "sequelize"
    )
  ) or (
    // Knex.raw
    call.getCalleeName() = "raw" and
    call.getReceiver().toString() = "knex"
  )
select sink.getLocation(),
       "SQL query execution sink: " + sink.toString(),
       sink.getFile().getRelativePath(),
       sink.getLocation().getStartLine(),
       sink.getLocation().getStartColumn(),
       sink.getLocation().getEndLine(),
       sink.getLocation().getEndColumn()
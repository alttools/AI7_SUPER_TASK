/**
 * @name SQL injection sinks in Java
 * @description Finds SQL query execution sinks
 * @kind problem
 * @problem.severity error
 * @id java/sql-injection-sink
 * @tags security
 *       external/cwe/cwe-89
 */

import java

from DataFlow::Node sink
where 
  // JDBC execute methods
  exists(MethodAccess ma |
    ma = sink.asExpr() and
    ma.getMethod().hasName(["execute", "executeQuery", "executeUpdate", "addBatch"]) and
    (
      ma.getMethod().getDeclaringType().hasQualifiedName("java.sql", ["Statement", "PreparedStatement", "CallableStatement"]) or
      ma.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("java.sql", ["Statement", "PreparedStatement", "CallableStatement"])
    )
  ) or
  // Hibernate/JPA createQuery
  exists(MethodAccess ma |
    ma = sink.asExpr() and
    ma.getMethod().hasName(["createQuery", "createNativeQuery", "createSQLQuery"]) and
    (
      ma.getQualifier().getType().hasName(["Session", "EntityManager"]) or
      ma.getQualifier().getType().getASupertype*().hasName(["Session", "EntityManager"])
    )
  ) or
  // Spring JdbcTemplate
  exists(MethodAccess ma |
    ma = sink.asExpr() and
    ma.getMethod().hasName(["execute", "query", "queryForObject", "queryForList", "update", "batchUpdate"]) and
    ma.getQualifier().getType().hasName("JdbcTemplate")
  )
select sink.getLocation(),
       "SQL query execution sink: " + sink.toString(),
       sink.getLocation().getFile().getRelativePath(),
       sink.getLocation().getStartLine(),
       sink.getLocation().getStartColumn(),
       sink.getLocation().getEndLine(),
       sink.getLocation().getEndColumn()
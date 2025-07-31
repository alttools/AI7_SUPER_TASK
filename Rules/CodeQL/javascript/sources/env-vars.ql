/**
 * @name Environment variable access
 * @description Finds access to environment variables
 * @kind problem
 * @problem.severity warning
 * @id js/env-var-source
 * @tags security
 */

import javascript

from DataFlow::Node source, PropAccess access
where 
  access = source.asExpr() and
  access.getBase().toString() = "process.env"
select source.getLocation(),
       "Environment variable access: " + source.toString(),
       source.getFile().getRelativePath(),
       source.getLocation().getStartLine(),
       source.getLocation().getStartColumn(),
       source.getLocation().getEndLine(),
       source.getLocation().getEndColumn()
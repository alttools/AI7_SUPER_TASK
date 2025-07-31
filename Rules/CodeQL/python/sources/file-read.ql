/**
 * @name File system read operations in Python
 * @description Finds file system read operations that could expose sensitive data
 * @kind problem
 * @problem.severity warning
 * @id py/file-read-source
 * @tags security
 *       external/cwe/cwe-22
 */

import python

from DataFlow::Node source, CallNode call
where 
  call = source.asExpr() and
  (
    // open() function for reading
    call.getFunction().toString() = "open" and
    (
      not exists(StrConst mode |
        mode = call.getArg(1) and
        mode.getText().matches("%w%")
      ) or
      exists(StrConst mode |
        mode = call.getArg(1) and
        mode.getText().matches("%r%")
      )
    )
  ) or
  // File read methods
  exists(AttrNode attr |
    attr = call.getFunction() and
    attr.getName() = ["read", "readline", "readlines"] and
    exists(CallNode openCall |
      openCall.getFunction().toString() = "open" and
      attr.getObject() = openCall
    )
  ) or
  // pathlib read methods
  exists(AttrNode attr |
    attr = call.getFunction() and
    attr.getName() = ["read_text", "read_bytes"] and
    attr.getObject().toString().matches("%Path%")
  )
select source.getLocation(),
       "File read operation: " + source.toString(),
       source.getLocation().getFile().getRelativePath(),
       source.getLocation().getStartLine(),
       source.getLocation().getStartColumn(),
       source.getLocation().getEndLine(),
       source.getLocation().getEndColumn()
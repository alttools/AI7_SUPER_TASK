/**
 * @name File system read operations
 * @description Finds file system read operations that could expose sensitive data
 * @kind problem
 * @problem.severity warning
 * @id js/file-read-source
 * @tags security
 *       external/cwe/cwe-22
 */

import javascript

from DataFlow::Node source, CallExpr call
where 
  call = source.asExpr() and
  (
    // fs.readFile, fs.readFileSync
    call.getCalleeName() = ["readFile", "readFileSync"] and
    call.getReceiver().toString() = "fs"
  ) or (
    // fs.createReadStream
    call.getCalleeName() = "createReadStream" and
    call.getReceiver().toString() = "fs"
  ) or (
    // require('fs').readFile
    exists(DataFlow::ModuleImportNode fs |
      fs.getPath() = "fs" and
      call.getCallee() = fs.getAPropertyRead(["readFile", "readFileSync", "createReadStream"])
    )
  )
select source.getLocation(),
       "File read operation detected: " + source.toString(),
       source.getFile().getRelativePath(),
       source.getLocation().getStartLine(),
       source.getLocation().getStartColumn(),
       source.getLocation().getEndLine(),
       source.getLocation().getEndColumn()
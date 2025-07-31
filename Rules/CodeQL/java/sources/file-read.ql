/**
 * @name File system read operations in Java
 * @description Finds file system read operations that could expose sensitive data
 * @kind problem
 * @problem.severity warning
 * @id java/file-read-source
 * @tags security
 *       external/cwe/cwe-22
 */

import java

from DataFlow::Node source
where 
  // FileInputStream
  exists(ClassInstanceExpr cie |
    cie = source.asExpr() and
    cie.getType().hasQualifiedName("java.io", "FileInputStream")
  ) or
  // Files.read* methods
  exists(MethodAccess ma |
    ma = source.asExpr() and
    ma.getMethod().hasName(["readAllBytes", "readAllLines", "readString", "lines", "newInputStream", "newBufferedReader"]) and
    ma.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Files")
  ) or
  // BufferedReader, FileReader
  exists(ClassInstanceExpr cie |
    cie = source.asExpr() and
    cie.getType().hasQualifiedName("java.io", ["BufferedReader", "FileReader"])
  ) or
  // Scanner for files
  exists(ClassInstanceExpr cie |
    cie = source.asExpr() and
    cie.getType().hasQualifiedName("java.util", "Scanner") and
    cie.getArgument(0).getType().hasQualifiedName("java.io", "File")
  )
select source.getLocation(),
       "File read operation: " + source.toString(),
       source.getLocation().getFile().getRelativePath(),
       source.getLocation().getStartLine(),
       source.getLocation().getStartColumn(),
       source.getLocation().getEndLine(),
       source.getLocation().getEndColumn()
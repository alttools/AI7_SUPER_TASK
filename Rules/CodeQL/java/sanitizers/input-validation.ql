/**
 * @name Input validation and sanitization in Java
 * @description Finds input validation and sanitization functions
 * @kind problem
 * @problem.severity info
 * @id java/input-validation-sanitizer
 * @tags security
 */

import java

from DataFlow::Node sanitizer
where 
  // String validation methods
  exists(MethodAccess ma |
    ma = sanitizer.asExpr() and
    ma.getMethod().hasName(["replaceAll", "replace", "trim", "matches", "contains"]) and
    ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String")
  ) or
  // Pattern matching
  exists(MethodAccess ma |
    ma = sanitizer.asExpr() and
    ma.getMethod().hasName(["matches", "find"]) and
    ma.getMethod().getDeclaringType().hasQualifiedName("java.util.regex", ["Pattern", "Matcher"])
  ) or
  // Apache Commons StringEscapeUtils
  exists(MethodAccess ma |
    ma = sanitizer.asExpr() and
    ma.getMethod().hasName(["escapeHtml", "escapeHtml4", "escapeXml", "escapeJava", "escapeSql"]) and
    ma.getMethod().getDeclaringType().hasName("StringEscapeUtils")
  ) or
  // OWASP ESAPI
  exists(MethodAccess ma |
    ma = sanitizer.asExpr() and
    ma.getMethod().hasName(["encodeForHTML", "encodeForSQL", "encodeForJavaScript", "encodeForURL"]) and
    ma.getMethod().getDeclaringType().hasName("Encoder")
  ) or
  // Input validation annotations (detected at parameter level)
  exists(Parameter p |
    p = sanitizer.asParameter() and
    p.getAnAnnotation().getType().hasName(["Valid", "NotNull", "NotEmpty", "NotBlank", "Pattern", "Size", "Min", "Max"])
  )
select sanitizer.getLocation(),
       "Input sanitization: " + sanitizer.toString(),
       sanitizer.getLocation().getFile().getRelativePath(),
       sanitizer.getLocation().getStartLine(),
       sanitizer.getLocation().getStartColumn(),
       sanitizer.getLocation().getEndLine(),
       sanitizer.getLocation().getEndColumn()
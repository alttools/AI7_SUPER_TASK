/**
 * @name Input validation and sanitization in Python
 * @description Finds input validation and sanitization functions
 * @kind problem
 * @problem.severity info
 * @id py/input-validation-sanitizer
 * @tags security
 */

import python

from DataFlow::Node sanitizer
where 
  // String validation methods
  exists(CallNode call |
    call = sanitizer.asExpr() and
    exists(AttrNode attr |
      attr = call.getFunction() and
      attr.getName() = ["strip", "replace", "encode", "decode", "isalnum", "isalpha", "isdigit", "isdecimal"] and
      exists(DataFlow::Node obj |
        obj = attr.getObject() and
        obj.getAType().toString() = "str"
      )
    )
  ) or
  // Regular expression operations
  exists(CallNode call |
    call = sanitizer.asExpr() and
    exists(AttrNode attr |
      attr = call.getFunction() and
      attr.getObject().toString() = "re" and
      attr.getName() = ["match", "search", "sub", "escape"]
    )
  ) or
  // html.escape
  exists(CallNode call |
    call = sanitizer.asExpr() and
    exists(AttrNode attr |
      attr = call.getFunction() and
      attr.getObject().toString() = "html" and
      attr.getName() = "escape"
    )
  ) or
  // urllib.parse.quote
  exists(CallNode call |
    call = sanitizer.asExpr() and
    exists(AttrNode attr |
      attr = call.getFunction() and
      attr.getName() = ["quote", "quote_plus"] and
      exists(AttrNode obj |
        obj = attr.getObject() and
        obj.getObject().toString() = "urllib" and
        obj.getName() = "parse"
      )
    )
  ) or
  // bleach.clean
  exists(CallNode call |
    call = sanitizer.asExpr() and
    exists(AttrNode attr |
      attr = call.getFunction() and
      attr.getObject().toString() = "bleach" and
      attr.getName() = "clean"
    )
  )
select sanitizer.getLocation(),
       "Input sanitization: " + sanitizer.toString(),
       sanitizer.getLocation().getFile().getRelativePath(),
       sanitizer.getLocation().getStartLine(),
       sanitizer.getLocation().getStartColumn(),
       sanitizer.getLocation().getEndLine(),
       sanitizer.getLocation().getEndColumn()
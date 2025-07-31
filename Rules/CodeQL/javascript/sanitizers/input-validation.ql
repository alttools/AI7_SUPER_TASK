/**
 * @name Input validation and sanitization
 * @description Finds input validation and sanitization functions
 * @kind problem
 * @problem.severity info
 * @id js/input-validation-sanitizer
 * @tags security
 */

import javascript

from DataFlow::Node sanitizer
where 
  // String validation methods
  exists(CallExpr call |
    call = sanitizer.asExpr() and
    (
      // Built-in validation
      call.getCalleeName() = ["test", "match", "search", "replace", "trim", "escape"] and
      exists(DataFlow::Node receiver |
        receiver = call.getReceiver() and
        receiver.analyze().getAType() = TTString()
      )
    ) or (
      // Common validation libraries
      call.getCalleeName() = ["isEmail", "isURL", "isAlphanumeric", "isInt", "escape", "sanitize", "validate"] or
      // Validator.js methods
      exists(PropAccess pa |
        pa = call.getCallee() and
        pa.getBase().toString() = "validator" and
        pa.getPropertyName().matches("is%")
      )
    )
  ) or
  // Regular expression test
  exists(CallExpr call |
    call = sanitizer.asExpr() and
    call.getCalleeName() = "test" and
    call.getReceiver().analyze().getAType() = TTRegExp()
  ) or
  // DOMPurify and similar
  exists(CallExpr call |
    call = sanitizer.asExpr() and
    call.getCalleeName() = ["sanitize", "clean"] and
    call.getReceiver().toString() = ["DOMPurify", "sanitizeHtml"]
  )
select sanitizer.getLocation(),
       "Input sanitization: " + sanitizer.toString(),
       sanitizer.getFile().getRelativePath(),
       sanitizer.getLocation().getStartLine(),
       sanitizer.getLocation().getStartColumn(),
       sanitizer.getLocation().getEndLine(),
       sanitizer.getLocation().getEndColumn()
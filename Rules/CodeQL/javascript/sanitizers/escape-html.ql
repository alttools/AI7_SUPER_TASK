/**
 * @name HTML escaping functions
 * @description Finds HTML escaping functions
 * @kind problem
 * @problem.severity info
 * @id js/html-escape-sanitizer
 * @tags security
 */

import javascript

from DataFlow::Node sanitizer, CallExpr call
where 
  call = sanitizer.asExpr() and
  (
    // Common escape functions
    call.getCalleeName() = ["escapeHtml", "escape", "escapeHTML", "encodeHTML", "htmlEscape", "sanitize"] or
    // Lodash/underscore escape
    (
      call.getCalleeName() = "escape" and
      call.getReceiver().toString() = ["_", "lodash"]
    ) or
    // he.encode, entities.encode
    (
      call.getCalleeName() = ["encode", "escape"] and
      call.getReceiver().toString() = ["he", "entities", "html-entities"]
    ) or
    // Express/EJS escape
    exists(PropAccess pa |
      pa = call.getCallee() and
      pa.getBase().toString() = "ejs" and
      pa.getPropertyName() = "escape"
    )
  )
select sanitizer.getLocation(),
       "HTML escaping: " + sanitizer.toString(),
       sanitizer.getFile().getRelativePath(),
       sanitizer.getLocation().getStartLine(),
       sanitizer.getLocation().getStartColumn(),
       sanitizer.getLocation().getEndLine(),
       sanitizer.getLocation().getEndColumn()
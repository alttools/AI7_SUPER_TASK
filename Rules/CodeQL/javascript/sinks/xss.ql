/**
 * @name Cross-site scripting sinks
 * @description Finds HTML/DOM manipulation sinks that could lead to XSS
 * @kind problem
 * @problem.severity error
 * @id js/xss-sink
 * @tags security
 *       external/cwe/cwe-79
 */

import javascript

from DataFlow::Node sink
where 
  // DOM manipulation
  exists(PropAccess pa |
    pa = sink.asExpr() and
    pa.getPropertyName() = ["innerHTML", "outerHTML"] and
    pa.isLValue()
  ) or
  // document.write
  exists(CallExpr call |
    call = sink.asExpr() and
    call.getCalleeName() = ["write", "writeln"] and
    call.getReceiver().toString() = "document"
  ) or
  // jQuery html()
  exists(CallExpr call |
    call = sink.asExpr() and
    call.getCalleeName() = "html" and
    call.getNumArgument() > 0 and
    call.getReceiver().toString().matches("$(%)")
  ) or
  // React dangerouslySetInnerHTML
  exists(PropAccess pa |
    pa = sink.asExpr() and
    pa.getPropertyName() = "dangerouslySetInnerHTML"
  ) or
  // res.send/write without escaping
  exists(CallExpr call |
    call = sink.asExpr() and
    call.getCalleeName() = ["send", "write", "end"] and
    call.getReceiver().toString() = "res"
  )
select sink.getLocation(),
       "XSS sink: " + sink.toString(),
       sink.getFile().getRelativePath(),
       sink.getLocation().getStartLine(),
       sink.getLocation().getStartColumn(),
       sink.getLocation().getEndLine(),
       sink.getLocation().getEndColumn()
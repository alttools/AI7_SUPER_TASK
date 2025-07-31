/**
 * @name User input sources in Java
 * @description Finds sources of user-controlled input in Java web applications
 * @kind problem
 * @problem.severity warning
 * @id java/user-input-source
 * @tags security
 *       external/cwe/cwe-20
 */

import java
import semmle.code.java.dataflow.FlowSources

from DataFlow::Node source
where 
  source instanceof RemoteFlowSource or
  // Servlet request parameters
  exists(MethodAccess ma |
    ma = source.asExpr() and
    ma.getMethod().hasName(["getParameter", "getParameterValues", "getHeader", "getHeaders", "getCookies", "getInputStream", "getReader"]) and
    ma.getQualifier().getType().hasQualifiedName("javax.servlet.http", "HttpServletRequest")
  ) or
  // Spring request parameters
  exists(Parameter p |
    p = source.asParameter() and
    p.getAnAnnotation().getType().hasName(["RequestParam", "PathVariable", "RequestHeader", "RequestBody", "CookieValue"])
  ) or
  // JAX-RS parameters
  exists(Parameter p |
    p = source.asParameter() and
    p.getAnAnnotation().getType().hasName(["QueryParam", "PathParam", "HeaderParam", "FormParam", "CookieParam"])
  )
select source.getLocation(),
       "User input source: " + source.toString(),
       source.getLocation().getFile().getRelativePath(),
       source.getLocation().getStartLine(),
       source.getLocation().getStartColumn(),
       source.getLocation().getEndLine(),
       source.getLocation().getEndColumn()
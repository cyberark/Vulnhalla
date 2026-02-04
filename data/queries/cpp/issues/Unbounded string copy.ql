/**
 * @name Unbounded string copy
 * @description Using unbounded string copy functions like strcpy or strcat
 *              with user-controlled input can lead to buffer overflow.
 * @kind path-problem
 * @id cpp/unbounded-string-copy
 * @problem.severity error
 * @security-severity 9.0
 * @precision medium
 * @tags security
 *       reliability
 *       external/cwe/cwe-119
 *       external/cwe/cwe-120
 *       external/cwe/cwe-676
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.security.FlowSources
import UnboundedCopy::PathGraph

/**
 * A call to an unbounded string copy function.
 */
class UnboundedStringCopyCall extends FunctionCall {
  UnboundedStringCopyCall() {
    this.getTarget().hasGlobalOrStdName([
      "strcpy",
      "strcat",
      "wcscpy",
      "wcscat",
      "_tcscpy",
      "_tcscat",
      "lstrcpy",
      "lstrcpyA",
      "lstrcpyW",
      "lstrcat",
      "lstrcatA",
      "lstrcatW"
    ])
  }

  /**
   * Gets the source argument (the string being copied).
   */
  Expr getSourceArgument() {
    result = this.getArgument(1)
  }

  /**
   * Gets the destination argument.
   */
  Expr getDestinationArgument() {
    result = this.getArgument(0)
  }
}

/**
 * A call to gets() which is always dangerous.
 */
class GetsCall extends FunctionCall {
  GetsCall() {
    this.getTarget().hasGlobalOrStdName(["gets", "_getws"])
  }
}

module UnboundedCopyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof FlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(UnboundedStringCopyCall call |
      sink.asExpr() = call.getSourceArgument() or
      sink.asIndirectExpr() = call.getSourceArgument()
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    // If there's a length check before the copy, it might be safe
    exists(FunctionCall fc |
      fc.getTarget().hasGlobalOrStdName(["strlen", "wcslen", "strnlen"]) and
      node.asExpr() = fc.getAnArgument()
    )
  }
}

module UnboundedCopy = TaintTracking::Global<UnboundedCopyConfig>;

from FunctionCall call, UnboundedCopy::PathNode source, UnboundedCopy::PathNode sink
where
  UnboundedCopy::flowPath(source, sink) and
  exists(UnboundedStringCopyCall ucall |
    call = ucall and
    (sink.getNode().asExpr() = ucall.getSourceArgument() or
     sink.getNode().asIndirectExpr() = ucall.getSourceArgument())
  )
select call, source, sink,
  "This call to " + call.getTarget().getName() +
  " copies $@ without bounds checking, potentially causing buffer overflow.",
  source.getNode(), "user-controlled data"

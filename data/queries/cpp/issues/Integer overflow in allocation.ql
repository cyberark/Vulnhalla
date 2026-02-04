/**
 * @name Integer overflow in allocation size
 * @description Using user-controlled integer values in memory allocation size
 *              calculations can lead to integer overflow and heap overflow.
 * @kind path-problem
 * @id cpp/integer-overflow-allocation
 * @problem.severity error
 * @security-severity 8.1
 * @precision medium
 * @tags security
 *       reliability
 *       external/cwe/cwe-190
 *       external/cwe/cwe-680
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.security.FlowSources
import IntegerOverflow::PathGraph

/**
 * A memory allocation function call.
 */
class AllocationCall extends FunctionCall {
  int sizeArgIndex;

  AllocationCall() {
    exists(string name | name = this.getTarget().getName() |
      (name = "malloc" and sizeArgIndex = 0) or
      (name = "calloc" and sizeArgIndex = 0) or  // first arg is count
      (name = "realloc" and sizeArgIndex = 1) or
      (name = "reallocarray" and sizeArgIndex = 1) or
      (name = "alloca" and sizeArgIndex = 0) or
      (name = "_alloca" and sizeArgIndex = 0) or
      (name = "_malloca" and sizeArgIndex = 0) or
      (name = "HeapAlloc" and sizeArgIndex = 2) or
      (name = "GlobalAlloc" and sizeArgIndex = 1) or
      (name = "LocalAlloc" and sizeArgIndex = 1) or
      (name = "VirtualAlloc" and sizeArgIndex = 1)
    )
  }

  /**
   * Gets the size argument of the allocation.
   */
  Expr getSizeArgument() {
    result = this.getArgument(sizeArgIndex)
  }
}

/**
 * An arithmetic operation that could overflow.
 */
class ArithmeticInSize extends Expr {
  ArithmeticInSize() {
    (this instanceof MulExpr or
     this instanceof AddExpr or
     this instanceof LShiftExpr) and
    exists(AllocationCall alloc |
      this.getParent*() = alloc.getSizeArgument()
    )
  }
}

module IntegerOverflowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof FlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(AllocationCall alloc, ArithmeticInSize arith |
      arith.getParent*() = alloc.getSizeArgument() and
      (sink.asExpr() = arith.getAChild*() or
       sink.asIndirectExpr() = arith.getAChild*())
    )
    or
    exists(AllocationCall alloc |
      sink.asExpr() = alloc.getSizeArgument() or
      sink.asIndirectExpr() = alloc.getSizeArgument()
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    // Checks for overflow or bounds
    exists(RelationalOperation rel |
      node.asExpr() = rel.getAnOperand()
    )
  }
}

module IntegerOverflow = TaintTracking::Global<IntegerOverflowConfig>;

from AllocationCall alloc, IntegerOverflow::PathNode source, IntegerOverflow::PathNode sink
where
  IntegerOverflow::flowPath(source, sink) and
  (sink.getNode().asExpr().getParent*() = alloc.getSizeArgument() or
   sink.getNode().asIndirectExpr().getParent*() = alloc.getSizeArgument())
select alloc, source, sink,
  "The allocation size is derived from $@ and may overflow, leading to undersized allocation.",
  source.getNode(), "user-controlled input"

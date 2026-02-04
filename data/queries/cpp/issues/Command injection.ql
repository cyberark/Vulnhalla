/**
 * @name Command injection
 * @description Using user-supplied data in a call to system() or similar functions
 *              may allow an attacker to execute arbitrary commands.
 * @kind path-problem
 * @id cpp/command-injection
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @tags security
 *       external/cwe/cwe-78
 *       external/cwe/cwe-88
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.security.FlowSources
import CommandInjection::PathGraph

/**
 * A function call that executes a command through the shell.
 */
class ShellCommandExecution extends FunctionCall {
  ShellCommandExecution() {
    this.getTarget().hasGlobalOrStdName([
      "system",
      "popen",
      "execl",
      "execle",
      "execlp",
      "execv",
      "execve",
      "execvp",
      "execvpe",
      "_popen",
      "_wpopen",
      "_wsystem"
    ])
  }

  /**
   * Gets the argument that specifies the command to execute.
   */
  Expr getCommandArgument() {
    // For system/popen, the command is the first argument
    if this.getTarget().hasGlobalOrStdName(["system", "popen", "_popen", "_wpopen", "_wsystem"])
    then result = this.getArgument(0)
    else
      // For exec* functions, the command is also the first argument
      result = this.getArgument(0)
  }
}

module CommandInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof FlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(ShellCommandExecution call |
      sink.asExpr() = call.getCommandArgument() or
      sink.asIndirectExpr() = call.getCommandArgument()
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    // Sanitization through validation functions (basic heuristic)
    exists(FunctionCall fc |
      fc.getTarget().getName().toLowerCase().matches(["%valid%", "%sanitiz%", "%escape%", "%check%"]) and
      node.asExpr() = fc
    )
  }
}

module CommandInjection = TaintTracking::Global<CommandInjectionConfig>;

from ShellCommandExecution call, CommandInjection::PathNode source, CommandInjection::PathNode sink
where
  CommandInjection::flowPath(source, sink) and
  (sink.getNode().asExpr() = call.getCommandArgument() or
   sink.getNode().asIndirectExpr() = call.getCommandArgument())
select call, source, sink,
  "This command execution uses $@ which may be controlled by an attacker.",
  source.getNode(), "user-supplied data"

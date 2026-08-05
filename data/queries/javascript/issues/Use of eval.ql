/**
 * @name Use of eval
 * @description Calls to eval can execute attacker-controlled JavaScript.
 * @kind problem
 * @problem.severity warning
 * @security-severity 9.8
 * @precision high
 * @id js/use-of-eval
 * @tags security
 *       external/cwe/cwe-095
 */
import javascript

from CallExpr call, VarAccess callee
where
  not call.getTopLevel().isExterns() and
  callee = call.getCallee().stripParens() and
  callee.getName() = "eval"
select call, "Use of eval may execute untrusted code."

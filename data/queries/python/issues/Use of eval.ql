/**
 * @name Use of eval
 * @description Calling Python's eval function can execute attacker-controlled code when its input is untrusted.
 * @kind problem
 * @id py/use-of-eval
 * @problem.severity warning
 * @security-severity 8.8
 * @precision medium
 * @tags security
 *       external/cwe/cwe-095
 */

import python
private import semmle.python.ApiGraphs

from CallNode call
where call = API::builtin("eval").getACall().asCfgNode()
select call, "Calling eval may execute attacker-controlled Python code."

import python
import semmle.python.types.FunctionObject

private predicate isReviewableFunction(Function f) {
  f.inSource() and
  not f.getName() = "lambda" and
  not f.getName() = "listcomp" and
  not f.getName() = "setcomp" and
  not f.getName() = "dictcomp" and
  not f.getName() = "genexpr"
}

private int getFunctionStartLine(Function f) {
  result = f.getLocation().getStartLine() and
  not exists(f.getADecorator())
  or
  result = min([f.getLocation().getStartLine(), f.getADecorator().getLocation().getStartLine()])
}

private int getClassStartLine(Class c) {
  result = c.getLocation().getStartLine() and
  not exists(c.getADecorator())
  or
  result = min([c.getLocation().getStartLine(), c.getADecorator().getLocation().getStartLine()])
}

private int getScopeEndLine(Scope s) {
  result = max(Stmt statement | s.contains(statement) | statement.getLocation().getEndLine())
  or
  not exists(s.getAStmt()) and result = s.getLocation().getEndLine()
}

private string getModuleName(Module m) {
  if exists(m.getName()) then result = m.getName() else result = m.getFile().getStem()
}

private string getFunctionName(Function f) {
  result = getModuleName(f.getEnclosingModule()) + "." + f.getQualifiedName()
}

private string getClassBodyName(Class c) {
  result = getModuleName(c.getEnclosingModule()) + "." + c.getQualifiedName() + ".<class_body>"
}

private string getModuleBodyName(Module m) {
  result = getModuleName(m) + ".<module>"
}

private string getFunctionId(Function f) {
  result = f.getLocation().getFile().toString() + ":" + getFunctionStartLine(f).toString()
}

private string getClassBodyId(Class c) {
  result = "class:" + c.getLocation().getFile().toString() + ":" + getClassStartLine(c).toString()
}

private string getModuleBodyId(Module m) {
  result = "module:" + m.getFile().toString()
}

private string getScopeId(Scope s) {
  result = getFunctionId(s.(Function))
  or
  result = getClassBodyId(s.(Class))
  or
  result = getModuleBodyId(s.(Module))
}

private predicate isReviewableCallerScope(Scope caller) {
  caller instanceof Function and isReviewableFunction(caller.(Function))
  or caller instanceof Class and caller.(Class).inSource()
  or caller instanceof Module and caller.(Module).inSource()
}

/**
 * Resolves a direct name call through the exact Python variable binding.
 *
 * This is a narrow fallback for source-level calls that the points-to call graph
 * does not resolve. Requiring the definition and call names to share the same
 * Variable, and requiring that variable to have a single store, avoids
 * repository-wide same-name guessing.
 */
private predicate directNameCall(Scope caller, Function callee) {
  exists(FunctionDef definition, Name definitionName, Call call, Name calledName, Variable binding |
    definition.getDefinedFunction() = callee and
    definitionName = definition.getATarget().(Name) and
    calledName = call.getFunc().(Name) and
    definitionName.getVariable() = binding and
    calledName.getVariable() = binding and
    definitionName = binding.getAStore() and
    not exists(Name otherStore |
      otherStore = binding.getAStore() and
      otherStore != definitionName
    ) and
    caller = call.getScope() and
    isReviewableCallerScope(caller)
  )
}

private predicate calls(Scope caller, Function callee) {
  exists(PyFunctionObject target, CallNode call |
    callee = target.getFunction() and
    (
      call = target.getAFunctionCall()
      or
      call = target.getAMethodCall()
    ) and
    caller = call.getScope() and
    isReviewableCallerScope(caller)
  )
  or
  directNameCall(caller, callee)
}

private string getCaller(Function f) {
  exists(Scope caller | calls(caller, f) | result = getScopeId(caller))
  or
  not exists(Scope caller | calls(caller, f)) and result = ""
}

private predicate functionRow(
  string functionName, File sourceFile, int startLine, string functionId, int endLine, string callerId
) {
  exists(Function f |
    isReviewableFunction(f) and
    functionName = getFunctionName(f) and
    sourceFile = f.getLocation().getFile() and
    startLine = getFunctionStartLine(f) and
    functionId = getFunctionId(f) and
    endLine = getScopeEndLine(f) and
    callerId = getCaller(f)
  )
}

private predicate classBodyRow(
  string functionName, File sourceFile, int startLine, string functionId, int endLine, string callerId
) {
  exists(Class c |
    c.inSource() and
    functionName = getClassBodyName(c) and
    sourceFile = c.getLocation().getFile() and
    startLine = getClassStartLine(c) and
    functionId = getClassBodyId(c) and
    endLine = getScopeEndLine(c) and
    callerId = getModuleBodyId(c.getEnclosingModule())
  )
}

private predicate moduleBodyRow(
  string functionName, File sourceFile, int startLine, string functionId, int endLine, string callerId
) {
  exists(Module m |
    m.inSource() and
    functionName = getModuleBodyName(m) and
    sourceFile = m.getFile() and
    startLine = 1 and
    functionId = getModuleBodyId(m) and
    endLine = max([1, getScopeEndLine(m)]) and
    callerId = ""
  )
}

from string functionName, File sourceFile, int startLine, string functionId, int endLine, string callerId
where
  functionRow(functionName, sourceFile, startLine, functionId, endLine, callerId)
  or classBodyRow(functionName, sourceFile, startLine, functionId, endLine, callerId)
  or moduleBodyRow(functionName, sourceFile, startLine, functionId, endLine, callerId)
select
  functionName as function_name,
  sourceFile as file,
  startLine as start_line,
  functionId as function_id,
  endLine as end_line,
  callerId as caller_id

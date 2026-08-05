import javascript

private predicate isSourceNode(AstNode n) {
  not n.getTopLevel().isExterns()
}

private string getFunctionId(Function f) {
  result = f.getFile().toString() + ":" +
    f.getLocation().getStartLine().toString() + ":" +
    f.getLocation().getStartColumn().toString()
}

private string getClassBodyId(ClassDefinition c) {
  result = "class:" + c.getFile().toString() + ":" + c.getLocation().getStartLine().toString()
}

private string getCallerId(InvokeExpr invoke) {
  result = getFunctionId(invoke.getEnclosingFunction())
  or
  not exists(invoke.getEnclosingFunction()) and
  exists(ClassDefinition c |
    c = invoke.getParent*() and
    result = getClassBodyId(c)
  )
  or
  not exists(invoke.getEnclosingFunction()) and
  not exists(ClassDefinition c | c = invoke.getParent*()) and
  result = "module:" + invoke.getFile().toString()
}

private string getExprName(Expr e) {
  result = e.stripParens().(VarAccess).getName()
  or
  exists(PropAccess access, ThisExpr base |
    access = e.stripParens() and
    base = access.getBase().stripParens() and
    result = "this." + access.getPropertyName()
  )
  or
  result = e.stripParens().(PropAccess).getQualifiedName()
  or
  e.stripParens() instanceof ThisExpr and result = "this"
}

private predicate invocationRow(
  string callerId, File sourceFile, int lineNumber, int columnNumber,
  string callKind, string calleeName, string receiverName, string targetFunctionId
) {
  exists(MethodCallExpr call |
    isSourceNode(call) and
    callerId = getCallerId(call) and
    sourceFile = call.getFile() and
    lineNumber = call.getLocation().getStartLine() and
    columnNumber = call.getLocation().getStartColumn() and
    callKind = "method" and
    calleeName = call.getMethodName() and
    receiverName = getExprName(call.getReceiver()) and
    targetFunctionId = ""
  )
  or
  exists(CallExpr call |
    isSourceNode(call) and
    not call instanceof MethodCallExpr and
    callerId = getCallerId(call) and
    sourceFile = call.getFile() and
    lineNumber = call.getLocation().getStartLine() and
    columnNumber = call.getLocation().getStartColumn() and
    callKind = "call" and
    calleeName = getExprName(call.getCallee()) and
    receiverName = "" and
    targetFunctionId = ""
  )
  or
  exists(NewExpr call |
    isSourceNode(call) and
    callerId = getCallerId(call) and
    sourceFile = call.getFile() and
    lineNumber = call.getLocation().getStartLine() and
    columnNumber = call.getLocation().getStartColumn() and
    callKind = "constructor" and
    calleeName = getExprName(call.getCallee()) and
    receiverName = "" and
    targetFunctionId = ""
  )
}

private predicate callbackRow(
  string callerId, File sourceFile, int lineNumber, int columnNumber,
  string callKind, string calleeName, string receiverName, string targetFunctionId
) {
  exists(InvokeExpr call, int index, Function callback |
    isSourceNode(call) and
    callback = call.getArgument(index).stripParens() and
    callerId = getCallerId(call) and
    sourceFile = call.getFile() and
    lineNumber = call.getLocation().getStartLine() and
    columnNumber = call.getLocation().getStartColumn() and
    callKind = "callback" and
    calleeName = callback.getName() and
    receiverName = "" and
    targetFunctionId = getFunctionId(callback)
  )
  or
  exists(InvokeExpr call, int index, VarAccess callback |
    isSourceNode(call) and
    callback = call.getArgument(index).stripParens() and
    callerId = getCallerId(call) and
    sourceFile = call.getFile() and
    lineNumber = call.getLocation().getStartLine() and
    columnNumber = call.getLocation().getStartColumn() and
    callKind = "callback" and
    calleeName = callback.getName() and
    receiverName = "" and
    targetFunctionId = ""
  )
}

from string callerId, File sourceFile, int lineNumber, int columnNumber,
  string callKind, string calleeName, string receiverName, string targetFunctionId
where
  invocationRow(callerId, sourceFile, lineNumber, columnNumber, callKind, calleeName, receiverName, targetFunctionId)
  or callbackRow(callerId, sourceFile, lineNumber, columnNumber, callKind, calleeName, receiverName, targetFunctionId)
select
  callerId as caller_id,
  sourceFile as file,
  lineNumber as line,
  columnNumber as column,
  callKind as call_kind,
  calleeName as callee_name,
  receiverName as receiver_name,
  targetFunctionId as target_function_id

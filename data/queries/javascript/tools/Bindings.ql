import javascript

private predicate isSourceNode(AstNode n) {
  not n.getTopLevel().isExterns()
}

private string getFunctionId(Function f) {
  result = f.getFile().toString() + ":" +
    f.getLocation().getStartLine().toString() + ":" +
    f.getLocation().getStartColumn().toString()
}

private string getScopeId(Expr n) {
  result = getFunctionId(n.getEnclosingFunction())
  or
  not exists(n.getEnclosingFunction()) and result = "module:" + n.getFile().toString()
}

private string getExprName(Expr e) {
  result = e.stripParens().(VarAccess).getName()
  or
  result = e.stripParens().(PropAccess).getQualifiedName()
}

private predicate variableConstructorBinding(
  string scopeId, string bindingName, string targetName,
  string bindingKind, File sourceFile, int line
) {
  exists(VariableDeclarator declaration, VarDecl local, NewExpr init |
    isSourceNode(declaration) and
    declaration.getBindingPattern() = local and
    declaration.getInit().stripParens() = init and
    scopeId = getScopeId(declaration) and
    bindingName = local.getName() and
    targetName = getExprName(init.getCallee()) and
    bindingKind = "constructor" and
    sourceFile = declaration.getFile() and
    line = declaration.getLocation().getStartLine()
  )
}

private predicate thisConstructorBinding(
  string scopeId, string bindingName, string targetName,
  string bindingKind, File sourceFile, int line
) {
  exists(AssignExpr assignment, PropAccess target, ThisExpr base, NewExpr init |
    isSourceNode(assignment) and
    target = assignment.getLhs() and
    base = target.getBase() and
    assignment.getRhs().stripParens() = init and
    scopeId = getScopeId(assignment) and
    bindingName = "this." + target.getPropertyName() and
    targetName = getExprName(init.getCallee()) and
    bindingKind = "constructor" and
    sourceFile = assignment.getFile() and
    line = assignment.getLocation().getStartLine()
  )
}

private predicate variableAliasBinding(
  string scopeId, string bindingName, string targetName,
  string bindingKind, File sourceFile, int line
) {
  exists(VariableDeclarator declaration, VarDecl local, Expr init |
    isSourceNode(declaration) and
    declaration.getBindingPattern() = local and
    declaration.getInit().stripParens() = init and
    not init instanceof NewExpr and
    exists(getExprName(init)) and
    scopeId = getScopeId(declaration) and
    bindingName = local.getName() and
    targetName = getExprName(init) and
    bindingKind = "alias" and
    sourceFile = declaration.getFile() and
    line = declaration.getLocation().getStartLine()
  )
}

private predicate objectBinding(
  string scopeId, string bindingName, string targetName,
  string bindingKind, File sourceFile, int line
) {
  exists(VariableDeclarator declaration, VarDecl local, ObjectExpr init |
    isSourceNode(declaration) and
    declaration.getBindingPattern() = local and
    declaration.getInit().stripParens() = init and
    scopeId = getScopeId(declaration) and
    bindingName = local.getName() and
    targetName = local.getName() and
    bindingKind = "object" and
    sourceFile = declaration.getFile() and
    line = declaration.getLocation().getStartLine()
  )
}

from string scopeId, string bindingName, string targetName,
  string bindingKind, File sourceFile, int lineNumber
where
  variableConstructorBinding(scopeId, bindingName, targetName, bindingKind, sourceFile, lineNumber)
  or thisConstructorBinding(scopeId, bindingName, targetName, bindingKind, sourceFile, lineNumber)
  or variableAliasBinding(scopeId, bindingName, targetName, bindingKind, sourceFile, lineNumber)
  or objectBinding(scopeId, bindingName, targetName, bindingKind, sourceFile, lineNumber)
select
  scopeId as scope_id,
  bindingName as binding_name,
  targetName as target_name,
  bindingKind as binding_kind,
  sourceFile as file,
  lineNumber as line

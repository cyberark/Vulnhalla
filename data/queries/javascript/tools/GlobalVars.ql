import javascript

private predicate isSourceNode(AstNode n) {
  not n.getTopLevel().isExterns()
}

private predicate moduleVariable(
  string globalName, File sourceFile, int startLine, int endLine
) {
  exists(VariableDeclarator declaration, VarDecl local, DeclStmt statement |
    isSourceNode(declaration) and
    declaration.getBindingPattern() = local and
    statement = declaration.getDeclStmt() and
    statement.getContainer() instanceof TopLevel and
    globalName = sourceFile.getRelativePath() + "::" + local.getName() and
    sourceFile = declaration.getFile() and
    startLine = statement.getLocation().getStartLine() and
    endLine = statement.getLocation().getEndLine()
  )
}

private predicate explicitGlobalProperty(
  string globalName, File sourceFile, int startLine, int endLine
) {
  exists(AssignExpr assignment, PropAccess target, VarAccess base |
    isSourceNode(assignment) and
    not exists(assignment.getEnclosingFunction()) and
    target = assignment.getLhs() and
    base = target.getBase() and
    base.getName() = ["globalThis", "global", "window", "exports"] and
    globalName = sourceFile.getRelativePath() + "::" + target.getPropertyName() and
    sourceFile = assignment.getFile() and
    startLine = assignment.getLocation().getStartLine() and
    endLine = assignment.getLocation().getEndLine()
  )
}

from string globalName, File sourceFile, int startLine, int endLine
where
  moduleVariable(globalName, sourceFile, startLine, endLine)
  or explicitGlobalProperty(globalName, sourceFile, startLine, endLine)
select
  globalName as global_var_name,
  sourceFile as file,
  startLine as start_line,
  endLine as end_line

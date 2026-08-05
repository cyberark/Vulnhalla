import javascript

private predicate isSourceNode(AstNode n) {
  not n.getTopLevel().isExterns()
}

private string getClassSimpleName(ClassDefinition c) {
  result = c.getIdentifier().getName()
  or
  exists(VarDef vd | c = vd.getSource() | result = vd.getTarget().(VarRef).getName())
  or
  not exists(c.getIdentifier()) and
  not exists(VarDef vd | c = vd.getSource()) and
  result = "<anonymous_class>@" + c.getLocation().getStartLine().toString()
}

private predicate prototypePart(
  string ownerName, File sourceFile, int startLine, int endLine
) {
  exists(AssignExpr assignment, PropAccess target, PropAccess prototype, VarAccess owner |
    isSourceNode(assignment) and
    target = assignment.getLhs() and
    prototype = target.getBase() and
    prototype.getPropertyName() = "prototype" and
    owner = prototype.getBase() and
    ownerName = owner.getName() and
    sourceFile = assignment.getFile() and
    startLine = assignment.getLocation().getStartLine() and
    endLine = assignment.getLocation().getEndLine()
  )
  or
  exists(Function constructor |
    isSourceNode(constructor) and
    constructor.getName() = ownerName and
    sourceFile = constructor.getFile() and
    exists(AssignExpr assignment, PropAccess target, PropAccess prototype, VarAccess owner |
      assignment.getFile() = sourceFile and
      target = assignment.getLhs() and
      prototype = target.getBase() and
      prototype.getPropertyName() = "prototype" and
      owner = prototype.getBase() and
      owner.getName() = ownerName
    ) and
    startLine = constructor.getLocation().getStartLine() and
    endLine = constructor.getLocation().getEndLine()
  )
}

private predicate classRow(
  string typeName, string className, File sourceFile,
  int startLine, int endLine, string simpleName
) {
  exists(ClassDefinition c |
    isSourceNode(c) and
    typeName = "Class" and
    simpleName = getClassSimpleName(c) and
    className = c.getFile().getRelativePath() + "::" + simpleName and
    sourceFile = c.getFile() and
    startLine = c.getLocation().getStartLine() and
    endLine = c.getLocation().getEndLine()
  )
  or
  exists(string owner |
    prototypePart(owner, sourceFile, _, _) and
    typeName = "PrototypeClass" and
    simpleName = owner and
    className = sourceFile.getRelativePath() + "::" + owner and
    startLine = min(int line | exists(int e | prototypePart(owner, sourceFile, line, e)) | line) and
    endLine = max(int line | exists(int s | prototypePart(owner, sourceFile, s, line)) | line)
  )
}

from string typeName, string className, File sourceFile,
  int startLine, int endLine, string simpleName
where classRow(typeName, className, sourceFile, startLine, endLine, simpleName)
select
  typeName as type,
  className as class_name,
  sourceFile as file,
  startLine as start_line,
  endLine as end_line,
  simpleName as simple_name

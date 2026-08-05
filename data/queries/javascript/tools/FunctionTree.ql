import javascript

private predicate isSourceTopLevel(TopLevel tl) {
  not tl.isExterns()
}

private predicate isReviewableFunction(Function f) {
  exists(f.getBody()) and isSourceTopLevel(f.getTopLevel())
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

private predicate isClassMemberFunction(Function f) {
  exists(MemberDeclaration member | member.getInit() = f)
}

private predicate isPrototypeMethod(Function f) {
  exists(AssignExpr assignment, PropAccess target, PropAccess prototype |
    assignment.getRhs().getUnderlyingValue() = f and
    target = assignment.getLhs() and
    prototype = target.getBase() and
    prototype.getPropertyName() = "prototype"
  )
}

private predicate isNamedObjectMethod(Function f) {
  exists(Property property, ObjectExpr object, VariableDeclarator declaration |
    property.getInit() = f and
    object = property.getObjectExpr() and
    declaration.getInit() = object and
    declaration.getBindingPattern() instanceof VarDecl
  )
}

private string getLocalFunctionName(Function f) {
  exists(MemberDeclaration member, ClassDefinition c |
    member.getInit() = f and c = member.getDeclaringClass()
  |
    result = getClassSimpleName(c) + "." + member.getName()
  )
  or
  exists(AssignExpr assignment, PropAccess target, PropAccess prototype, VarAccess owner |
    assignment.getRhs().getUnderlyingValue() = f and
    target = assignment.getLhs() and
    prototype = target.getBase() and
    prototype.getPropertyName() = "prototype" and
    owner = prototype.getBase()
  |
    result = owner.getName() + "." + target.getPropertyName()
  )
  or
  exists(Property property, ObjectExpr object, VariableDeclarator declaration, VarDecl owner |
    property.getInit() = f and
    object = property.getObjectExpr() and
    declaration.getInit() = object and
    declaration.getBindingPattern() = owner
  |
    result = owner.getName() + "." + property.getName()
  )
  or
  not isClassMemberFunction(f) and not isPrototypeMethod(f) and not isNamedObjectMethod(f) and
  exists(f.getName()) and result = f.getName()
  or
  not isClassMemberFunction(f) and not isPrototypeMethod(f) and not isNamedObjectMethod(f) and
  not exists(f.getName()) and
  result = "<anonymous>@" + f.getLocation().getStartLine().toString()
}

private int getFunctionStartLine(Function f) {
  result = f.getLocation().getStartLine() and
  not exists(MemberDeclaration member | member.getInit() = f)
  or
  exists(MemberDeclaration member | member.getInit() = f |
    result = min([member.getLocation().getStartLine(), member.getADecorator().getLocation().getStartLine()])
    or
    not exists(member.getADecorator()) and result = member.getLocation().getStartLine()
  )
}

private int getFunctionEndLine(Function f) {
  result = f.getLocation().getEndLine() and
  not exists(MemberDeclaration member | member.getInit() = f)
  or
  exists(MemberDeclaration member | member.getInit() = f |
    result = member.getLocation().getEndLine()
  )
}

private string getFunctionName(Function f) {
  result = f.getFile().getRelativePath() + "::" + getLocalFunctionName(f)
}

private string getFunctionId(Function f) {
  result = f.getFile().toString() + ":" +
    f.getLocation().getStartLine().toString() + ":" +
    f.getLocation().getStartColumn().toString()
}

private string getModuleId(File file) {
  result = "module:" + file.toString()
}

private string getClassBodyId(ClassDefinition c) {
  result = "class:" + c.getFile().toString() + ":" + c.getLocation().getStartLine().toString()
}

private int getFileEndLine(File file) {
  result = max(int line | exists(AstNode n | n.getFile() = file | line = n.getLocation().getEndLine()) | line)
  or
  not exists(AstNode n | n.getFile() = file) and result = 1
}

private predicate functionRow(
  string functionName, File sourceFile, int startLine, string functionId, int endLine, string callerId
) {
  exists(Function f |
    isReviewableFunction(f) and
    functionName = getFunctionName(f) and
    sourceFile = f.getFile() and
    startLine = getFunctionStartLine(f) and
    functionId = getFunctionId(f) and
    endLine = getFunctionEndLine(f) and
    callerId = ""
  )
}

private predicate classBodyRow(
  string functionName, File sourceFile, int startLine, string functionId, int endLine, string callerId
) {
  exists(ClassDefinition c |
    isSourceTopLevel(c.getTopLevel()) and
    functionName = c.getFile().getRelativePath() + "::" + getClassSimpleName(c) + ".<class_body>" and
    sourceFile = c.getFile() and
    startLine = c.getLocation().getStartLine() and
    functionId = getClassBodyId(c) and
    endLine = c.getLocation().getEndLine() and
    callerId = getModuleId(c.getFile())
  )
}

private predicate moduleRow(
  string functionName, File sourceFile, int startLine, string functionId, int endLine, string callerId
) {
  exists(TopLevel tl |
    isSourceTopLevel(tl) and sourceFile = tl.getFile()
  ) and
  functionName = sourceFile.getRelativePath() + "::<module>" and
  startLine = 1 and
  functionId = getModuleId(sourceFile) and
  endLine = getFileEndLine(sourceFile) and
  callerId = ""
}

from string functionName, File sourceFile, int startLine, string functionId, int endLine, string callerId
where
  functionRow(functionName, sourceFile, startLine, functionId, endLine, callerId)
  or classBodyRow(functionName, sourceFile, startLine, functionId, endLine, callerId)
  or moduleRow(functionName, sourceFile, startLine, functionId, endLine, callerId)
select
  functionName as function_name,
  sourceFile as file,
  startLine as start_line,
  functionId as function_id,
  endLine as end_line,
  callerId as caller_id

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

private string getResolvedFile(Import imp) {
  result = imp.getImportedFile().toString()
  or
  not exists(imp.getImportedFile()) and result = ""
}

private string getResolvedReExportFile(ReExportDeclaration declaration) {
  result = declaration.getReExportedModule().getFile().toString()
  or
  not exists(declaration.getReExportedModule()) and result = ""
}

private string getNamespaceImportedName(ImportSpecifier spec) {
  result = spec.getImportedName()
  or
  spec instanceof ImportNamespaceSpecifier and result = "*"
}

private predicate esmImport(
  string localName, string importedModule, string importedName,
  File sourceFile, string scopeId, int startLine, string sourceModule,
  string resolvedFile, string importKind
) {
  exists(ImportDeclaration declaration, ImportSpecifier spec |
    isSourceNode(declaration) and
    spec = declaration.getASpecifier() and
    localName = spec.getLocal().getName() and
    importedModule = declaration.getRawImportPath() and
    importedName = getNamespaceImportedName(spec) and
    sourceFile = declaration.getFile() and
    scopeId = "module:" + declaration.getFile().toString() and
    startLine = declaration.getLocation().getStartLine() and
    sourceModule = declaration.getFile().getRelativePath() and
    resolvedFile = getResolvedFile(declaration) and
    importKind = "esm"
  )
}

private predicate commonJsWholeImport(
  string localName, string importedModule, string importedName,
  File sourceFile, string scopeId, int startLine, string sourceModule,
  string resolvedFile, string importKind
) {
  exists(VariableDeclarator declaration, VarDecl local, Require req |
    isSourceNode(declaration) and
    declaration.getBindingPattern() = local and
    declaration.getInit().stripParens() = req and
    localName = local.getName() and
    importedModule = req.getArgument(0).getStringValue() and
    importedName = "*" and
    sourceFile = declaration.getFile() and
    scopeId = getScopeId(declaration) and
    startLine = declaration.getLocation().getStartLine() and
    sourceModule = declaration.getFile().getRelativePath() and
    resolvedFile = getResolvedFile(req) and
    importKind = "commonjs"
  )
}

private predicate commonJsMemberImport(
  string localName, string importedModule, string importedName,
  File sourceFile, string scopeId, int startLine, string sourceModule,
  string resolvedFile, string importKind
) {
  exists(VariableDeclarator declaration, VarDecl local, PropAccess member, Require req |
    isSourceNode(declaration) and
    declaration.getBindingPattern() = local and
    declaration.getInit().stripParens() = member and
    member.getBase().stripParens() = req and
    localName = local.getName() and
    importedModule = req.getArgument(0).getStringValue() and
    importedName = member.getPropertyName() and
    sourceFile = declaration.getFile() and
    scopeId = getScopeId(declaration) and
    startLine = declaration.getLocation().getStartLine() and
    sourceModule = declaration.getFile().getRelativePath() and
    resolvedFile = getResolvedFile(req) and
    importKind = "commonjs_member"
  )
}

private predicate commonJsDestructuredImport(
  string localName, string importedModule, string importedName,
  File sourceFile, string scopeId, int startLine, string sourceModule,
  string resolvedFile, string importKind
) {
  exists(
    VariableDeclarator declaration, ObjectPattern pattern,
    PropertyPattern property, VarRef local, Require req
  |
    isSourceNode(declaration) and
    declaration.getBindingPattern() = pattern and
    property = pattern.getAPropertyPattern() and
    local = property.getValuePattern().(BindingPattern).getABindingVarRef() and
    declaration.getInit().stripParens() = req and
    localName = local.getName() and
    importedModule = req.getArgument(0).getStringValue() and
    importedName = property.getName() and
    sourceFile = declaration.getFile() and
    scopeId = getScopeId(declaration) and
    startLine = declaration.getLocation().getStartLine() and
    sourceModule = declaration.getFile().getRelativePath() and
    resolvedFile = getResolvedFile(req) and
    importKind = "commonjs_destructured"
  )
}

private predicate localDefaultExport(
  string localName, string importedModule, string importedName,
  File sourceFile, string scopeId, int startLine, string sourceModule,
  string resolvedFile, string importKind
) {
  exists(ExportDefaultDeclaration declaration, VarDecl target |
    isSourceNode(declaration) and
    target = declaration.getADecl() and
    localName = "default" and importedModule = "" and
    importedName = target.getName() and
    sourceFile = declaration.getFile() and
    scopeId = "module:" + declaration.getFile().toString() and
    startLine = declaration.getLocation().getStartLine() and
    sourceModule = declaration.getFile().getRelativePath() and
    resolvedFile = declaration.getFile().toString() and
    importKind = "export_local"
  )
  or
  exists(ExportDefaultDeclaration declaration, VarAccess target |
    isSourceNode(declaration) and
    target = declaration.getOperand().(Expr).stripParens() and
    localName = "default" and importedModule = "" and
    importedName = target.getName() and
    sourceFile = declaration.getFile() and
    scopeId = "module:" + declaration.getFile().toString() and
    startLine = declaration.getLocation().getStartLine() and
    sourceModule = declaration.getFile().getRelativePath() and
    resolvedFile = declaration.getFile().toString() and
    importKind = "export_local"
  )
  or
  exists(ExportDefaultDeclaration declaration |
    isSourceNode(declaration) and
    not exists(declaration.getADecl()) and
    not declaration.getOperand() instanceof VarAccess and
    localName = "default" and importedModule = "" and
    importedName = "<default>" and
    sourceFile = declaration.getFile() and
    scopeId = "module:" + declaration.getFile().toString() and
    startLine = declaration.getLocation().getStartLine() and
    sourceModule = declaration.getFile().getRelativePath() and
    resolvedFile = declaration.getFile().toString() and
    importKind = "export_local"
  )
}

private predicate localNamedExport(
  string localName, string importedModule, string importedName,
  File sourceFile, string scopeId, int startLine, string sourceModule,
  string resolvedFile, string importKind
) {
  exists(ExportNamedDeclaration declaration, Identifier target |
    isSourceNode(declaration) and
    not declaration instanceof ReExportDeclaration and
    target = declaration.getAnExportedDecl() and
    localName = target.getName() and importedModule = "" and
    importedName = target.getName() and
    sourceFile = declaration.getFile() and
    scopeId = "module:" + declaration.getFile().toString() and
    startLine = declaration.getLocation().getStartLine() and
    sourceModule = declaration.getFile().getRelativePath() and
    resolvedFile = declaration.getFile().toString() and
    importKind = "export_local"
  )
  or
  exists(ExportNamedDeclaration declaration, ExportSpecifier spec |
    isSourceNode(declaration) and
    not declaration instanceof ReExportDeclaration and
    spec = declaration.getASpecifier() and
    localName = spec.getExportedName() and importedModule = "" and
    importedName = spec.getLocalName() and
    sourceFile = declaration.getFile() and
    scopeId = "module:" + declaration.getFile().toString() and
    startLine = declaration.getLocation().getStartLine() and
    sourceModule = declaration.getFile().getRelativePath() and
    resolvedFile = declaration.getFile().toString() and
    importKind = "export_local"
  )
}

private predicate selectiveReExport(
  string localName, string importedModule, string importedName,
  File sourceFile, string scopeId, int startLine, string sourceModule,
  string resolvedFile, string importKind
) {
  exists(SelectiveReExportDeclaration declaration, ExportSpecifier spec |
    isSourceNode(declaration) and
    spec = declaration.getASpecifier() and
    localName = spec.getExportedName() and
    importedModule = declaration.getImportedPath().getStringValue() and
    importedName = spec.getLocalName() and
    sourceFile = declaration.getFile() and
    scopeId = "module:" + declaration.getFile().toString() and
    startLine = declaration.getLocation().getStartLine() and
    sourceModule = declaration.getFile().getRelativePath() and
    resolvedFile = getResolvedReExportFile(declaration) and
    importKind = "reexport"
  )
}

private predicate bulkReExport(
  string localName, string importedModule, string importedName,
  File sourceFile, string scopeId, int startLine, string sourceModule,
  string resolvedFile, string importKind
) {
  exists(BulkReExportDeclaration declaration |
    isSourceNode(declaration) and
    localName = "*" and
    importedModule = declaration.getImportedPath().getStringValue() and
    importedName = "*" and
    sourceFile = declaration.getFile() and
    scopeId = "module:" + declaration.getFile().toString() and
    startLine = declaration.getLocation().getStartLine() and
    sourceModule = declaration.getFile().getRelativePath() and
    resolvedFile = getResolvedReExportFile(declaration) and
    importKind = "reexport_all"
  )
}

from string localName, string importedModule, string importedName,
  File sourceFile, string scopeId, int startLine, string sourceModule,
  string resolvedFile, string importKind
where
  esmImport(localName, importedModule, importedName, sourceFile, scopeId, startLine,
    sourceModule, resolvedFile, importKind)
  or commonJsWholeImport(localName, importedModule, importedName, sourceFile, scopeId,
    startLine, sourceModule, resolvedFile, importKind)
  or commonJsMemberImport(localName, importedModule, importedName, sourceFile, scopeId,
    startLine, sourceModule, resolvedFile, importKind)
  or commonJsDestructuredImport(localName, importedModule, importedName, sourceFile, scopeId,
    startLine, sourceModule, resolvedFile, importKind)
  or localDefaultExport(localName, importedModule, importedName, sourceFile, scopeId,
    startLine, sourceModule, resolvedFile, importKind)
  or localNamedExport(localName, importedModule, importedName, sourceFile, scopeId,
    startLine, sourceModule, resolvedFile, importKind)
  or selectiveReExport(localName, importedModule, importedName, sourceFile, scopeId,
    startLine, sourceModule, resolvedFile, importKind)
  or bulkReExport(localName, importedModule, importedName, sourceFile, scopeId,
    startLine, sourceModule, resolvedFile, importKind)
select
  localName as local_name,
  importedModule as imported_module,
  importedName as imported_name,
  sourceFile as file,
  scopeId as scope_id,
  startLine as start_line,
  sourceModule as source_module,
  resolvedFile as resolved_file,
  importKind as import_kind

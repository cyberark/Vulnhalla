import python

private int getFunctionStartLine(Function f) {
  result = f.getLocation().getStartLine() and not exists(f.getADecorator())
  or
  result = min([f.getLocation().getStartLine(), f.getADecorator().getLocation().getStartLine()])
}

private int getClassStartLine(Class c) {
  result = c.getLocation().getStartLine() and not exists(c.getADecorator())
  or
  result = min([c.getLocation().getStartLine(), c.getADecorator().getLocation().getStartLine()])
}

private string getFunctionId(Function f) {
  result = f.getLocation().getFile().toString() + ":" + getFunctionStartLine(f).toString()
}

private string getScopeId(Scope s) {
  result = getFunctionId(s.(Function))
  or
  result = "module:" + s.(Module).getFile().toString()
  or
  result = "class:" + s.(Class).getLocation().getFile().toString() + ":" + getClassStartLine(s.(Class)).toString()
}

private string getModuleName(Module m) {
  if exists(m.getName()) then result = m.getName() else result = m.getFile().getStem()
}

private string importedModule(Alias a) {
  result = a.getValue().(ImportExpr).getImportedModuleName()
  or
  result = a.getValue().(ImportMember).getModule().(ImportExpr).getImportedModuleName()
}

private string importedName(Alias a) {
  a.getValue() instanceof ImportExpr and result = ""
  or
  result = a.getValue().(ImportMember).getName()
}

from Import i, Alias a, Name local
where
  i.getEnclosingModule().inSource() and
  a = i.getAName() and
  local = a.getAsname()
select
  local.getId() as local_name,
  importedModule(a) as imported_module,
  importedName(a) as imported_name,
  i.getLocation().getFile() as file,
  getScopeId(i.getScope()) as scope_id,
  i.getLocation().getStartLine() as start_line,
  getModuleName(i.getEnclosingModule()) as source_module

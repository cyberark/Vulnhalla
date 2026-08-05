import python

private int getStartLine(Class c) {
  result = c.getLocation().getStartLine() and
  not exists(c.getADecorator())
  or
  result = min([c.getLocation().getStartLine(), c.getADecorator().getLocation().getStartLine()])
}

private int getEndLine(Class c) {
  result = max(Stmt statement | c.contains(statement) | statement.getLocation().getEndLine())
  or
  not exists(c.getAStmt()) and result = c.getLocation().getEndLine()
}

private string getModuleName(Module m) {
  if exists(m.getName()) then result = m.getName() else result = m.getFile().getStem()
}

private string getClassName(Class c) {
  result = getModuleName(c.getEnclosingModule()) + "." + c.getQualifiedName()
}

from Class c
where c.inSource()
select
  "Class" as type,
  getClassName(c) as class_name,
  c.getLocation().getFile() as file,
  getStartLine(c) as start_line,
  getEndLine(c) as end_line,
  c.getName() as simple_name

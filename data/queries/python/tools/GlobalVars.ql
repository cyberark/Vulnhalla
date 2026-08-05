import python

private Stmt getStoreStatement(GlobalVariable g) {
  exists(Name store |
    store = g.getAStore() and
    store.getScope() = g.getScope() and
    result.contains(store) and
    not exists(Stmt inner |
      result.contains(inner) and
      inner.contains(store)
    )
  )
}

private Stmt getInitialStoreStatement(GlobalVariable g) {
  result = getStoreStatement(g) and
  not exists(Stmt earlier |
    earlier = getStoreStatement(g) and
    earlier.getLocation().getStartLine() < result.getLocation().getStartLine()
  )
}

private string getModuleName(Module m) {
  if exists(m.getName()) then result = m.getName() else result = m.getFile().getStem()
}

from GlobalVariable g, Module m, Stmt init
where
  m = g.getScope() and
  m.inSource() and
  init = getInitialStoreStatement(g) and
  not init instanceof FunctionDef and
  not init instanceof ClassDef
select
  getModuleName(m) + "." + g.getId() as global_var_name,
  init.getLocation().getFile() as file,
  init.getLocation().getStartLine() as start_line,
  init.getLocation().getEndLine() as end_line

"""Build JavaScript caller/callee edges from lightweight CodeQL syntax indexes.

The JavaScript CodeQL whole-program call graph is deliberately not used here: on
large projects it is expensive to compile and evaluate, while Vulnhalla only
needs human-style navigation.  The CodeQL queries extract functions, calls,
imports, and simple object bindings.  This module links those indexes and writes
the same ``FunctionTree.csv`` contract used by the existing C/C++ and Python
paths.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path
from typing import DefaultDict, Dict, Iterable, List, Optional, Sequence, Set, Tuple


FUNCTION_FIELDS = [
    "function_name", "file", "start_line", "function_id", "end_line", "caller_id"
]
CLASS_FIELDS = ["type", "class_name", "file", "start_line", "end_line", "simple_name"]


def _clean(value: object) -> str:
    return "" if value is None else str(value).replace('"', "").strip()


def _read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [
            {key: _clean(value) for key, value in row.items() if key is not None}
            for row in csv.DictReader(handle)
        ]


def _write_csv(path: Path, fields: Sequence[str], rows: Iterable[Dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields), extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _local_function_name(row: Dict[str, str]) -> str:
    return row.get("function_name", "").split("::", 1)[-1]


def _simple_name(name: str) -> str:
    return _clean(name).replace("()", "").split(".")[-1]


def _module_scope(file_name: str) -> str:
    return f"module:{file_name}"


def _owner_class(row: Optional[Dict[str, str]]) -> str:
    if not row:
        return ""
    local = _local_function_name(row)
    if local.endswith(".<class_body>"):
        return local[: -len(".<class_body>")]
    if "." in local and not local.startswith("<anonymous"):
        return local.rsplit(".", 1)[0]
    return ""


def _rows_in_file(
    rows: Sequence[Dict[str, str]], file_name: str
) -> List[Dict[str, str]]:
    return [row for row in rows if row.get("file") == file_name]


def _dedupe_by_id(rows: Iterable[Dict[str, str]]) -> List[Dict[str, str]]:
    seen: Set[str] = set()
    result: List[Dict[str, str]] = []
    for row in rows:
        identity = row.get("function_id", "")
        if identity and identity not in seen:
            seen.add(identity)
            result.append(row)
    return result


class JavaScriptNavigationLinker:
    """Resolve lightweight JavaScript call records to extracted functions."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        raw_functions = _read_csv(db_path / "FunctionTree.csv")
        # The final FunctionTree may contain one row per caller.  Collapse it
        # before linking so the finalizer is safe to run more than once.
        canonical: Dict[str, Dict[str, str]] = {}
        for row in raw_functions:
            function_id = row.get("function_id", "")
            if not function_id:
                continue
            canonical_row = dict(row)
            # Only synthetic class bodies have a structural caller that comes
            # directly from CodeQL. Ordinary function callers are regenerated
            # from Calls.csv so this finalizer is safe to run repeatedly.
            if not _local_function_name(row).endswith(".<class_body>"):
                canonical_row["caller_id"] = ""
            canonical.setdefault(function_id, canonical_row)
        self.functions = list(canonical.values())
        self.calls = _read_csv(db_path / "Calls.csv")
        self.imports = _read_csv(db_path / "Imports.csv")
        self.bindings = _read_csv(db_path / "Bindings.csv")
        self.import_rows = [
            row for row in self.imports
            if not row.get("import_kind", "").startswith(("export_", "reexport"))
        ]
        self.exports_by_file: DefaultDict[str, List[Dict[str, str]]] = defaultdict(list)
        for row in self.imports:
            if row.get("import_kind", "").startswith(("export_", "reexport")):
                self.exports_by_file[row.get("file", "")].append(row)
        self.by_id = {
            row["function_id"]: row for row in self.functions if row.get("function_id")
        }
        self.by_file: DefaultDict[str, List[Dict[str, str]]] = defaultdict(list)
        self.global_simple_functions: DefaultDict[str, List[Dict[str, str]]] = defaultdict(list)
        self.global_method_functions: DefaultDict[str, List[Dict[str, str]]] = defaultdict(list)
        for row in self.functions:
            file_name = row.get("file", "")
            local_name = _local_function_name(row)
            self.by_file[file_name].append(row)
            if not local_name.endswith(("<module>", "<class_body>")):
                self.global_simple_functions[_simple_name(local_name)].append(row)
                if "." in local_name:
                    self.global_method_functions[local_name.rsplit(".", 1)[-1]].append(row)

        self.imports_by_scope: DefaultDict[str, List[Dict[str, str]]] = defaultdict(list)
        self.imports_by_scope_name: DefaultDict[
            Tuple[str, str], List[Dict[str, str]]
        ] = defaultdict(list)
        for row in self.import_rows:
            scope_id = row.get("scope_id", "")
            local_name = row.get("local_name", "")
            self.imports_by_scope[scope_id].append(row)
            self.imports_by_scope_name[(scope_id, local_name)].append(row)

        self.bindings_by_scope: DefaultDict[
            Tuple[str, str], List[Dict[str, str]]
        ] = defaultdict(list)
        self.class_field_bindings: DefaultDict[
            Tuple[str, str, str], List[Dict[str, str]]
        ] = defaultdict(list)
        for row in self.bindings:
            scope_id = row.get("scope_id", "")
            binding_name = row.get("binding_name", "")
            self.bindings_by_scope[(scope_id, binding_name)].append(row)
            owner = _owner_class(self.by_id.get(scope_id))
            if owner and binding_name.startswith("this."):
                self.class_field_bindings[
                    (row.get("file", ""), owner, binding_name)
                ].append(row)

        # JavaScript projects contain many repeated calls to the same names and
        # often route imports through barrel files.  These caches keep linking
        # linear in the extracted indexes instead of repeatedly scanning them.
        self._match_cache: Dict[
            Tuple[str, str, str, bool], List[Dict[str, str]]
        ] = {}
        self._export_cache: Dict[Tuple[str, str], List[Tuple[str, str]]] = {}
        self._import_target_cache: Dict[
            Tuple[str, str, str, str, str, str], List[Tuple[str, str]]
        ] = {}
        self._call_cache: Dict[
            Tuple[str, str, str, str, str, str], List[Dict[str, str]]
        ] = {}

    def _visible_imports(
        self, caller_id: str, file_name: str
    ) -> List[Dict[str, str]]:
        return (
            self.imports_by_scope.get(caller_id, [])
            + self.imports_by_scope.get(_module_scope(file_name), [])
        )

    def _import_for_name(
        self, caller_id: str, file_name: str, local_name: str
    ) -> Optional[Dict[str, str]]:
        for scope_id in (caller_id, _module_scope(file_name)):
            rows = self.imports_by_scope_name.get((scope_id, local_name), [])
            if rows:
                return rows[0]
        return None

    def _target_file(self, import_row: Dict[str, str]) -> str:
        resolved = import_row.get("resolved_file", "")
        if resolved:
            return resolved

        raw = import_row.get("imported_module", "")
        source = Path(import_row.get("file", ""))
        if raw.startswith("."):
            candidate = (source.parent / raw).as_posix()
            candidates = [
                candidate,
                candidate + ".js",
                candidate + ".jsx",
                candidate + ".ts",
                candidate + ".tsx",
                candidate + ".mjs",
                candidate + ".cjs",
                str(Path(candidate) / "index.js"),
                str(Path(candidate) / "index.ts"),
            ]
            for item in candidates:
                if item in self.by_file:
                    return item
        return ""

    def _match_in_file(
        self,
        file_name: str,
        requested: str,
        *,
        owner: str = "",
        allow_unique: bool = False,
    ) -> List[Dict[str, str]]:
        cache_key = (file_name, _clean(requested).strip("."), owner, allow_unique)
        cached = self._match_cache.get(cache_key)
        if cached is not None:
            return cached

        candidates = [
            row for row in self.by_file.get(file_name, [])
            if not _local_function_name(row).endswith(("<module>", "<class_body>"))
        ]
        requested = _clean(requested).strip(".")
        names: Set[str] = {requested}
        if owner:
            names.add(f"{owner}.{requested}")

        exact = [row for row in candidates if _local_function_name(row) in names]
        if exact:
            result = _dedupe_by_id(exact)
            self._match_cache[cache_key] = result
            return result

        suffix = [
            row for row in candidates
            if _local_function_name(row).endswith("." + requested)
        ]
        if suffix:
            result = _dedupe_by_id(suffix)
            self._match_cache[cache_key] = result
            return result

        simple = [
            row for row in candidates
            if _simple_name(_local_function_name(row)) == _simple_name(requested)
        ]
        if len(simple) == 1 or allow_unique:
            result = _dedupe_by_id(simple)
            self._match_cache[cache_key] = result
            return result
        self._match_cache[cache_key] = []
        return []

    def _resolve_export(
        self,
        file_name: str,
        exported_name: str,
        seen: Optional[Set[Tuple[str, str]]] = None,
    ) -> List[Tuple[str, str]]:
        """Resolve an ESM export through local aliases and barrel re-exports."""
        key = (file_name, exported_name)
        cached = self._export_cache.get(key)
        if cached is not None:
            return cached
        visited = set() if seen is None else set(seen)
        if not file_name or key in visited:
            return []
        visited.add(key)

        rows = self.exports_by_file.get(file_name, [])
        direct = [row for row in rows if row.get("local_name") == exported_name]
        wildcards = [
            row for row in rows if row.get("import_kind") == "reexport_all"
        ]
        results: List[Tuple[str, str]] = []
        for row in direct:
            kind = row.get("import_kind", "")
            target_name = row.get("imported_name", "") or exported_name
            if kind == "export_local":
                results.append((file_name, target_name))
            elif kind == "reexport":
                target_file = self._target_file(row)
                results.extend(self._resolve_export(target_file, target_name, visited))
        for row in wildcards:
            target_file = self._target_file(row)
            results.extend(self._resolve_export(target_file, exported_name, visited))

        if not results:
            # CommonJS modules and source files without explicit export rows are
            # still directly navigable by their extracted local names.
            results.append((file_name, exported_name))

        deduped: List[Tuple[str, str]] = []
        seen_targets: Set[Tuple[str, str]] = set()
        for target in results:
            if target not in seen_targets:
                seen_targets.add(target)
                deduped.append(target)
        self._export_cache[key] = deduped
        return deduped

    def _resolved_import_targets(
        self,
        import_row: Dict[str, str],
        remainder: str = "",
    ) -> List[Tuple[str, str]]:
        cache_key = (
            import_row.get("file", ""),
            import_row.get("local_name", ""),
            import_row.get("imported_module", ""),
            import_row.get("imported_name", ""),
            import_row.get("import_kind", ""),
            remainder,
        )
        cached = self._import_target_cache.get(cache_key)
        if cached is not None:
            return cached

        target_file = self._target_file(import_row)
        if not target_file:
            self._import_target_cache[cache_key] = []
            return []
        imported_name = import_row.get("imported_name", "")
        kind = import_row.get("import_kind", "")

        if kind.startswith("commonjs"):
            if imported_name == "*":
                target_name = remainder
            else:
                target_name = ".".join(
                    part for part in (imported_name, remainder) if part
                )
            result = [(target_file, target_name)]
            self._import_target_cache[cache_key] = result
            return result

        if imported_name == "*":
            if not remainder:
                result = [(target_file, "*")]
                self._import_target_cache[cache_key] = result
                return result
            first, dot, rest = remainder.partition(".")
            result = [
                (resolved_file, resolved_name + (dot + rest if dot else ""))
                for resolved_file, resolved_name in self._resolve_export(target_file, first)
            ]
            self._import_target_cache[cache_key] = result
            return result

        targets = self._resolve_export(target_file, imported_name or "default")
        result = [
            (resolved_file, resolved_name + ("." + remainder if remainder else ""))
            for resolved_file, resolved_name in targets
        ]
        self._import_target_cache[cache_key] = result
        return result

    def _resolve_imported_function(
        self,
        caller_id: str,
        caller_file: str,
        requested: str,
    ) -> List[Dict[str, str]]:
        first, _, remainder = requested.partition(".")
        import_row = self._import_for_name(caller_id, caller_file, first)
        if not import_row:
            return []

        matches: List[Dict[str, str]] = []
        for target_file, target_name in self._resolved_import_targets(import_row, remainder):
            if target_name == "<default>":
                target_functions = [
                    row for row in self.by_file.get(target_file, [])
                    if not _local_function_name(row).endswith(("<module>", "<class_body>"))
                ]
                if len(target_functions) == 1:
                    matches.extend(target_functions)
                continue
            matches.extend(self._match_in_file(target_file, target_name))
        return _dedupe_by_id(matches)

    def _resolve_class_name(
        self, caller_id: str, caller_file: str, requested: str
    ) -> Tuple[str, str]:
        """Return ``(target_file, class_name)`` for a constructor/class reference."""
        first, _, remainder = requested.partition(".")
        import_row = self._import_for_name(caller_id, caller_file, first)
        if import_row:
            targets = self._resolved_import_targets(import_row, remainder)
            if targets:
                target_file, target_name = targets[0]
                return target_file, target_name.split(".")[0]
        return caller_file, requested.split(".")[0]

    def _binding_targets(
        self,
        caller_id: str,
        caller_file: str,
        owner: str,
        binding_name: str,
    ) -> List[Dict[str, str]]:
        rows = list(self.bindings_by_scope.get((caller_id, binding_name), []))
        rows += self.bindings_by_scope.get((_module_scope(caller_file), binding_name), [])
        if owner and binding_name.startswith("this."):
            rows += self.class_field_bindings.get((caller_file, owner, binding_name), [])
        return rows

    def _resolve_direct(
        self, caller_id: str, caller_file: str, requested: str
    ) -> List[Dict[str, str]]:
        caller = self.by_id.get(caller_id)
        owner = _owner_class(caller)

        imported = self._resolve_imported_function(caller_id, caller_file, requested)
        if imported:
            return imported

        same_file = self._match_in_file(caller_file, requested, owner=owner)
        if same_file:
            return same_file

        # Only accept a repository-wide simple-name fallback when it is unique.
        simple = _simple_name(requested)
        global_matches = _dedupe_by_id(self.global_simple_functions.get(simple, []))
        return global_matches if len(global_matches) == 1 else []

    def _resolve_callback(
        self, caller_id: str, caller_file: str, requested: str
    ) -> List[Dict[str, str]]:
        """Resolve a function passed as an argument without repository-wide guessing.

        A plain variable argument can be ordinary data just as easily as a callback.
        Keep callback edges only when the name is tied to an import or a function in
        the same source file. Inline callbacks already carry an exact function ID.
        """
        caller = self.by_id.get(caller_id)
        owner = _owner_class(caller)
        imported = self._resolve_imported_function(caller_id, caller_file, requested)
        if imported:
            return imported
        return self._match_in_file(caller_file, requested, owner=owner)

    def _resolve_constructor(
        self, caller_id: str, caller_file: str, requested: str
    ) -> List[Dict[str, str]]:
        target_file, class_name = self._resolve_class_name(caller_id, caller_file, requested)
        matches = self._match_in_file(target_file, f"{class_name}.constructor")
        if matches:
            return matches
        # Legacy constructor function.
        return self._match_in_file(target_file, class_name)

    def _resolve_method(
        self,
        caller_id: str,
        caller_file: str,
        receiver: str,
        method: str,
    ) -> List[Dict[str, str]]:
        caller = self.by_id.get(caller_id)
        owner = _owner_class(caller)
        receiver = _clean(receiver)

        if receiver == "this":
            return self._match_in_file(caller_file, method, owner=owner)

        if method in {"call", "apply", "bind"}:
            direct = self._resolve_direct(caller_id, caller_file, receiver)
            if direct:
                return direct

        if receiver.startswith("this."):
            for binding in self._binding_targets(
                caller_id, caller_file, owner, receiver
            ):
                target = binding.get("target_name", "")
                target_file, class_name = self._resolve_class_name(
                    caller_id, caller_file, target
                )
                matches = self._match_in_file(target_file, method, owner=class_name)
                if matches:
                    return matches

        for binding in self._binding_targets(caller_id, caller_file, owner, receiver):
            target = binding.get("target_name", "")
            if binding.get("binding_kind") == "object":
                matches = self._match_in_file(caller_file, f"{target}.{method}")
            elif binding.get("binding_kind") == "alias":
                # An alias may point to an imported namespace/object.
                imported = self._resolve_imported_method(
                    caller_id, caller_file, target, method
                )
                matches = imported or self._match_in_file(
                    caller_file, method, owner=target.split(".")[0]
                )
            else:
                target_file, class_name = self._resolve_class_name(
                    caller_id, caller_file, target
                )
                matches = self._match_in_file(target_file, method, owner=class_name)
            if matches:
                return matches

        imported = self._resolve_imported_method(
            caller_id, caller_file, receiver, method
        )
        if imported:
            return imported

        # Static class call or object-literal method in the current module.
        same_file = self._match_in_file(caller_file, method, owner=receiver)
        if same_file:
            return same_file

        # Avoid guessing among common method names across unrelated classes.
        global_matches = _dedupe_by_id(self.global_method_functions.get(method, []))
        return global_matches if len(global_matches) == 1 else []

    def _resolve_imported_method(
        self,
        caller_id: str,
        caller_file: str,
        receiver: str,
        method: str,
    ) -> List[Dict[str, str]]:
        first, _, remainder = receiver.partition(".")
        import_row = self._import_for_name(caller_id, caller_file, first)
        if not import_row:
            return []

        matches: List[Dict[str, str]] = []
        for target_file, target_name in self._resolved_import_targets(import_row, remainder):
            if target_name == "*":
                matches.extend(self._match_in_file(target_file, method))
                continue

            # Imported module-level objects such as `client` often receive
            # their concrete class through `const client = new Client()`.
            module_id = _module_scope(target_file)
            for binding in self.bindings_by_scope.get((module_id, target_name), []):
                bound_target = binding.get("target_name", "")
                if binding.get("binding_kind") == "object":
                    matches.extend(
                        self._match_in_file(target_file, f"{bound_target}.{method}")
                    )
                else:
                    matches.extend(
                        self._match_in_file(
                            target_file, method, owner=bound_target.split(".")[0]
                        )
                    )

            owner = target_name.split(".")[0]
            matches.extend(self._match_in_file(target_file, method, owner=owner))
            if not matches:
                matches.extend(self._match_in_file(target_file, method))
        return _dedupe_by_id(matches)

    def resolve_call(self, call: Dict[str, str]) -> List[Dict[str, str]]:
        target_id = call.get("target_function_id", "")
        if target_id and target_id in self.by_id:
            return [self.by_id[target_id]]

        caller_id = call.get("caller_id", "")
        caller_file = call.get("file", "")
        kind = call.get("call_kind", "")
        callee = call.get("callee_name", "")
        receiver = call.get("receiver_name", "")
        if not caller_id or not callee:
            return []

        cache_key = (caller_id, caller_file, kind, callee, receiver, target_id)
        cached = self._call_cache.get(cache_key)
        if cached is not None:
            return cached

        if kind == "constructor":
            result = self._resolve_constructor(caller_id, caller_file, callee)
        elif kind == "method":
            result = self._resolve_method(caller_id, caller_file, receiver, callee)
        elif kind == "callback":
            result = self._resolve_callback(caller_id, caller_file, callee)
        else:
            result = self._resolve_direct(caller_id, caller_file, callee)
        self._call_cache[cache_key] = result
        return result

    def link(self) -> List[Dict[str, str]]:
        callers: DefaultDict[str, Set[str]] = defaultdict(set)
        for call in self.calls:
            caller_id = call.get("caller_id", "")
            for target in self.resolve_call(call):
                target_id = target.get("function_id", "")
                if caller_id and target_id and caller_id != target_id:
                    callers[target_id].add(caller_id)

        output: List[Dict[str, str]] = []
        for row in self.functions:
            function_id = row.get("function_id", "")
            fixed_caller = row.get("caller_id", "")
            if fixed_caller:
                output.append(dict(row))
                continue
            function_callers = sorted(callers.get(function_id, set()))
            if function_callers:
                for caller_id in function_callers:
                    linked = dict(row)
                    linked["caller_id"] = caller_id
                    output.append(linked)
            else:
                output.append(dict(row))
        return output


def _merge_class_ranges(db_path: Path) -> None:
    path = db_path / "Classes.csv"
    rows = _read_csv(path)
    grouped: Dict[Tuple[str, str], Dict[str, str]] = {}
    for row in rows:
        key = (row.get("class_name", ""), row.get("file", ""))
        if key not in grouped:
            grouped[key] = dict(row)
            continue
        current = grouped[key]
        current["start_line"] = str(
            min(int(current["start_line"]), int(row["start_line"]))
        )
        current["end_line"] = str(
            max(int(current["end_line"]), int(row["end_line"]))
        )
        if current.get("type") != "Class" and row.get("type") == "Class":
            current["type"] = "Class"
    _write_csv(path, CLASS_FIELDS, grouped.values())


def finalize_javascript_navigation(db_path: str | Path) -> None:
    """Link JavaScript calls and normalize class ranges in a CodeQL database."""
    db = Path(db_path)
    required = ["FunctionTree.csv", "Calls.csv", "Imports.csv", "Bindings.csv"]
    missing = [name for name in required if not (db / name).exists()]
    if missing:
        raise FileNotFoundError(
            f"Cannot finalize JavaScript navigation; missing: {', '.join(missing)}"
        )
    linker = JavaScriptNavigationLinker(db)
    _write_csv(db / "FunctionTree.csv", FUNCTION_FIELDS, linker.link())
    if (db / "Classes.csv").exists():
        _merge_class_ranges(db)

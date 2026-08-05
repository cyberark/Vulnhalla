"""
CodeQL database lookup utilities.

This module provides functions to query CodeQL CSV files (FunctionTree.csv,
Macros.csv, GlobalVars.csv, Classes.csv) and extract code snippets from
the source archive. Python lookups additionally use Imports.csv internally to
resolve aliases without adding another LLM-facing tool.
"""

import csv
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

from src.utils.exceptions import CodeQLError
from src.utils.common_functions import read_file_lines_from_zip
from src.utils.csv_parser import parse_csv_row


class CodeQLDBLookup:
    """
    Encapsulates CodeQL database lookup operations for functions, macros,
    global variables, classes, and caller relationships.
    """

    def _iter_csv_lines(
        self,
        file_path: Union[str, Path],
        file_type_name: str
    ):
        """
        Generator that yields lines from a CSV file, handling file I/O errors.

        This helper centralizes CSV file opening, line iteration, and error handling.
        Each method can iterate over the yielded lines and apply method-specific logic.

        Args:
            file_path: Path to the CSV file to read.
            file_type_name: Descriptive name for the file type (e.g., "Function tree file",
                           "Macros CSV", "GlobalVars CSV") for error messages.

        Yields:
            str: Each line from the CSV file (including newline characters).

        Raises:
            CodeQLError: If file cannot be read (not found, permission denied, etc.).
        """
        try:
            with Path(file_path).open("r", encoding="utf-8") as f:
                while True:
                    line = f.readline()
                    if not line:
                        break
                    yield line
        except (FileNotFoundError, PermissionError, OSError) as e:
            raise self._convert_csv_file_error(e, file_path, file_type_name) from e


    @staticmethod
    def _convert_csv_file_error(
        error: Exception,
        file_path: Union[str, Path],
        file_type_name: str
    ) -> CodeQLError:
        """
        Convert file I/O exceptions to CodeQLError with consistent messaging.

        Args:
            error: The original exception (FileNotFoundError, PermissionError, or OSError).
            file_path: Path to the CSV file that caused the error.
            file_type_name: Descriptive name for the file type (e.g., "Function tree file",
                           "Macros CSV", "GlobalVars CSV") for error messages.

        Returns:
            CodeQLError: Converted exception with appropriate message.
        """
        file_path_str = str(file_path)
        if isinstance(error, FileNotFoundError):
            return CodeQLError(f"{file_type_name} not found: {file_path_str}")
        elif isinstance(error, PermissionError):
            return CodeQLError(f"Permission denied reading {file_type_name}: {file_path_str}")
        elif isinstance(error, OSError):
            return CodeQLError(f"OS error while reading {file_type_name}: {file_path_str}")
        else:
            # Fallback for unexpected exception types
            return CodeQLError(f"Error reading {file_type_name}: {file_path_str}")


    @staticmethod
    def _clean_value(value: Any) -> str:
        """Return a normalized CSV value without CodeQL's surrounding quotes."""
        if value is None:
            return ""
        return str(value).replace('"', '').strip()


    def _read_csv_dicts(
        self,
        file_path: Union[str, Path],
        file_type_name: str
    ) -> List[Dict[str, str]]:
        """Read a CodeQL CSV using its header row (used by Python-only lookups)."""
        try:
            with Path(file_path).open("r", encoding="utf-8", newline="") as csv_file:
                return [
                    {key: self._clean_value(value) for key, value in row.items() if key is not None}
                    for row in csv.DictReader(csv_file)
                ]
        except (FileNotFoundError, PermissionError, OSError) as e:
            raise self._convert_csv_file_error(e, file_path, file_type_name) from e


    @staticmethod
    def _python_normalize_name(name: str) -> str:
        """Normalize a Python symbol as an LLM is likely to provide it."""
        normalized = CodeQLDBLookup._clean_value(name).replace("::", ".")
        if normalized.endswith("()"):
            normalized = normalized[:-2]
        while normalized.startswith("self.") or normalized.startswith("cls."):
            normalized = normalized.split(".", 1)[1]
        return normalized.strip(".")


    @staticmethod
    def _python_canonical_qualified_name(name: str) -> str:
        """Normalize package ``__init__`` names to the package name visible in imports."""
        normalized = CodeQLDBLookup._python_normalize_name(name)
        normalized = normalized.replace(".__init__.", ".")
        if normalized.endswith(".__init__"):
            normalized = normalized[:-9]
        return normalized


    @staticmethod
    def _python_names_equivalent(indexed_name: str, resolved_name: str) -> bool:
        """Compare module-qualified names while tolerating an extracted package-root prefix."""
        indexed = CodeQLDBLookup._python_canonical_qualified_name(indexed_name)
        resolved = CodeQLDBLookup._python_canonical_qualified_name(resolved_name)
        if indexed == resolved:
            return True
        if "." not in indexed or "." not in resolved:
            return False
        return resolved.endswith("." + indexed) or indexed.endswith("." + resolved)


    @staticmethod
    def _python_module_from_function(function: Optional[Dict[str, Any]]) -> str:
        """Infer the module prefix from a function's qualified name and source path."""
        if not function:
            return ""

        qualified_name = CodeQLDBLookup._clean_value(function.get("function_name", ""))
        file_name = CodeQLDBLookup._clean_value(function.get("file", "")).replace("\\", "/")
        if not qualified_name or not file_name:
            return ""

        path_parts = [part for part in file_name.split("/") if part]
        if not path_parts:
            return ""
        path_parts[-1] = Path(path_parts[-1]).stem
        if path_parts[-1] == "__init__":
            path_parts = path_parts[:-1]

        candidates: List[str] = []
        for index in range(len(path_parts)):
            candidate = ".".join(path_parts[index:])
            if candidate and (qualified_name == candidate or qualified_name.startswith(candidate + ".")):
                candidates.append(candidate)
        return max(candidates, key=len) if candidates else ""


    @staticmethod
    def _python_dedupe_rows(rows: Iterable[Dict[str, str]], id_key: str) -> List[Dict[str, str]]:
        """Deduplicate rows while preserving query output order."""
        seen: Set[str] = set()
        result: List[Dict[str, str]] = []
        for row in rows:
            identity = CodeQLDBLookup._clean_value(row.get(id_key, ""))
            if id_key != "function_id":
                identity = "|".join(
                    [
                        identity,
                        CodeQLDBLookup._clean_value(row.get("file", "")),
                        CodeQLDBLookup._clean_value(row.get("start_line", "")),
                    ]
                )
            if not identity.strip("|"):
                identity = repr(sorted(row.items()))
            if identity not in seen:
                seen.add(identity)
                result.append(row)
        return result


    def _python_import_rows(self, curr_db: str) -> List[Dict[str, str]]:
        """Load the internal Python import-binding index when available."""
        imports_file = Path(curr_db) / "Imports.csv"
        if not imports_file.exists():
            return []
        return self._read_csv_dicts(imports_file, "Imports CSV")


    def _python_context_imports(
        self,
        imports: List[Dict[str, str]],
        current_function: Optional[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        """Return visible imports, preferring the current function over its module."""
        if not current_function:
            return []

        function_id = self._clean_value(current_function.get("function_id", ""))
        file_name = self._clean_value(current_function.get("file", ""))
        module_scope = f"module:{file_name}"

        function_rows = [row for row in imports if row.get("scope_id") == function_id]
        module_rows = [row for row in imports if row.get("scope_id") == module_scope]
        return function_rows + module_rows


    def _python_expand_reexport(
        self,
        target: str,
        imports: List[Dict[str, str]],
        depth: int = 0
    ) -> Set[str]:
        """Follow package re-exports such as ``from .models import User``."""
        target = self._python_normalize_name(target)
        results = {target}
        if not target or depth >= 5:
            return results

        for row in imports:
            source_module = self._python_canonical_qualified_name(row.get("source_module", ""))
            local_name = row.get("local_name", "")
            visible_name = ".".join(part for part in (source_module, local_name) if part)
            if target != visible_name and not target.startswith(visible_name + "."):
                continue

            remainder = target[len(visible_name):].lstrip(".")
            imported_module = self._python_canonical_qualified_name(row.get("imported_module", ""))
            imported_name = row.get("imported_name", "")
            replacement = ".".join(
                part for part in (imported_module, imported_name, remainder) if part
            )
            if replacement and replacement != target:
                results.update(self._python_expand_reexport(replacement, imports, depth + 1))
        return results


    def _python_resolve_imported_names(
        self,
        requested_name: str,
        curr_db: str,
        current_function: Optional[Dict[str, Any]]
    ) -> Set[str]:
        """Resolve a name at the current source context through Python import aliases."""
        requested_name = self._python_normalize_name(requested_name)
        imports = self._python_import_rows(curr_db)
        if not requested_name or not imports:
            return set()

        first, _, remainder = requested_name.partition(".")
        resolved: Set[str] = set()
        for row in self._python_context_imports(imports, current_function):
            if row.get("local_name") != first:
                continue

            imported_module = self._python_canonical_qualified_name(row.get("imported_module", ""))
            imported_name = row.get("imported_name", "")
            if imported_name:
                target = ".".join(part for part in (imported_module, imported_name, remainder) if part)
            elif imported_module:
                # ``import pkg.mod`` binds ``pkg`` unless an alias is used. Avoid pkg.mod.mod.X.
                if first == imported_module.split(".")[0] and remainder:
                    target = first + "." + remainder
                else:
                    target = ".".join(part for part in (imported_module, remainder) if part)
            else:
                continue

            resolved.update(self._python_expand_reexport(target, imports))
        return resolved


    @staticmethod
    def _python_ambiguity(kind: str, requested_name: str, candidates: Iterable[str]) -> str:
        choices = ", ".join(sorted(set(candidates)))
        return (
            f"{kind} '{requested_name}' is ambiguous in this Python project. "
            f"Use one of these qualified names: {choices}."
        )


    def _python_entity_candidates(
        self,
        rows: List[Dict[str, str]],
        name_key: str,
        requested_name: str,
        curr_db: str,
        current_function: Optional[Dict[str, Any]],
        *,
        simple_key: Optional[str] = None,
        less_strict: bool = False
    ) -> List[Dict[str, str]]:
        """Resolve a Python class or module binding without guessing among duplicates."""
        requested = self._python_normalize_name(requested_name)
        if not requested:
            return []

        module_name = self._python_module_from_function(current_function)
        current_file = self._clean_value(current_function.get("file", "")) if current_function else ""
        imported_names = self._python_resolve_imported_names(requested, curr_db, current_function)

        # An explicitly qualified name is deterministic.
        exact_requested = [row for row in rows if row.get(name_key, "") == requested]
        if "." in requested and exact_requested:
            return exact_requested

        # Imported aliases should resolve to the imported definition, not only the import line.
        imported_matches = [
            row for row in rows
            if any(
                self._python_names_equivalent(row.get(name_key, ""), imported_name)
                for imported_name in imported_names
            )
        ]
        if imported_matches:
            return imported_matches

        direct_names: Set[str] = {requested}
        if module_name:
            direct_names.add(f"{module_name}.{requested}")
        exact = [row for row in rows if row.get(name_key, "") in direct_names]
        if exact:
            return exact

        # A same-file definition is the next strongest human navigation signal.
        simple_requested = requested.split(".")[-1]
        same_file = []
        for row in rows:
            row_simple = row.get(simple_key, "") if simple_key else row.get(name_key, "").split(".")[-1]
            if row_simple == simple_requested and current_file and row.get("file", "") == current_file:
                same_file.append(row)
        if same_file:
            return same_file

        # A unique simple name is safe. Multiple matches are returned as an explicit ambiguity.
        simple_matches = []
        for row in rows:
            row_name = row.get(name_key, "")
            row_simple = row.get(simple_key, "") if simple_key else row_name.split(".")[-1]
            if row_simple == simple_requested or row_name.endswith("." + requested):
                simple_matches.append(row)
        if simple_matches:
            return simple_matches

        if less_strict:
            return [
                row for row in rows
                if requested in row.get(name_key, "")
                or (simple_key and requested in row.get(simple_key, ""))
            ]
        return []


    def _python_get_function_by_name(
        self,
        function_tree_file: str,
        function_name: str,
        all_functions: List[Dict[str, Any]],
        less_strict: bool = False
    ) -> Tuple[Union[str, Dict[str, str]], Optional[Dict[str, str]]]:
        """Python-specific function navigation using call edges and lexical/import context."""
        rows = self._read_csv_dicts(function_tree_file, "Function tree file")
        requested = self._python_normalize_name(function_name)
        if not requested:
            return "Function name cannot be empty.", None

        # First follow the exact CodeQL call edges from the most recently reviewed function.
        for parent in reversed(all_functions):
            parent_id = self._clean_value(parent.get("function_id", ""))
            linked = self._python_dedupe_rows(
                (row for row in rows if row.get("caller_id", "") == parent_id),
                "function_id"
            )
            matches = self._python_match_functions(linked, requested, parent, Path(function_tree_file).parent)
            if len(matches) == 1:
                return matches[0], parent
            if len(matches) > 1:
                return self._python_ambiguity(
                    "Function", function_name, (row["function_name"] for row in matches)
                ), None

        # Static call resolution can be incomplete for dynamic Python. Fall back to safe context resolution.
        current = all_functions[-1] if all_functions else None
        matches = self._python_match_functions(
            rows, requested, current, Path(function_tree_file).parent, less_strict
        )
        matches = self._python_dedupe_rows(matches, "function_id")
        if len(matches) == 1:
            return matches[0], None
        if len(matches) > 1:
            return self._python_ambiguity(
                "Function", function_name, (row["function_name"] for row in matches)
            ), None

        if not less_strict:
            return self._python_get_function_by_name(
                function_tree_file, function_name, all_functions, True
            )
        return (
            f"Function '{function_name}' not found. Make sure you're using "
            "the correct tool and args."
        ), None


    def _python_match_functions(
        self,
        rows: Iterable[Dict[str, str]],
        requested: str,
        current_function: Optional[Dict[str, Any]],
        curr_db: Path,
        less_strict: bool = False
    ) -> List[Dict[str, str]]:
        """Score function candidates by exact, import, class, module, and simple-name context."""
        rows = list(rows)
        requested = self._python_normalize_name(requested)
        module_name = self._python_module_from_function(current_function)
        current_name = self._clean_value(current_function.get("function_name", "")) if current_function else ""

        direct_names: Set[str] = {requested}
        if module_name:
            direct_names.add(f"{module_name}.{requested}")
            relative_name = current_name[len(module_name) + 1:] if current_name.startswith(module_name + ".") else ""
            if "." in relative_name:
                owner = relative_name.rsplit(".", 1)[0]
                direct_names.add(f"{module_name}.{owner}.{requested}")

        exact = [row for row in rows if row.get("function_name", "") in direct_names]
        if exact:
            return exact

        imported_names = self._python_resolve_imported_names(requested, str(curr_db), current_function)
        imported_matches = [
            row for row in rows
            if any(
                self._python_names_equivalent(row.get("function_name", ""), imported_name)
                for imported_name in imported_names
            )
        ]
        if imported_matches:
            return imported_matches

        suffix = [row for row in rows if row.get("function_name", "").endswith("." + requested)]
        if suffix:
            return suffix

        simple = requested.split(".")[-1]
        simple_matches = [
            row for row in rows if row.get("function_name", "").split(".")[-1] == simple
        ]
        if simple_matches:
            return simple_matches

        if less_strict:
            return [row for row in rows if requested in row.get("function_name", "")]
        return []


    @staticmethod
    def _javascript_normalize_name(name: str) -> str:
        """Normalize a JavaScript symbol as it is commonly written in source or tool calls."""
        normalized = CodeQLDBLookup._clean_value(name).strip()
        if normalized.startswith("new "):
            normalized = normalized[4:].strip()
        if normalized.endswith("()"):
            normalized = normalized[:-2]
        while normalized.startswith("this."):
            normalized = normalized[5:]
        return normalized.strip(".")


    @staticmethod
    def _javascript_local_name(indexed_name: str) -> str:
        return CodeQLDBLookup._clean_value(indexed_name).split("::", 1)[-1]


    @staticmethod
    def _javascript_dedupe_rows(
        rows: Iterable[Dict[str, str]], id_key: str
    ) -> List[Dict[str, str]]:
        seen: Set[str] = set()
        result: List[Dict[str, str]] = []
        for row in rows:
            identity = CodeQLDBLookup._clean_value(row.get(id_key, ""))
            if id_key != "function_id":
                identity = "|".join(
                    (
                        identity,
                        CodeQLDBLookup._clean_value(row.get("file", "")),
                        CodeQLDBLookup._clean_value(row.get("start_line", "")),
                    )
                )
            if identity and identity not in seen:
                seen.add(identity)
                result.append(row)
        return result


    @staticmethod
    def _javascript_ambiguity(
        kind: str, requested_name: str, candidates: Iterable[str]
    ) -> str:
        choices = ", ".join(sorted(set(candidates)))
        return (
            f"{kind} '{requested_name}' is ambiguous in this JavaScript project. "
            f"Use one of these qualified names: {choices}."
        )


    def _javascript_import_rows(self, curr_db: str) -> List[Dict[str, str]]:
        imports_file = Path(curr_db) / "Imports.csv"
        if not imports_file.exists():
            return []
        return self._read_csv_dicts(imports_file, "Imports CSV")


    def _javascript_context_imports(
        self,
        imports: List[Dict[str, str]],
        current_function: Optional[Dict[str, Any]],
    ) -> List[Dict[str, str]]:
        if not current_function:
            return []
        function_id = self._clean_value(current_function.get("function_id", ""))
        file_name = self._clean_value(current_function.get("file", ""))
        def is_import(row: Dict[str, str]) -> bool:
            kind = row.get("import_kind", "")
            return not kind.startswith(("export_", "reexport"))

        function_rows = [
            row for row in imports
            if row.get("scope_id") == function_id and is_import(row)
        ]
        module_rows = [
            row for row in imports
            if row.get("scope_id") == f"module:{file_name}" and is_import(row)
        ]
        return function_rows + module_rows


    @staticmethod
    def _javascript_target_file(import_row: Dict[str, str]) -> str:
        resolved = CodeQLDBLookup._clean_value(import_row.get("resolved_file", ""))
        if resolved:
            return resolved

        raw = CodeQLDBLookup._clean_value(import_row.get("imported_module", ""))
        source_file = CodeQLDBLookup._clean_value(import_row.get("file", ""))
        if not raw.startswith(".") or not source_file:
            return ""
        base = (Path(source_file).parent / raw).as_posix()
        # The exact file existence is checked against extracted CSV rows by callers.
        return base


    @staticmethod
    def _javascript_file_matches(candidate_file: str, target_file: str) -> bool:
        candidate = CodeQLDBLookup._clean_value(candidate_file).replace("\\", "/")
        target = CodeQLDBLookup._clean_value(target_file).replace("\\", "/")
        if not candidate or not target:
            return False
        if candidate == target:
            return True
        target_no_ext = str(Path(target).with_suffix(""))
        candidate_no_ext = str(Path(candidate).with_suffix(""))
        if candidate_no_ext == target_no_ext:
            return True
        return candidate_no_ext in {
            str(Path(target_no_ext) / "index"),
            target_no_ext.rstrip("/") + "/index",
        }


    def _javascript_resolve_export(
        self,
        imports: List[Dict[str, str]],
        file_name: str,
        exported_name: str,
        seen: Optional[Set[Tuple[str, str]]] = None,
    ) -> List[Tuple[str, str]]:
        """Resolve local aliases and ESM barrel re-exports to source names."""
        key = (self._clean_value(file_name), self._clean_value(exported_name))
        visited = set() if seen is None else set(seen)
        if not key[0] or key in visited:
            return []
        visited.add(key)

        export_rows = [
            row for row in imports
            if self._clean_value(row.get("file", "")) == key[0]
            and row.get("import_kind", "").startswith(("export_", "reexport"))
        ]
        direct = [row for row in export_rows if row.get("local_name") == key[1]]
        wildcards = [
            row for row in export_rows if row.get("import_kind") == "reexport_all"
        ]
        targets: List[Tuple[str, str]] = []
        for row in direct:
            target_name = row.get("imported_name", "") or key[1]
            if row.get("import_kind") == "export_local":
                targets.append((key[0], target_name))
            elif row.get("import_kind") == "reexport":
                target_file = self._javascript_target_file(row)
                targets.extend(
                    self._javascript_resolve_export(
                        imports, target_file, target_name, visited
                    )
                )
        for row in wildcards:
            target_file = self._javascript_target_file(row)
            targets.extend(
                self._javascript_resolve_export(
                    imports, target_file, key[1], visited
                )
            )

        if not targets:
            targets.append(key)
        result: List[Tuple[str, str]] = []
        seen_targets: Set[Tuple[str, str]] = set()
        for target in targets:
            if target not in seen_targets:
                seen_targets.add(target)
                result.append(target)
        return result


    def _javascript_resolved_import_targets(
        self,
        import_row: Dict[str, str],
        imports: List[Dict[str, str]],
        remainder: str = "",
    ) -> List[Tuple[str, str]]:
        target_file = self._javascript_target_file(import_row)
        if not target_file:
            return []
        imported_name = import_row.get("imported_name", "")
        kind = import_row.get("import_kind", "")

        if kind.startswith("commonjs"):
            target_name = remainder if imported_name == "*" else ".".join(
                part for part in (imported_name, remainder) if part
            )
            return [(target_file, target_name)]

        if imported_name == "*":
            if not remainder:
                return [(target_file, "*")]
            first, dot, rest = remainder.partition(".")
            return [
                (resolved_file, resolved_name + (dot + rest if dot else ""))
                for resolved_file, resolved_name in self._javascript_resolve_export(
                    imports, target_file, first
                )
            ]

        return [
            (
                resolved_file,
                resolved_name + ("." + remainder if remainder else ""),
            )
            for resolved_file, resolved_name in self._javascript_resolve_export(
                imports, target_file, imported_name or "default"
            )
        ]


    def _javascript_import_target(
        self,
        requested_name: str,
        curr_db: str,
        current_function: Optional[Dict[str, Any]],
    ) -> Optional[Tuple[Dict[str, str], str]]:
        requested = self._javascript_normalize_name(requested_name)
        first, _, remainder = requested.partition(".")
        imports = self._javascript_import_rows(curr_db)
        for row in self._javascript_context_imports(imports, current_function):
            if row.get("local_name") == first:
                return row, remainder
        return None


    def _javascript_match_entity_rows(
        self,
        rows: List[Dict[str, str]],
        name_key: str,
        requested_name: str,
        curr_db: str,
        current_function: Optional[Dict[str, Any]],
        *,
        simple_key: Optional[str] = None,
        less_strict: bool = False,
    ) -> List[Dict[str, str]]:
        requested = self._javascript_normalize_name(requested_name)
        if not requested:
            return []

        current_file = self._clean_value(current_function.get("file", "")) if current_function else ""
        simple_requested = requested.split(".")[-1]

        # Explicit file-qualified names are deterministic.
        exact = [row for row in rows if row.get(name_key, "") == requested]
        if "::" in requested and exact:
            return exact

        # The nearest same-file binding wins over repository-wide duplicates.
        same_file = []
        for row in rows:
            row_name = self._javascript_local_name(row.get(name_key, ""))
            row_simple = row.get(simple_key, "") if simple_key else row_name.split(".")[-1]
            if current_file and row.get("file") == current_file and (
                row_name == requested or row_simple == simple_requested
            ):
                same_file.append(row)
        if same_file:
            return same_file

        imported = self._javascript_import_target(
            requested, curr_db, current_function
        )
        if imported:
            import_row, remainder = imported
            imports = self._javascript_import_rows(curr_db)
            imported_matches: List[Dict[str, str]] = []
            target_rows: List[Dict[str, str]] = []
            for target_file, target_name in self._javascript_resolved_import_targets(
                import_row, imports, remainder
            ):
                expected = {
                    target_name,
                    target_name.split(".")[0],
                    target_name.split(".")[-1],
                }
                for row in rows:
                    if target_file and not self._javascript_file_matches(
                        row.get("file", ""), target_file
                    ):
                        continue
                    target_rows.append(row)
                    row_name = self._javascript_local_name(row.get(name_key, ""))
                    row_simple = (
                        row.get(simple_key, "") if simple_key else row_name.split(".")[-1]
                    )
                    if row_simple in expected or row_name in expected:
                        imported_matches.append(row)
            if imported_matches:
                return imported_matches
            unique_target_rows = self._javascript_dedupe_rows(target_rows, name_key)
            if len(unique_target_rows) == 1:
                return unique_target_rows

        simple_matches = []
        for row in rows:
            row_name = self._javascript_local_name(row.get(name_key, ""))
            row_simple = row.get(simple_key, "") if simple_key else row_name.split(".")[-1]
            if row_name == requested or row_simple == simple_requested or row_name.endswith("." + requested):
                simple_matches.append(row)
        if simple_matches:
            return simple_matches

        if less_strict:
            return [
                row for row in rows
                if requested in self._javascript_local_name(row.get(name_key, ""))
                or (simple_key and requested in row.get(simple_key, ""))
            ]
        return []


    def _javascript_match_functions(
        self,
        rows: Iterable[Dict[str, str]],
        requested_name: str,
        curr_db: str,
        current_function: Optional[Dict[str, Any]],
        less_strict: bool = False,
    ) -> List[Dict[str, str]]:
        requested = self._javascript_normalize_name(requested_name)
        rows = list(rows)
        if not requested:
            return []

        current_file = self._clean_value(current_function.get("file", "")) if current_function else ""
        current_local = self._javascript_local_name(
            current_function.get("function_name", "") if current_function else ""
        )
        owner = current_local.rsplit(".", 1)[0] if "." in current_local else ""

        direct_names = {requested}
        if owner:
            direct_names.add(f"{owner}.{requested}")
        exact = [
            row for row in rows
            if self._javascript_local_name(row.get("function_name", "")) in direct_names
        ]
        if exact:
            return exact

        imported = self._javascript_import_target(requested, curr_db, current_function)
        if imported:
            import_row, remainder = imported
            imports = self._javascript_import_rows(curr_db)
            imported_matches: List[Dict[str, str]] = []
            for target_file, target_name in self._javascript_resolved_import_targets(
                import_row, imports, remainder
            ):
                expected = {target_name}
                if target_name == "<default>":
                    target_functions = [
                        row for row in rows
                        if self._javascript_file_matches(row.get("file", ""), target_file)
                        and not self._javascript_local_name(
                            row.get("function_name", "")
                        ).endswith(("<module>", "<class_body>"))
                    ]
                    if len(target_functions) == 1:
                        imported_matches.extend(target_functions)
                    continue
                imported_matches.extend(
                    row for row in rows
                    if self._javascript_file_matches(row.get("file", ""), target_file)
                    and (
                        self._javascript_local_name(row.get("function_name", "")) in expected
                        or any(
                            self._javascript_local_name(
                                row.get("function_name", "")
                            ).endswith("." + name)
                            for name in expected if name
                        )
                    )
                )
            if imported_matches:
                return imported_matches

        same_file = [
            row for row in rows
            if current_file
            and row.get("file") == current_file
            and (
                self._javascript_local_name(row.get("function_name", "")) == requested
                or self._javascript_local_name(row.get("function_name", "")).endswith("." + requested)
            )
        ]
        if same_file:
            return same_file

        simple = requested.split(".")[-1]
        simple_matches = [
            row for row in rows
            if self._javascript_local_name(row.get("function_name", "")).split(".")[-1] == simple
        ]
        if simple_matches:
            return simple_matches
        if less_strict:
            return [
                row for row in rows
                if requested in self._javascript_local_name(row.get("function_name", ""))
            ]
        return []


    def _javascript_get_function_by_name(
        self,
        function_tree_file: str,
        function_name: str,
        all_functions: List[Dict[str, Any]],
        less_strict: bool = False,
    ) -> Tuple[Union[str, Dict[str, str]], Optional[Dict[str, str]]]:
        rows = self._read_csv_dicts(function_tree_file, "Function tree file")
        curr_db = str(Path(function_tree_file).parent)

        # First follow exact caller/callee edges from the latest review context.
        for parent in reversed(all_functions):
            parent_id = self._clean_value(parent.get("function_id", ""))
            linked = self._javascript_dedupe_rows(
                (row for row in rows if row.get("caller_id") == parent_id),
                "function_id",
            )
            matches = self._javascript_dedupe_rows(
                self._javascript_match_functions(
                    linked, function_name, curr_db, parent, less_strict
                ),
                "function_id",
            )
            if len(matches) == 1:
                return matches[0], parent
            if len(matches) > 1:
                return self._javascript_ambiguity(
                    "Function", function_name,
                    (row["function_name"] for row in matches),
                ), None

        current = all_functions[-1] if all_functions else None
        matches = self._javascript_dedupe_rows(
            self._javascript_match_functions(
                rows, function_name, curr_db, current, less_strict
            ),
            "function_id",
        )
        if len(matches) == 1:
            return matches[0], None
        if len(matches) > 1:
            return self._javascript_ambiguity(
                "Function", function_name,
                (row["function_name"] for row in matches),
            ), None
        if not less_strict:
            return self._javascript_get_function_by_name(
                function_tree_file, function_name, all_functions, True
            )
        return (
            f"Function '{function_name}' not found. Make sure you're using "
            "the correct tool and args."
        ), None


    def get_function_by_line(
        self,
        function_tree_file: str,
        file: str,
        line: int
    ) -> Optional[Dict[str, str]]:
        """
        Retrieve the function dictionary from a CSV (FunctionTree.csv) that matches
        the specified file and line coverage.

        Args:
            function_tree_file (str): Path to the FunctionTree.csv file.
            file (str): Name of the file as it appears in the CSV row.
            line (int): A line number within the function's start_line and end_line range.

        Returns:
            Optional[Dict[str, str]]: The matching function row as a dict, or None if not found.
        
        Raises:
            CodeQLError: If function tree file cannot be read (not found, permission denied, etc.).
        """
        keys = ["function_name", "file", "start_line", "function_id", "end_line", "caller_id"]
        for function in self._iter_csv_lines(function_tree_file, "Function tree file"):
            if file in function:
                row_dict = parse_csv_row(function, keys)
                if row_dict and row_dict["start_line"] and row_dict["end_line"]:
                    start = int(row_dict["start_line"])
                    end = int(row_dict["end_line"])
                    if start <= line <= end:
                        return row_dict
        return None


    def get_function_by_name(
            self,
            function_tree_file: str,
            function_name: str,
            all_function: List[Dict[str, Any]],
            less_strict: bool = False,
            language: str = "c"
        ) -> Tuple[Union[str, Dict[str, str]], Optional[Dict[str, str]]]:
            """
            Retrieve a function by searching function_name in FunctionTree.csv.
            If not found, tries partial match if less_strict is True.

            Args:
                function_tree_file (str): Path to FunctionTree.csv.
                function_name (str): Desired function name (e.g., 'MyClass::MyFunc').
                all_function (List[Dict[str, Any]]): A list of known function dictionaries.
                less_strict (bool, optional): If True, use partial matching. Defaults to False.
                language (str, optional): Use ``python`` for context-aware Python resolution.
                    Existing C/C++ behavior remains the default.

            Returns:
                Tuple[Union[str, Dict[str, str]], Optional[Dict[str, str]]]:
                    - The found function (dict) or an error message (str).
                    - The "parent function" that references it, if relevant.
            
            Raises:
                CodeQLError: If function tree file cannot be read (not found, permission denied, etc.).
            """
            if language == "python":
                return self._python_get_function_by_name(
                    function_tree_file, function_name, all_function, less_strict
                )
            if language == "javascript":
                return self._javascript_get_function_by_name(
                    function_tree_file, function_name, all_function, less_strict
                )

            keys = ["function_name", "file", "start_line", "function_id", "end_line", "caller_id"]
            function_name_only = function_name.split("::")[-1]

            for current_function in all_function:
                try:
                    with Path(function_tree_file).open("r", encoding="utf-8") as f:
                        while True:
                            row = f.readline()
                            if not row:
                                break
                            if current_function["function_id"] in row:
                                row_dict = parse_csv_row(row, keys)
                                if not row_dict:
                                    continue

                                candidate_name = row_dict["function_name"].replace("\"", "")
                                if (candidate_name == function_name_only
                                        or (less_strict and function_name_only in candidate_name)):
                                    return row_dict, current_function
                except (FileNotFoundError, PermissionError, OSError) as e:
                    raise self._convert_csv_file_error(e, function_tree_file, "Function tree file") from e

            # Try partial matching if less_strict is False
            if not less_strict:
                return self.get_function_by_name(function_tree_file, function_name, all_function, True)
            else:
                err = (
                    f"Function '{function_name}' not found. Make sure you're using "
                    "the correct tool and args."
                )
                return err, None


    def get_macro(
        self,
        curr_db: str,
        macro_name: str,
        less_strict: bool = False
    ) -> Union[str, Dict[str, str]]:
        """
        Return macro info from Macros.csv for the given macro_name.
        If not found, tries partial match if less_strict is True.

        Args:
            curr_db (str): Path to the current CodeQL database folder.
            macro_name (str): Macro name to search for.
            less_strict (bool, optional): If True, use partial matching.

        Returns:
            Union[str, Dict[str, str]]:
                - A dict with 'macro_name' and 'body' if found,
                - or an error message string if not found.
        
        Raises:
            CodeQLError: If Macros CSV file cannot be read (not found, permission denied, etc.).
        """
        macro_file = Path(curr_db) / "Macros.csv"
        keys = ["macro_name", "body"]

        for macro in self._iter_csv_lines(macro_file, "Macros CSV"):
            if macro_name in macro:
                row_dict = parse_csv_row(macro, keys)
                if not row_dict:
                    continue

                actual_name = row_dict["macro_name"].replace("\"", "")
                if (actual_name == macro_name
                        or (less_strict and macro_name in actual_name)):
                    return row_dict

        if not less_strict:
            return self.get_macro(curr_db, macro_name, True)
        else:
            return (
                f"Macro '{macro_name}' not found. Make sure you're using the correct tool "
                "with correct args."
            )


    def get_global_var(
        self,
        curr_db: str,
        global_var_name: str,
        less_strict: bool = False,
        language: str = "c",
        current_function: Optional[Dict[str, Any]] = None
    ) -> Union[str, Dict[str, str]]:
        """
        Return a global variable from GlobalVars.csv matching global_var_name.
        If not found, tries partial match if less_strict is True.

        Args:
            curr_db (str): Path to current CodeQL database folder.
            global_var_name (str): The name of the global variable to find.
            less_strict (bool, optional): If True, use partial matching.
            language (str, optional): Use ``python`` for context-aware Python resolution.
            current_function (dict, optional): Current Python function used to resolve imports
                and duplicate module-level names.

        Returns:
            Union[str, Dict[str, str]]:
                - A dict with ['global_var_name','file','start_line','end_line'] if found,
                - or an error message string if not found.
        
        Raises:
            CodeQLError: If GlobalVars CSV file cannot be read (not found, permission denied, etc.).
        """
        global_var_file = Path(curr_db) / "GlobalVars.csv"
        keys = ["global_var_name", "file", "start_line", "end_line"]

        if language == "python":
            rows = self._read_csv_dicts(global_var_file, "GlobalVars CSV")
            matches = self._python_dedupe_rows(
                self._python_entity_candidates(
                    rows,
                    "global_var_name",
                    global_var_name,
                    curr_db,
                    current_function,
                    less_strict=less_strict
                ),
                "global_var_name"
            )
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                return self._python_ambiguity(
                    "Global var", global_var_name,
                    (row["global_var_name"] for row in matches)
                )
            if not less_strict:
                return self.get_global_var(
                    curr_db, global_var_name, True, language, current_function
                )
            return (
                f"Global var '{global_var_name}' not found. "
                "Could it be a class or should you use another tool?"
            )

        if language == "javascript":
            rows = self._read_csv_dicts(global_var_file, "GlobalVars CSV")
            matches = self._javascript_dedupe_rows(
                self._javascript_match_entity_rows(
                    rows,
                    "global_var_name",
                    global_var_name,
                    curr_db,
                    current_function,
                    less_strict=less_strict,
                ),
                "global_var_name",
            )
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                return self._javascript_ambiguity(
                    "Global var", global_var_name,
                    (row["global_var_name"] for row in matches),
                )
            if not less_strict:
                return self.get_global_var(
                    curr_db, global_var_name, True, language, current_function
                )
            return (
                f"Global var '{global_var_name}' not found. "
                "Could it be a class or should you use another tool?"
            )

        var_name_only = global_var_name.split("::")[-1]

        for line in self._iter_csv_lines(global_var_file, "GlobalVars CSV"):
            if var_name_only in line:
                data_dict = parse_csv_row(line, keys)
                if not data_dict:
                    continue

                actual_name = data_dict["global_var_name"].replace("\"", "")
                if (actual_name == var_name_only
                        or (less_strict and var_name_only in actual_name)):
                    return data_dict

        if not less_strict:
            return self.get_global_var(curr_db, global_var_name, True)
        else:
            return (
                f"Global var '{global_var_name}' not found. "
                "Could it be a macro or should you use another tool?"
            )


    def get_class(
        self,
        curr_db: str,
        class_name: str,
        less_strict: bool = False,
        language: str = "c",
        current_function: Optional[Dict[str, Any]] = None
    ) -> Union[str, Dict[str, str]]:
        """
        Return class info (type, class_name, file, start_line, end_line, simple_name)
        from Classes.csv for class_name. If not found, tries partial match if less_strict is True.

        Args:
            curr_db (str): Path to current CodeQL database folder.
            class_name (str): The name of the class/struct/union to find.
            less_strict (bool, optional): If True, use partial matching.
            language (str, optional): Use ``python`` for context-aware Python resolution.
            current_function (dict, optional): Current Python function used to resolve imports
                and duplicate class names.

        Returns:
            Union[str, Dict[str, str]]:
                - A dict with keys ['type','class_name','file','start_line','end_line','simple_name']
                - or an error message string if not found.
        
        Raises:
            CodeQLError: If Classes CSV file cannot be read (not found, permission denied, etc.).
        """
        classes_file = Path(curr_db) / "Classes.csv"
        keys = ["type", "class_name", "file", "start_line", "end_line", "simple_name"]

        if language == "python":
            rows = self._read_csv_dicts(classes_file, "Classes CSV")
            matches = self._python_dedupe_rows(
                self._python_entity_candidates(
                    rows,
                    "class_name",
                    class_name,
                    curr_db,
                    current_function,
                    simple_key="simple_name",
                    less_strict=less_strict
                ),
                "class_name"
            )
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                return self._python_ambiguity(
                    "Class", class_name, (row["class_name"] for row in matches)
                )
            if not less_strict:
                return self.get_class(curr_db, class_name, True, language, current_function)
            return f"Class '{class_name}' not found."

        if language == "javascript":
            rows = self._read_csv_dicts(classes_file, "Classes CSV")
            matches = self._javascript_dedupe_rows(
                self._javascript_match_entity_rows(
                    rows,
                    "class_name",
                    class_name,
                    curr_db,
                    current_function,
                    simple_key="simple_name",
                    less_strict=less_strict,
                ),
                "class_name",
            )
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                return self._javascript_ambiguity(
                    "Class", class_name, (row["class_name"] for row in matches)
                )
            if not less_strict:
                return self.get_class(curr_db, class_name, True, language, current_function)
            return f"Class '{class_name}' not found."

        class_name_only = class_name.split("::")[-1]

        for row in self._iter_csv_lines(classes_file, "Classes CSV"):
            if class_name_only in row:
                row_dict = parse_csv_row(row, keys)
                if not row_dict:
                    continue

                actual_class = row_dict["class_name"].replace("\"", "")
                simple_class = row_dict["simple_name"].replace("\"", "")
                if (
                    actual_class == class_name_only
                    or simple_class == class_name_only
                    or (less_strict and class_name_only in actual_class)
                    or (less_strict and class_name_only in simple_class)
                ):
                    return row_dict

        if not less_strict:
            return self.get_class(curr_db, class_name, True)
        else:
            return f"Class '{class_name}' not found. Could it be a Namespace?"


    def get_caller_function(
        self,
        function_tree_file: str,
        current_function: Dict[str, str]
    ) -> Union[str, Dict[str, str]]:
        """
        Return the caller function from function_tree_file that calls current_function.

        Args:
            function_tree_file (str): Path to FunctionTree.csv.
            current_function (Dict[str, str]): The function dictionary whose caller we want.

        Returns:
            Union[str, Dict[str, str]]:
                - Dict describing the caller if found
                - or an error string if the caller wasn't found.
        
        Raises:
            CodeQLError: If function tree file cannot be read (not found, permission denied, etc.).
        """
        keys = ["function_name", "file", "start_line", "function_id", "end_line", "caller_id"]
        caller_id = current_function["caller_id"].replace("\"", "").strip()

        for line in self._iter_csv_lines(function_tree_file, "Function tree file"):
            if caller_id in line:
                data_dict = parse_csv_row(line, keys)
                if not data_dict:
                    continue
                if data_dict["function_id"].replace("\"", "").strip() == caller_id:
                    return data_dict

        # Fallback if 'caller_id' is in format file:line
        maybe_line = caller_id.split(":")
        if len(maybe_line) == 2:
            file_part, line_part = maybe_line
            function = self.get_function_by_line(function_tree_file, file_part[1:], int(line_part))
            if function:
                return function

        return (
            "Caller function was not found. "
            "Make sure you are using the correct tool with the correct args."
        )


    def extract_function_lines_from_db(
        self,
        db_path: str,
        current_function: Dict[str, str],
    ) -> Tuple[str, int, int, List[str]]:
        """
        Extract function lines from the CodeQL database source archive.

        Args:
            db_path (str): Path to the CodeQL database directory.
            current_function (Dict[str, str]): The function dictionary.

        Returns:
            Tuple[str, int, int, List[str]]:
                - file_path (str): The file path (after .replace and [1:])
                - start_line (int): Starting line number
                - end_line (int): Ending line number
                - all_lines (List[str]): Full file splitlines
        """
        src_zip = Path(db_path) / "src.zip"
        file_path = current_function["file"].replace("\"", "")[1:]
        code_file = read_file_lines_from_zip(str(src_zip), file_path)
        lines = code_file.split("\n")

        start_line = int(current_function["start_line"])
        end_line = int(current_function["end_line"])
        return file_path, start_line, end_line, lines


    @staticmethod
    def format_numbered_snippet(file_path: str, start_line: int, snippet_lines: List[str]) -> str:
        """
        Format a code snippet with line numbers.

        Args:
            file_path (str): Path to the source file.
            start_line (int): Starting line number (1-indexed).
            snippet_lines (List[str]): The code lines to format.

        Returns:
            str: Formatted snippet with line numbers.
        """
        snippet = "\n".join(
            f"{start_line + i}: {text}" for i, text in enumerate(snippet_lines)
        )
        return f"file: {file_path}\n{snippet}"

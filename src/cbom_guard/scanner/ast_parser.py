"""Multi-language Tree-sitter AST parser with import & alias resolution."""

from __future__ import annotations

from pathlib import Path

import tree_sitter
import tree_sitter_c
import tree_sitter_cpp
import tree_sitter_go
import tree_sitter_javascript
import tree_sitter_python

from cbom_guard.models import Language, ParsedCall, ParsedFile, ParsedSymbol

EXTENSION_TO_LANGUAGE: dict[str, Language] = {
    ".py": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
    ".ts": Language.JAVASCRIPT,
    ".tsx": Language.JAVASCRIPT,
    ".c": Language.C,
    ".h": Language.C,
    ".cpp": Language.CPP,
    ".cc": Language.CPP,
    ".cxx": Language.CPP,
    ".hpp": Language.CPP,
    ".go": Language.GO,
}


def detect_language(path: Path) -> Language | None:
    """Detect supported programming language from file extension."""
    return EXTENSION_TO_LANGUAGE.get(path.suffix.lower())


def _build_languages() -> dict[Language, tree_sitter.Language]:
    return {
        Language.PYTHON: tree_sitter.Language(tree_sitter_python.language()),
        Language.JAVASCRIPT: tree_sitter.Language(tree_sitter_javascript.language()),
        Language.C: tree_sitter.Language(tree_sitter_c.language()),
        Language.CPP: tree_sitter.Language(tree_sitter_cpp.language()),
        Language.GO: tree_sitter.Language(tree_sitter_go.language()),
    }


def _node_text(node: tree_sitter.Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _strip_quotes(raw: str) -> str:
    if len(raw) >= 2 and raw[0] in ("'", '"', "`") and raw[-1] == raw[0]:
        return raw[1:-1]
    for prefix in ("b", "B", "u", "U", "r", "R", "f", "F"):
        if raw.startswith(prefix) and len(raw) >= 3 and raw[1] in ("'", '"') and raw[-1] == raw[1]:
            return raw[2:-1]
    return raw


def _resolve_dotted_name(name: str, imports: dict[str, str]) -> str:
    if not name:
        return name
    parts = name.split(".")
    head = parts[0]
    if head in imports:
        resolved_head = imports[head]
        if len(parts) == 1:
            return resolved_head
        return f"{resolved_head}.{'.'.join(parts[1:])}"
    return name


def _extract_literal_or_symbol(
    node: tree_sitter.Node,
    source: bytes,
    imports: dict[str, str],
) -> str | int | float | bool | None:
    """Extract a Python/JS/C/Go literal value or resolved symbol name from an AST node."""
    ntype = node.type
    text = _node_text(node, source).strip()

    if ntype in ("integer", "number_literal", "int_literal"):
        try:
            return int(text.replace("_", ""), 0)
        except ValueError:
            try:
                return float(text)
            except ValueError:
                return text

    if ntype in ("float", "float_literal"):
        try:
            return float(text.replace("_", ""))
        except ValueError:
            return text

    if ntype in ("string", "string_literal", "interpreted_string_literal", "raw_string_literal"):
        return _strip_quotes(text)

    if ntype in ("true", "True"):
        return True
    if ntype in ("false", "False"):
        return False
    if ntype in ("none", "None", "null", "nil"):
        return None

    # Handle zero-argument constructor calls like ec.SECP256R1() or hashes.SHA256()
    if ntype in ("call", "call_expression", "new_expression"):
        fn_node = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        if fn_node is not None:
            fn_text = _node_text(fn_node, source).strip()
            return _resolve_dotted_name(fn_text, imports)

    if ntype in (
        "identifier",
        "attribute",
        "member_expression",
        "selector_expression",
        "field_expression",
        "scoped_identifier",
    ):
        return _resolve_dotted_name(text.replace("::", "."), imports)

    return text


class ASTParser:
    """Tree-sitter based multi-language AST parser."""

    def __init__(self) -> None:
        self._languages = _build_languages()
        self._parsers: dict[Language, tree_sitter.Parser] = {
            lang: tree_sitter.Parser(ts_lang) for lang, ts_lang in self._languages.items()
        }

    def parse_file(self, path: Path, language: Language | None = None) -> ParsedFile:
        """Parse a source file into a structured ParsedFile with resolved imports & calls."""
        lang = language or detect_language(path)
        if lang is None or lang not in self._parsers:
            raise ValueError(f"Unsupported language for file: {path}")

        source = path.read_bytes()
        return self.parse_bytes(source=source, path=str(path), language=lang)

    def parse_bytes(self, source: bytes, path: str, language: Language) -> ParsedFile:
        """Parse raw source bytes into a structured ParsedFile."""
        parser = self._parsers[language]
        tree = parser.parse(source)
        root = tree.root_node

        imports: dict[str, str] = {}
        imported_modules: list[str] = []

        if language == Language.PYTHON:
            self._collect_python_imports(root, source, imports, imported_modules)
        elif language == Language.JAVASCRIPT:
            self._collect_js_imports(root, source, imports, imported_modules)
        elif language == Language.GO:
            self._collect_go_imports(root, source, imports, imported_modules)
        elif language in (Language.C, Language.CPP):
            self._collect_c_includes(root, source, imported_modules)

        calls: list[ParsedCall] = []
        symbols: list[ParsedSymbol] = []
        self._walk_calls_and_symbols(
            node=root,
            source=source,
            language=language,
            imports=imports,
            calls=calls,
            symbols=symbols,
        )

        return ParsedFile(
            path=path,
            language=language,
            imports=imports,
            imported_modules=imported_modules,
            calls=calls,
            symbols=symbols,
        )

    def _collect_python_imports(
        self,
        root: tree_sitter.Node,
        source: bytes,
        imports: dict[str, str],
        imported_modules: list[str],
    ) -> None:
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == "import_statement":
                for child in node.children:
                    if child.type == "dotted_name":
                        mod = _node_text(child, source)
                        imported_modules.append(mod)
                        top = mod.split(".")[0]
                        imports.setdefault(top, top)
                        imports[mod] = mod
                    elif child.type == "aliased_import":
                        name_node = child.child_by_field_name("name")
                        alias_node = child.child_by_field_name("alias")
                        if name_node is not None and alias_node is not None:
                            mod = _node_text(name_node, source)
                            alias = _node_text(alias_node, source)
                            imported_modules.append(mod)
                            imports[alias] = mod
            elif node.type == "import_from_statement":
                mod_node = node.child_by_field_name("module_name")
                mod_name = _node_text(mod_node, source) if mod_node is not None else ""
                if mod_name:
                    imported_modules.append(mod_name)
                for child in node.children:
                    if child == mod_node:
                        continue
                    if child.type == "dotted_name":
                        sym = _node_text(child, source)
                        full = f"{mod_name}.{sym}" if mod_name else sym
                        imported_modules.append(full)
                        imports[sym] = full
                    elif child.type == "aliased_import":
                        name_node = child.child_by_field_name("name")
                        alias_node = child.child_by_field_name("alias")
                        if name_node is not None and alias_node is not None:
                            sym = _node_text(name_node, source)
                            alias = _node_text(alias_node, source)
                            full = f"{mod_name}.{sym}" if mod_name else sym
                            imported_modules.append(full)
                            imports[alias] = full
            else:
                stack.extend(reversed(node.children))

    def _collect_js_imports(
        self,
        root: tree_sitter.Node,
        source: bytes,
        imports: dict[str, str],
        imported_modules: list[str],
    ) -> None:
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == "import_statement":
                src_node = node.child_by_field_name("source")
                mod = _strip_quotes(_node_text(src_node, source)) if src_node is not None else ""
                if mod:
                    imported_modules.append(mod)
                for child in node.children:
                    if child.type == "import_clause":
                        self._extract_js_import_clause(child, source, mod, imports)
            elif node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                val_node = node.child_by_field_name("value")
                if val_node is not None and val_node.type == "call_expression":
                    fn_node = val_node.child_by_field_name("function")
                    if fn_node is not None and _node_text(fn_node, source) == "require":
                        args_node = val_node.child_by_field_name("arguments")
                        if args_node is not None and args_node.named_child_count > 0:
                            arg0 = args_node.named_child(0)
                            if arg0 is not None:
                                mod = _strip_quotes(_node_text(arg0, source))
                                imported_modules.append(mod)
                                if name_node is not None:
                                    if name_node.type == "identifier":
                                        imports[_node_text(name_node, source)] = mod
                                    elif name_node.type == "object_pattern":
                                        for prop in name_node.named_children:
                                            if prop.type == "shorthand_property_identifier_pattern":
                                                sym = _node_text(prop, source)
                                                imports[sym] = f"{mod}.{sym}"
                                            elif prop.type == "pair_pattern":
                                                k = prop.child_by_field_name("key")
                                                v = prop.child_by_field_name("value")
                                                if k is not None and v is not None:
                                                    imports[_node_text(v, source)] = (
                                                        f"{mod}.{_node_text(k, source)}"
                                                    )
            stack.extend(reversed(node.children))

    def _extract_js_import_clause(
        self,
        clause: tree_sitter.Node,
        source: bytes,
        mod: str,
        imports: dict[str, str],
    ) -> None:
        for child in clause.named_children:
            if child.type == "identifier":
                imports[_node_text(child, source)] = mod
            elif child.type == "namespace_import":
                for sub in child.named_children:
                    if sub.type == "identifier":
                        imports[_node_text(sub, source)] = mod
            elif child.type == "named_imports":
                for spec in child.named_children:
                    if spec.type == "import_specifier":
                        name_n = spec.child_by_field_name("name")
                        alias_n = spec.child_by_field_name("alias")
                        if name_n is not None:
                            orig = _node_text(name_n, source)
                            local = _node_text(alias_n, source) if alias_n is not None else orig
                            imports[local] = f"{mod}.{orig}" if mod else orig

    def _collect_go_imports(
        self,
        root: tree_sitter.Node,
        source: bytes,
        imports: dict[str, str],
        imported_modules: list[str],
    ) -> None:
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == "import_spec":
                path_node = node.child_by_field_name("path")
                name_node = node.child_by_field_name("name")
                if path_node is not None:
                    mod = _strip_quotes(_node_text(path_node, source))
                    imported_modules.append(mod)
                    alias = (
                        _node_text(name_node, source)
                        if name_node is not None
                        else mod.split("/")[-1]
                    )
                    if alias not in (".", "_"):
                        imports[alias] = mod
            else:
                stack.extend(reversed(node.children))

    def _collect_c_includes(
        self,
        root: tree_sitter.Node,
        source: bytes,
        imported_modules: list[str],
    ) -> None:
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == "preproc_include":
                path_node = node.child_by_field_name("path")
                if path_node is not None:
                    raw = _node_text(path_node, source).strip()
                    if (raw.startswith("<") and raw.endswith(">")) or (
                        raw.startswith('"') and raw.endswith('"')
                    ):
                        imported_modules.append(raw[1:-1])
            else:
                stack.extend(reversed(node.children))

    def _walk_calls_and_symbols(
        self,
        node: tree_sitter.Node,
        source: bytes,
        language: Language,
        imports: dict[str, str],
        calls: list[ParsedCall],
        symbols: list[ParsedSymbol],
    ) -> None:
        stack = [node]
        while stack:
            curr = stack.pop()
            ntype = curr.type

            # Never descend into comments or import declarations for call/symbol matching
            if ntype in (
                "comment",
                "line_comment",
                "block_comment",
                "import_statement",
                "import_from_statement",
                "import_declaration",
                "preproc_include",
            ):
                continue

            if ntype in ("call", "call_expression", "new_expression"):
                parsed_call = self._parse_call_node(curr, source, language, imports)
                if parsed_call is not None:
                    calls.append(parsed_call)
            elif ntype in (
                "attribute",
                "member_expression",
                "selector_expression",
                "scoped_identifier",
                "identifier",
            ):
                # Avoid duplicating the callee itself as a standalone symbol unless it's an attribute
                parent = curr.parent
                is_callee = parent is not None and (
                    parent.child_by_field_name("function") == curr
                    or parent.child_by_field_name("constructor") == curr
                )
                if not is_callee and ntype in (
                    "attribute",
                    "member_expression",
                    "selector_expression",
                    "scoped_identifier",
                    "identifier",
                ):
                    raw_sym = _node_text(curr, source).strip()
                    normalized = raw_sym.replace("::", ".")
                    resolved = _resolve_dotted_name(normalized, imports)
                    symbols.append(
                        ParsedSymbol(
                            symbol=raw_sym,
                            resolved_symbol=resolved,
                            start_line=curr.start_point.row + 1,
                            start_col=curr.start_point.column + 1,
                            end_line=curr.end_point.row + 1,
                            end_col=curr.end_point.column + 1,
                            snippet=_node_text(curr, source),
                        )
                    )

            stack.extend(reversed(curr.children))

    def _parse_call_node(
        self,
        node: tree_sitter.Node,
        source: bytes,
        language: Language,
        imports: dict[str, str],
    ) -> ParsedCall | None:
        fn_node = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        if fn_node is None:
            return None

        raw_callee = _node_text(fn_node, source).strip()
        normalized_callee = raw_callee.replace("::", ".")
        resolved_callee = _resolve_dotted_name(normalized_callee, imports)

        args: list[str | int | float | bool | None] = []
        kwargs: dict[str, str | int | float | bool | None] = {}

        args_node = node.child_by_field_name("arguments")
        if args_node is not None:
            for child in args_node.named_children:
                if language == Language.PYTHON and child.type == "keyword_argument":
                    k_node = child.child_by_field_name("name")
                    v_node = child.child_by_field_name("value")
                    if k_node is not None and v_node is not None:
                        key = _node_text(k_node, source)
                        kwargs[key] = _extract_literal_or_symbol(v_node, source, imports)
                elif child.type not in ("comment", "line_comment", "block_comment"):
                    args.append(_extract_literal_or_symbol(child, source, imports))

        # For JS/TS object literal options (e.g., generateKeyPair('rsa', { modulusLength: 2048 }))
        if language == Language.JAVASCRIPT and args_node is not None:
            for child in args_node.named_children:
                if child.type == "object":
                    for prop in child.named_children:
                        if prop.type == "pair":
                            k_n = prop.child_by_field_name("key")
                            v_n = prop.child_by_field_name("value")
                            if k_n is not None and v_n is not None:
                                k_str = _strip_quotes(_node_text(k_n, source))
                                kwargs[k_str] = _extract_literal_or_symbol(v_n, source, imports)

        return ParsedCall(
            callee=raw_callee,
            resolved_callee=resolved_callee,
            args=args,
            kwargs=kwargs,
            start_line=node.start_point.row + 1,
            start_col=node.start_point.column + 1,
            end_line=node.end_point.row + 1,
            end_col=node.end_point.column + 1,
            snippet=_node_text(node, source),
        )

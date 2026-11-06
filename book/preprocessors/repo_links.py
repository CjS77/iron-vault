#!/usr/bin/env python3
"""mdBook preprocessor: the glossary page, and links that leave the book.

1. A chapter holding the `{{#glossary}}` marker gets `design/glossary.md` in its place, so the book's glossary is the
   implementers' glossary and each term is defined once (AGENTS.md, ubiquitous language).
2. A relative link to a file outside `book/src`, such as `../../../design/audit-logging.md`, works when the Markdown is
   read on GitHub but not on the published site. It is rewritten to the file on `main` in the repository. A link to a
   file that does not exist fails the build, since the link checker does not fetch web links.
3. A link to a guide that moved into the book from `design/` points at its page in the book, so the glossary's links
   reach the book rather than the pointer left behind.

The protocol is mdBook's: `repo_links.py supports <renderer>` exits 0, then `[context, book]` arrives as JSON on stdin
and the book goes back as JSON on stdout.
"""

import json
import os
import re
import sys

REPOSITORY_BLOB = "https://github.com/CjS77/iron-vault/blob/main"
GLOSSARY_MARKER = "{{#glossary}}"
GLOSSARY_SOURCE = "design/glossary.md"

# Repository paths whose content lives in the book, mapped to their page relative to the book's `src`.
IN_BOOK = {
    "design/glossary.md": "glossary.md",
    "design/linux-install.md": "installation/linux-install.md",
    "design/multiuser-linux.md": "installation/multiuser-linux.md",
    "design/log-operations.md": "reference/log-operations.md",
}

LINK = re.compile(r"\]\(([^)\s]+)\)")
FENCE = re.compile(r"^\s*(```|~~~)")
EXTERNAL = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*:|#|/)")


class LinkError(Exception):
    """A link that leaves the book names a file the repository does not have."""


class Paths:
    """The directories a link is resolved against."""

    def __init__(self, book_root, src):
        self.book_root = os.path.realpath(book_root)
        self.src = os.path.join(self.book_root, src)
        self.repo = os.path.dirname(self.book_root)

    def rewrite_target(self, target, base_dir, page_dir):
        """The target to write for `target`, written in a file in `base_dir`, shown on a page in `page_dir`."""
        if EXTERNAL.match(target):
            return target
        path, hash_sign, fragment = target.partition("#")
        resolved = os.path.normpath(os.path.join(base_dir, path))
        if resolved == self.src or resolved.startswith(self.src + os.sep):
            return os.path.relpath(resolved, page_dir) + hash_sign + fragment
        repo_path = os.path.relpath(resolved, self.repo)
        if repo_path.startswith(".."):
            raise LinkError(f"link {target} leaves the repository")
        if repo_path in IN_BOOK:
            page = os.path.join(self.src, IN_BOOK[repo_path])
            return os.path.relpath(page, page_dir) + hash_sign + fragment
        if not os.path.exists(resolved):
            raise LinkError(f"link {target} names {repo_path}, which does not exist")
        return f"{REPOSITORY_BLOB}/{repo_path}{hash_sign}{fragment}"

    def rewrite_links(self, markdown, base_dir, page_dir):
        """Rewrite every inline link outside fenced code blocks."""
        in_fence = False
        lines = []
        for line in markdown.split("\n"):
            if FENCE.match(line):
                in_fence = not in_fence
            if not in_fence:
                line = LINK.sub(lambda m: "](" + self.rewrite_target(m.group(1), base_dir, page_dir) + ")", line)
            lines.append(line)
        return "\n".join(lines)


def process_chapter(chapter, paths):
    source_path = chapter.get("source_path")
    if not source_path:
        return
    page_dir = os.path.dirname(os.path.join(paths.src, source_path))
    content = paths.rewrite_links(chapter["content"], page_dir, page_dir)
    if GLOSSARY_MARKER in content:
        glossary_file = os.path.join(paths.repo, GLOSSARY_SOURCE)
        with open(glossary_file, encoding="utf-8") as f:
            glossary = paths.rewrite_links(f.read(), os.path.dirname(glossary_file), page_dir)
        content = content.replace(GLOSSARY_MARKER, glossary)
    chapter["content"] = content


def walk(items, paths):
    for item in items:
        if isinstance(item, dict) and "Chapter" in item:
            chapter = item["Chapter"]
            process_chapter(chapter, paths)
            walk(chapter.get("sub_items", []), paths)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "supports":
        sys.exit(0)
    context, book = json.load(sys.stdin)
    src = context.get("config", {}).get("book", {}).get("src", "src")
    try:
        walk(book["items"], Paths(context["root"], src))
    except LinkError as e:
        print(f"repo-links: {e}", file=sys.stderr)
        sys.exit(1)
    json.dump(book, sys.stdout)


if __name__ == "__main__":
    main()

# The Iron Vault manual

The user manual, built with [mdBook](https://rust-lang.github.io/mdBook/). Pages are in `src/`, and `src/SUMMARY.md`
sets their order.

## Tools

CI pins the tools; install the same versions:

```sh
cargo install mdbook --version 0.5.4 --locked
cargo install mdbook-linkcheck2 --version 0.13.0 --locked
cargo install mdbook-mermaid --version 0.17.1 --locked
mdbook-mermaid install book    # once: writes the Mermaid scripts the site loads
```

The Mermaid scripts are not committed. Run `mdbook-mermaid install book` again after changing the mdbook-mermaid
version, so the scripts match it; without them the build fails.

The build also runs `preprocessors/repo_links.py`, so it needs `python3`.

## Preview

From the repository root:

```sh
mdbook serve book    # http://localhost:3000, rebuilt on every save
```

## Build and check links

```sh
mdbook build book
```

This writes the site to `book/book/html` and checks every link between pages; a broken one fails the build. Web links
are not fetched.

## Where content comes from

- **The glossary** is `design/glossary.md`, put in place of the `{{#glossary}}` marker in `src/glossary.md` at build
  time. Edit the design file; there is one definition of each term.
- **Links that leave the book**, such as `../../design/iron-vault-specification.md`, work when the Markdown is read on
  GitHub. The preprocessor rewrites them to the file on `main` for the site, and fails the build if the file does not
  exist.

## Index

| Date       | Review                                                                                                            |
|------------|-------------------------------------------------------------------------------------------------------------------|
| 2026-11-09 | [Admin access for the iron-vault service account in protected and container installations](iron-vault-account.md) |

## Review report format

Each file in this folder represents a single standalone review of the Iron Vault code or design.

It has the following sections in the frontmatter:

```
---
title: A short title indicating what was reviewed, e.g. "Security review of container setup"
date: yyyy-mm-dd hh:mm - the time the review report was written
source: the git commit hash of the source code version reviewed
---
```

The report body contains the following sections:

* **Investigation Scope**: The specific question the review is answering, or the goal of the review
* **Source scope**: The scope of the source code reviewed (a single file, design only etc.)
* **Key findings**: Short, direct explanations of all key findings
  * Subheadings: Title (Severity); Description; Impact; Examples, if relevant
  * **Recommendations**: Short, direct set of actions that the report recommends to resolve the finding.
* **Actions taken**: Only completed after any/all recommended actions have been taken.


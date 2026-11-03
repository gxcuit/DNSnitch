# Backend Development Guidelines

> Best practices for backend development in this project.

---

## Overview

This directory contains guidelines for backend development. Fill in each file with your project's specific conventions.

---

## Guidelines Index

| Guide | Description | Status |
|-------|-------------|--------|
| [Directory Structure](./directory-structure.md) | Go package layout and dependency direction | Filled |
| [CLI Contract](./cli-contract.md) | `dnsleak` arguments, JSON output, exit codes | Filled |
| [mihomo Behavior Contract](./mihomo-semantics.md) | Verified mihomo resolution semantics the checks rely on | Filled |
| [Error Handling](./error-handling.md) | Error types, exit-2 vs findings, missing data | Filled |
| [Quality Guidelines](./quality-guidelines.md) | Required checks, conventions, forbidden patterns | Filled |
| [Database Guidelines](./database-guidelines.md) | ORM patterns, queries, migrations | N/A (no database) |
| [Logging Guidelines](./logging-guidelines.md) | Structured logging, log levels | N/A (CLI writes reports only, no logging) |

---

## How to Fill These Guidelines

For each guideline file:

1. Document your project's **actual conventions** (not ideals)
2. Include **code examples** from your codebase
3. List **forbidden patterns** and why
4. Add **common mistakes** your team has made

The goal is to help AI assistants and new team members understand how YOUR project works.

---

**Language**: All documentation should be written in **English**.

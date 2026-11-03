# Frontend Development Guidelines

> Best practices for frontend development in this project.

---

## Overview

This directory contains guidelines for frontend development. Fill in each file with your project's specific conventions.

---

## Guidelines Index

| Guide | Description | Status |
|-------|-------------|--------|
| [Directory Structure](./directory-structure.md) | `gui/frontend/` layout, generated `wailsjs/` | Filled |
| [Component Guidelines](./component-guidelines.md) | `<script setup>` components, styling via CSS variables | Filled |
| [Hook Guidelines](./hook-guidelines.md) | Composables (`useCheck`), sequence-guarded binding calls | Filled |
| [State Management](./state-management.md) | All state in `useCheck()`, backend is source of truth | Filled |
| [Quality Guidelines](./quality-guidelines.md) | Required checks, forbidden patterns, review checklist | Filled |
| [Type Safety](./type-safety.md) | Types generated from Go by Wails | Filled |

Stack: Wails v2.17.1 + Vue 3 + TypeScript + Vite (in `gui/frontend/`). Go-side contract: `.trellis/spec/backend/gui-bindings.md`.

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

---
name: deslop
description: Remove AI-generated code slop and clean up code style
---

# Remove AI code slop

Before finish: remove unnecessary comments, abnormal defensive try/catch, `any` casts to bypass types, deep nesting that should early-return, style inconsistent with surrounding files. Behavior unchanged unless fixing a clear bug. Minimal focused edits.

<!-- classification: INTERNAL USE ONLY -->
> **INTERNAL USE ONLY**

# Trivy Security Report

**Scan Type:** midas_2026-04-25_01-17-10_trivy-filesystem-results  
**Generated:** Sat Apr 25 01:22:00 UTC 2026  

## Summary

**Total Items:** 1

```json
{
  "SchemaVersion": 2,
  "Trivy": {
    "Version": "0.70.0"
  },
  "ReportID": "019dc237-b6f5-7ef7-bc2b-191e5d7a5e78",
  "CreatedAt": "2026-04-25T01:18:44.469983226Z",
  "ArtifactID": "sha256:c25864e2b5bff687c207616d17c34b8f97dace901aac6aea54d9f1c584b579f0",
  "ArtifactName": "/workspace",
  "ArtifactType": "repository",
  "Metadata": {
    "RepoURL": "https://github.com/MetroStar/midas",
    "Branch": "main",
    "Commit": "a62a3efec536e0d5e6d0e3ff7dba303acf62052d",
    "CommitMsg": "MID-987: drop tree-sitter-language-pack for individual grammar packages (#695)\n\n* MID-987: drop tree-sitter-language-pack for individual grammar packages\n\nReplace tree-sitter-language-pack (platform-specific Rust binary with\nglibc constraints) with:\n- tree-sitter-java, tree-sitter-python, tree-sitter-c-sharp (portable wheels)\n- ctypes loader for COBOL (no standalone PyPI package)\n\n_grammar_config.py now provides get_language() and get_parser() directly,\nremoving the ensure_configured() / language-pack.configure() pattern.\nAll parsers and lib/evaluation/code_quality.py updated to use the new API.\n\n* MID-987: address review feedback \u2014 update tree-sitter refs, add grammar_config test\n\n- Update etc/claude_prompts.md: replace tree-sitter-language-pack\n  references with _grammar_config imports.\n- Update pb-28752292: replace tree_sitter_language_pack imports with\n  knowledgebase.parsers._grammar_config.\n- Update pb-38263838: reflect per-language packages replacing\n  tree-sitter-language-pack.\n- Add tests/parser/grammar_config_test.py: baseline test covering\n  get_language(), get_parser(), caching, and unknown-language error.\n\n* Update tests/parser/grammar_config_test.py\n\nCo-authored-by: Eric Kelly <24855669+ericdatakelly@users.noreply.github.com>\n\n* Update error message for unsupported language test\n\n---------\n\nCo-authored-by: Eric Kelly <24855669+ericdatakelly@users.noreply.github.com>",
    "Author": "Austin Herrling <adherrling@gmail.com>",
    "Commit
```


---

> **INTERNAL USE ONLY**

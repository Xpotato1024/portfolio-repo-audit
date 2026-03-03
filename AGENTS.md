# AGENTS.md

## Scope
- This is an application repository under /workspace/apps.
- Runtime and infrastructure changes are managed in Home-Servers.

## Working Rules
- Use WSL tooling (git, gh, docker).
- Create feature branches and merge via Pull Request.
- Do not commit secrets or local .env values.

## 言語ポリシー
- PRタイトル/本文、コミットメッセージ、ドキュメント更新は日本語で記述する。
- コード識別子、コマンド名、ファイルパス、プロダクト名は正確性を優先して原文のままでよい。

## Release Flow
1. Implement and test in this repository.
2. Build and publish immutable image tag or digest.
3. Open a Home-Servers PR to update image reference and deployment config.
4. Deploy through Home-Servers workflows.

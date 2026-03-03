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

## CI/CD運用ルール
- `ci.yml`:
  - `pull_request(main)` / `push(main)` / `workflow_dispatch` で実行。
  - テスト・ビルド検証のみ。デプロイは行わない。
- `release_image.yml`:
  - `push(tags: v*)` または `workflow_dispatch` でGHCRへpublish。
  - 手動実行時は `tag` 入力を明示（未指定時は `manual-<sha7>`）。
- 本番反映はこのrepoでは完結しない。
  - image公開後に `Home-Servers` PRを作成し、merge後に `deploy_*_v2.yml` を手動実行する。

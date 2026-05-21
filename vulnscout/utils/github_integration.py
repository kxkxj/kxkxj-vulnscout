from __future__ import annotations
import base64
import re
import httpx
from vulnscout.core.config import settings

class GitHubError(Exception):
    pass

def _parse_repo(source_path: str) -> tuple[str, str]:
    m = re.match(r"(?:https://github\.com/|git@github\.com:)([^/]+)/([^/.]+)", source_path)
    if m:
        return m.group(1), m.group(2)
    raise GitHubError(f"Cannot parse GitHub repo from: {source_path}")

def _headers() -> dict:
    if not settings.github_token:
        raise GitHubError("GitHub token not configured. Set GITHUB_TOKEN in .env")
    return {"Authorization": f"Bearer {settings.github_token}", "Accept": "application/vnd.github.v3+json"}

def _api(path: str, method: str = "GET", json_data: dict | None = None) -> dict:
    try:
        resp = httpx.request(method, f"https://api.github.com{path}", headers=_headers(), json=json_data, timeout=30)
        if resp.status_code in (200, 201):
            return resp.json()
        raise GitHubError(f"GitHub API error ({resp.status_code}): {resp.text[:200]}")
    except httpx.RequestError as e:
        raise GitHubError(f"GitHub API request failed: {e}")

def create_issue(repo_path: str, title: str, body: str, labels: list[str] | None = None) -> dict:
    owner, repo = _parse_repo(repo_path)
    data: dict = {"title": title, "body": body}
    if labels:
        data["labels"] = labels
    return _api(f"/repos/{owner}/{repo}/issues", method="POST", json_data=data)

def create_pr(repo_path: str, branch_name: str, diff_content: str, commit_message: str, pr_title: str, pr_body: str, base_branch: str = "main") -> dict:
    owner, repo = _parse_repo(repo_path)
    ref_data = _api(f"/repos/{owner}/{repo}/git/ref/heads/{base_branch}")
    base_sha = ref_data["object"]["sha"]
    _api(f"/repos/{owner}/{repo}/git/refs", method="POST", json_data={"ref": f"refs/heads/{branch_name}", "sha": base_sha})
    files_changed = _parse_diff(diff_content)
    for file_path, patch_text in files_changed.items():
        try:
            current = _api(f"/repos/{owner}/{repo}/contents/{file_path}?ref={branch_name}")
            current_sha = current["sha"]
        except GitHubError:
            current_sha = None
        new_content = _apply_simple_patch(patch_text)
        if new_content is None:
            continue
        data = {"message": commit_message, "content": base64.b64encode(new_content.encode()).decode(), "branch": branch_name}
        if current_sha:
            data["sha"] = current_sha
        _api(f"/repos/{owner}/{repo}/contents/{file_path}", method="PUT", json_data=data)
    return _api(f"/repos/{owner}/{repo}/pulls", method="POST", json_data={"title": pr_title, "head": branch_name, "base": base_branch, "body": pr_body})

def _parse_diff(diff_content: str) -> dict[str, str]:
    files, current_file, current_lines = {}, None, []
    for line in diff_content.split("\n"):
        if line.startswith("--- a/"):
            continue
        elif line.startswith("+++ b/"):
            if current_file and current_lines:
                files[current_file] = "\n".join(current_lines)
            current_file = line[6:]
            current_lines = []
        else:
            current_lines.append(line)
    if current_file and current_lines:
        files[current_file] = "\n".join(current_lines)
    return files

def _apply_simple_patch(patch_text: str) -> str | None:
    if not patch_text:
        return None
    body = re.sub(r"^@@[^@]*@@\n?", "", patch_text, flags=re.MULTILINE)
    result = []
    for line in body.split("\n"):
        if line.startswith("+"):
            result.append(line[1:])
        elif line.startswith(" "):
            result.append(line[1:])
    return "\n".join(result)

def get_repo_info(repo_path: str) -> dict:
    owner, repo = _parse_repo(repo_path)
    return _api(f"/repos/{owner}/{repo}")

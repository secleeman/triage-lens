"""PyPI に公開できる状態のメタデータになっているかを検査する。

公開してから間違いに気づいても、PyPI は同じ版数を上書きできない。
そのため、公開前に CI で落ちるようにしておく。
"""

import importlib
import re
import tomllib
from pathlib import Path

import pytest

import triage_lens

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
RELEASE_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "release.yml"

PUBLIC_REPO_URL = "https://github.com/secleeman/triage-lens"
GITHUB_URL_PATTERN = re.compile(r"https://github\.com/[^\s\"'`)]+")


@pytest.fixture(scope="module")
def project() -> dict:
    return tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))["project"]


@pytest.fixture(scope="module")
def release_workflow() -> str:
    return RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")


def test_version_matches_package(project: dict) -> None:
    """pyproject.toml と __version__ がずれていると、名乗る版数が食い違う。"""
    assert project["version"] == triage_lens.__version__


def test_version_is_three_numbers(project: dict) -> None:
    """リリースワークフローは vX.Y.Z のタグしか受け付けない。"""
    assert re.fullmatch(r"\d+\.\d+\.\d+", project["version"])


@pytest.mark.parametrize(
    "field",
    ["description", "readme", "requires-python", "license", "license-files", "classifiers"],
)
def test_required_metadata_is_filled(project: dict, field: str) -> None:
    """PyPI のページで空欄になる項目を作らない。"""
    assert project[field]


def test_readme_and_license_files_exist(project: dict) -> None:
    """存在しないファイルを指しているとビルドが失敗する。"""
    assert (REPO_ROOT / project["readme"]).is_file()
    for pattern in project["license-files"]:
        assert list(REPO_ROOT.glob(pattern)), f"license-files に一致するファイルが無い: {pattern}"


def test_author_has_no_personal_information(project: dict) -> None:
    """作者欄は secleeman だけ。メールアドレスなどは公開しない。"""
    assert project["authors"] == [{"name": "secleeman"}]


def test_license_classifier_is_not_used(project: dict) -> None:
    """PEP 639 では license 式と "License ::" 分類子を併記できない（ビルドが失敗する）。"""
    assert not [c for c in project["classifiers"] if c.startswith("License ::")]


def test_supported_python_versions_are_classified(project: dict) -> None:
    """requires-python と分類子がずれていると、利用者に誤った対応表を見せることになる。"""
    classified = {
        c.rsplit(" :: ", 1)[-1]
        for c in project["classifiers"]
        if c.startswith("Programming Language :: Python :: 3.")
    }
    assert classified == {"3.11", "3.12", "3.13"}
    assert project["requires-python"] == ">=3.11"


def _is_under_public_repo(url: str) -> bool:
    """公開リポジトリそのもの、またはその配下のURLか。

    前方一致だけで見ると、公開リポジトリ名を接頭辞に持つ別のリポジトリを
    通してしまう。区切りの `/` まで含めて判定する。
    """
    return url == PUBLIC_REPO_URL or url.startswith(f"{PUBLIC_REPO_URL}/")


def test_urls_point_to_the_public_repository(project: dict) -> None:
    """公開ページから別のリポジトリへ誘導しない（開発用リポジトリは非公開のため）。"""
    assert project["urls"]["Homepage"] == PUBLIC_REPO_URL
    for name, url in project["urls"].items():
        assert _is_under_public_repo(url), f"{name} が公開リポジトリ以外を指している: {url}"


def test_bug_report_url_is_published(project: dict) -> None:
    """PyPI のページからバグ報告の受け先に辿れること。

    公開ミラーの Issue は「受付のみ」で運用する。受け先を載せないと、
    利用者が問い合わせ先を探して見つけられない。
    """
    assert project["urls"]["Issues"] == f"{PUBLIC_REPO_URL}/issues"


def test_pyproject_links_only_to_the_public_repository() -> None:
    """pyproject.toml は配布物に入る。公開リポジトリ以外のURLを残さない。"""
    urls = GITHUB_URL_PATTERN.findall(PYPROJECT_PATH.read_text(encoding="utf-8"))
    assert urls, "GitHub のURLが1つも無い（メタデータの欠落）"
    for url in urls:
        assert _is_under_public_repo(url), f"公開リポジトリ以外のURL: {url}"


def test_console_script_target_is_callable(project: dict) -> None:
    """pip install したあとに `triage-lens` コマンドが動くこと。"""
    module_name, _, attribute = project["scripts"]["triage-lens"].partition(":")
    entry_point = getattr(importlib.import_module(module_name), attribute)
    assert callable(entry_point)


def test_release_workflow_triggers_on_version_tags(release_workflow: str) -> None:
    """vX.Y.Z のタグ push だけで公開が走ること。"""
    assert '- "v[0-9]+.[0-9]+.[0-9]+"' in release_workflow
    assert "tags:" in release_workflow


def test_release_workflow_uses_trusted_publishing(release_workflow: str) -> None:
    """OIDC で認証する。id-token の権限が無いと Trusted Publishing は使えない。"""
    assert "id-token: write" in release_workflow
    assert "pypa/gh-action-pypi-publish@" in release_workflow


def test_release_workflow_has_no_long_lived_token(release_workflow: str) -> None:
    """APIトークンを Secrets に置く方式に戻っていないこと。"""
    lowered = release_workflow.lower()
    for forbidden in ["password:", "pypi_api_token", "twine_password", "secrets."]:
        assert forbidden not in lowered, f"長期トークンらしき記述がある: {forbidden}"


def test_release_workflow_pins_the_publish_action(release_workflow: str) -> None:
    """公開に使うアクションは版数を固定する（差し替わったものを黙って実行しない）。"""
    match = re.search(r"pypa/gh-action-pypi-publish@(\S+)", release_workflow)
    assert match, "公開アクションの指定が見つからない"
    assert re.fullmatch(r"v\d+\.\d+\.\d+", match.group(1)), (
        f"版数が固定されていない: {match.group(1)}"
    )


def test_sdist_excludes_tests() -> None:
    """テストは配布物に入れない。

    setuptools は既定で tests/test*.py を sdist に入れる。dev 専用の
    テストが公開される経路になるため、MANIFEST.in で必ず外しておく。
    """
    manifest = (REPO_ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    assert "prune tests" in manifest

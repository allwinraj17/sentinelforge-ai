from __future__ import annotations

from pathlib import Path
from typing import Any


IGNORED_DIRECTORIES = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".vite",
    "coverage",
    ".pytest_cache",
}


LANGUAGE_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".c": "C",
    ".cpp": "C++",
    ".h": "C/C++ Header",
    ".hpp": "C++ Header",
    ".cs": "C#",
    ".go": "Go",
    ".rs": "Rust",
    ".php": "PHP",
    ".rb": "Ruby",
    ".dart": "Dart",
    ".kt": "Kotlin",
    ".swift": "Swift",
    ".html": "HTML",
    ".css": "CSS",
    ".sql": "SQL",
}


DEPENDENCY_FILES = {
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pom.xml",
    "build.gradle",
    "gradle.properties",
    "pubspec.yaml",
    "composer.json",
    "go.mod",
    "cargo.toml",
}


CONFIGURATION_FILES = {
    ".env",
    ".env.example",
    "config.py",
    "settings.py",
    "application.properties",
    "application.yml",
    "application.yaml",
    "docker-compose.yml",
    "docker-compose.yaml",
    "vite.config.js",
    "vite.config.ts",
}


def should_ignore(path: Path) -> bool:
    for part in path.parts:
        if part in IGNORED_DIRECTORIES:
            return True

    return False


def is_source_file(path: Path) -> bool:
    return path.suffix.lower() in LANGUAGE_EXTENSIONS


def run_repository_understanding(
    repository_path: str | Path,
) -> dict[str, Any]:
    """
    Repository Understanding Agent.

    Performs deterministic repository structure analysis.

    It does not execute repository code and does not send
    repository contents to an external AI service.
    """

    root = Path(repository_path).resolve()

    if not root.exists():
        return {
            "agent": "Repository Understanding Agent",
            "success": False,
            "error": "Repository path does not exist.",
        }

    if not root.is_dir():
        return {
            "agent": "Repository Understanding Agent",
            "success": False,
            "error": "Repository path is not a directory.",
        }

    total_files = 0
    source_files = 0

    languages: dict[str, int] = {}

    dependency_files = []
    configuration_files = []
    authentication_related_files = []
    database_related_files = []

    repository_structure = []

    for path in root.rglob("*"):
        if should_ignore(path):
            continue

        if not path.is_file():
            continue

        total_files += 1

        try:
            relative_path = path.relative_to(root).as_posix()
        except ValueError:
            continue

        repository_structure.append(relative_path)

        filename = path.name.lower()
        extension = path.suffix.lower()

        if is_source_file(path):
            source_files += 1

            language = LANGUAGE_EXTENSIONS.get(
                extension
            )

            if language:
                languages[language] = (
                    languages.get(language, 0) + 1
                )

        if filename in DEPENDENCY_FILES:
            dependency_files.append(
                relative_path
            )

        if filename in CONFIGURATION_FILES:
            configuration_files.append(
                relative_path
            )

        lower_path = relative_path.lower()

        if any(
            keyword in lower_path
            for keyword in [
                "auth",
                "login",
                "signin",
                "signup",
                "jwt",
                "permission",
                "role",
            ]
        ):
            authentication_related_files.append(
                relative_path
            )

        if any(
            keyword in lower_path
            for keyword in [
                "database",
                "db",
                "sql",
                "repository",
                "model",
            ]
        ):
            database_related_files.append(
                relative_path
            )

    repository_structure.sort()
    dependency_files.sort()
    configuration_files.sort()
    authentication_related_files.sort()
    database_related_files.sort()

    return {
        "agent": "Repository Understanding Agent",
        "success": True,
        "total_files": total_files,
        "source_files": source_files,
        "languages": languages,
        "dependency_files": dependency_files,
        "configuration_files": configuration_files,
        "authentication_related_files": (
            authentication_related_files
        ),
        "database_related_files": (
            database_related_files
        ),
        "repository_structure": repository_structure,
    }
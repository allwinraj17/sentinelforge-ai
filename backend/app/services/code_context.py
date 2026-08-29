from pathlib import Path


def get_code_context(
    extract_dir: str,
    file_path: str,
    line_number: int,
    context_lines: int = 10,
) -> str:
    """
    Read a small section of source code around a vulnerability.
    """

    repository_root = Path(extract_dir).resolve()
    requested_file = (repository_root / file_path).resolve()

    # Prevent access outside the extracted repository
    try:
        requested_file.relative_to(repository_root)
    except ValueError:
        raise ValueError("Invalid file path.")

    if not requested_file.exists():
        raise FileNotFoundError(
            f"Source file not found: {file_path}"
        )

    if not requested_file.is_file():
        raise ValueError(
            f"Path is not a file: {file_path}"
        )

    try:
        lines = requested_file.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()
    except Exception as e:
        raise ValueError(
            f"Unable to read source file: {str(e)}"
        )

    if not lines:
        return ""

    target_index = max(line_number - 1, 0)

    start = max(
        target_index - context_lines,
        0,
    )

    end = min(
        target_index + context_lines + 1,
        len(lines),
    )

    selected_lines = lines[start:end]

    result = []

    for index, line in enumerate(
        selected_lines,
        start=start + 1,
    ):
        result.append(f"{index}: {line}")

    return "\n".join(result)
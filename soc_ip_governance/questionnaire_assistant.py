"""Helpers for filling vendor questionnaires from a master reference sheet."""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
from io import BytesIO
from pathlib import Path

import pandas as pd
import requests


@dataclass(frozen=True)
class _MatchResult:
    answer: str
    score: float
    is_exact: bool


def _normalize_text(value: object) -> str:
    text = "" if value is None else str(value)
    return " ".join(text.strip().lower().split())


def _find_column(df: pd.DataFrame, keywords: tuple[str, ...]) -> str | None:
    lowered_map = {column: _normalize_text(column) for column in df.columns}
    for column, lowered in lowered_map.items():
        if any(keyword in lowered for keyword in keywords):
            return column
    return None


def _best_text_column(df: pd.DataFrame) -> str:
    if df.empty:
        return str(df.columns[0])

    candidates: list[tuple[str, float]] = []
    for column in df.columns:
        series = df[column].astype(str).str.strip()
        non_empty = series[series != ""]
        if non_empty.empty:
            continue
        avg_len = float(non_empty.str.len().mean())
        candidates.append((str(column), avg_len))

    if not candidates:
        return str(df.columns[0])
    candidates.sort(key=lambda item: item[1], reverse=True)
    return candidates[0][0]


def read_questionnaire_upload(filename: str, raw_bytes: bytes) -> pd.DataFrame:
    """Read uploaded questionnaire bytes as CSV or Excel into a DataFrame."""

    suffix = Path(filename).suffix.lower()
    payload = BytesIO(raw_bytes)

    if suffix == ".csv":
        dataframe = pd.read_csv(payload)
    elif suffix in {".xlsx", ".xls", ".xlsm"}:
        dataframe = pd.read_excel(payload)
    else:
        raise ValueError(f"Unsupported file type: {suffix}")

    dataframe.columns = [str(column).strip() for column in dataframe.columns]
    return dataframe


def detect_question_column(questionnaire_df: pd.DataFrame) -> str:
    """Detect the most likely question column from questionnaire data."""

    if questionnaire_df is None or questionnaire_df.empty:
        raise ValueError("Questionnaire file has no rows")
    if len(questionnaire_df.columns) == 0:
        raise ValueError("Questionnaire file has no columns")

    direct = _find_column(
        questionnaire_df,
        ("question", "prompt", "control", "requirement", "item", "query"),
    )
    if direct:
        return direct

    return _best_text_column(questionnaire_df)


def _load_master_reference(master_csv_path: Path) -> tuple[pd.DataFrame, str, str]:
    master_df = pd.read_csv(master_csv_path)
    if master_df.empty or len(master_df.columns) == 0:
        raise ValueError("Master questionnaire sheet is empty")

    master_df.columns = [str(column).strip() for column in master_df.columns]

    question_col = _find_column(master_df, ("question", "prompt", "control", "requirement", "query"))
    answer_col = _find_column(master_df, ("answer", "response", "recommended", "guidance", "comments"))

    if question_col is None:
        question_col = _best_text_column(master_df)

    if answer_col is None:
        remaining = [str(column) for column in master_df.columns if str(column) != question_col]
        answer_col = remaining[0] if remaining else question_col

    return master_df, question_col, answer_col


def _build_master_lookup(master_df: pd.DataFrame, question_col: str, answer_col: str) -> tuple[dict[str, str], list[tuple[str, str]]]:
    exact_lookup: dict[str, str] = {}
    entries: list[tuple[str, str]] = []

    for _, row in master_df.iterrows():
        question = _normalize_text(row.get(question_col, ""))
        answer = str(row.get(answer_col, "")).strip()
        if not question or not answer:
            continue
        if question not in exact_lookup:
            exact_lookup[question] = answer
        entries.append((question, answer))

    return exact_lookup, entries


def _find_best_answer(question: str, exact_lookup: dict[str, str], entries: list[tuple[str, str]], min_score: float = 0.58) -> _MatchResult | None:
    normalized_question = _normalize_text(question)
    if not normalized_question:
        return None

    if normalized_question in exact_lookup:
        return _MatchResult(answer=exact_lookup[normalized_question], score=1.0, is_exact=True)

    best_answer = ""
    best_score = 0.0
    for master_question, answer in entries:
        score = SequenceMatcher(a=normalized_question, b=master_question).ratio()
        if score > best_score:
            best_score = score
            best_answer = answer

    if best_score < min_score or not best_answer:
        return None
    return _MatchResult(answer=best_answer, score=best_score, is_exact=False)


def _refine_with_gemini(question: str, base_answer: str, api_key: str, model: str) -> str:
    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    prompt = (
        "You are assisting with a security vendor questionnaire. "
        "Improve the provided answer to be concise, professional, and directly relevant to the question. "
        "Do not invent unsupported claims.\n\n"
        f"Question: {question}\n"
        f"Reference answer: {base_answer}\n"
        "Return only the final answer text."
    )
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    response = requests.post(
        endpoint,
        params={"key": api_key},
        json=payload,
        timeout=20,
    )
    response.raise_for_status()
    data = response.json()

    candidates = data.get("candidates") or []
    if not candidates:
        return base_answer
    parts = (
        candidates[0]
        .get("content", {})
        .get("parts", [])
    )
    if not parts:
        return base_answer
    text = str(parts[0].get("text", "")).strip()
    return text or base_answer


def fill_questionnaire_from_master(
    questionnaire_df: pd.DataFrame,
    question_column: str,
    master_csv_path: Path,
    gemini_api_key: str = "",
    gemini_model: str = "gemini-2.0-flash",
    use_gemini: bool = False,
) -> tuple[pd.DataFrame, dict]:
    """Fill questionnaire rows using best-match answers from a master reference sheet."""

    if question_column not in questionnaire_df.columns:
        raise ValueError(f"Question column not found: {question_column}")

    master_df, master_question_col, master_answer_col = _load_master_reference(Path(master_csv_path))
    exact_lookup, master_entries = _build_master_lookup(master_df, master_question_col, master_answer_col)
    if not master_entries:
        raise ValueError("Master questionnaire does not contain usable question/answer rows")

    answer_column = _find_column(questionnaire_df, ("answer", "response", "remarks", "comments")) or "Answer"
    output_df = questionnaire_df.copy()
    if answer_column not in output_df.columns:
        output_df[answer_column] = ""

    answered_rows = 0
    exact_matches = 0
    gemini_used = False

    for idx, row in output_df.iterrows():
        question = str(row.get(question_column, "")).strip()
        if not question:
            continue

        best_match = _find_best_answer(question, exact_lookup, master_entries)
        if best_match is None:
            continue

        final_answer = best_match.answer
        if use_gemini and gemini_api_key:
            try:
                final_answer = _refine_with_gemini(
                    question=question,
                    base_answer=best_match.answer,
                    api_key=gemini_api_key,
                    model=gemini_model,
                )
                gemini_used = True
            except Exception:
                final_answer = best_match.answer

        output_df.at[idx, answer_column] = final_answer
        answered_rows += 1
        if best_match.is_exact:
            exact_matches += 1

    summary = {
        "answered_rows": answered_rows,
        "exact_matches": exact_matches,
        "master_reference_rows": len(master_entries),
        "gemini_used": gemini_used,
    }
    return output_df, summary

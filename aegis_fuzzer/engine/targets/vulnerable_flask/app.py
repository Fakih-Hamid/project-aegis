from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request
from jinja2 import Template, UndefinedError

app = Flask(__name__)
DB_PATH = Path(__file__).resolve().parent / "aegis-users.db"


def _init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        );
        """
    )
    conn.execute("DELETE FROM users;")
    conn.executemany(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [
            ("admin", "hunter2"),
            ("guest", "guest"),
            ("operator", "P@ssw0rd"),
        ],
    )
    conn.commit()
    conn.close()


_init_db()


@app.route("/health", methods=["GET"])
def health() -> Any:
    return {"status": "ok"}


@app.route("/search", methods=["GET"])
def search() -> Any:
    term = request.args.get("q", "")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = f"SELECT username, password FROM users WHERE username LIKE '%{term}%';"
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        response = {"query": query, "results": rows}
    except sqlite3.Error as exc:
        conn.close()
        return jsonify({"error": str(exc), "query": query}), 500
    conn.close()

    if "{{" in term or "{%" in term:
        try:
            rendered = Template(term).render()
            response["rendered"] = rendered
        except UndefinedError as exc:
            response["template_error"] = str(exc)
    return jsonify(response)


if __name__ == "__main__":
    _init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)


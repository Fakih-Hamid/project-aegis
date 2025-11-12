from aegis_fuzzer.engine.targets.vulnerable_flask.app import app, _init_db  # type: ignore[F401]

if __name__ == "__main__":
    _init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)


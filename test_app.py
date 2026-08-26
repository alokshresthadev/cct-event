from pathlib import Path
import tempfile


def test_full_scoring_flow(monkeypatch):
    db_path = Path(tempfile.mktemp(suffix=".db"))
    monkeypatch.setenv("CTF_DATABASE", str(db_path))
    monkeypatch.setenv("CTF_ORGANIZER_KEY", "organizer-test-key")
    import app as ctf
    ctf.DB_PATH = db_path
    ctf.init_db()
    client = ctf.app.test_client()
    response = client.post("/register", data={"username": "first_player", "password": "password123"}, follow_redirects=True)
    assert response.status_code == 200
    login_response = client.post("/login", data={"username": "first_player", "password": "password123"})
    assert login_response.status_code == 302 and login_response.location.endswith("/dashboard")
    dashboard_response = client.get("/dashboard", follow_redirects=True)
    assert dashboard_response.status_code == 200 and dashboard_response.request.path == "/dashboard/2"
    assert client.get("/dashboard/1").status_code == 200
    assert ctf.FLAG_IDOR.encode() in client.get("/dashboard/1").data
    assert b"secrets/" in client.get("/files/").data
    assert ctf.FLAG_DIRLIST.encode() in client.get("/files/secrets/flag.txt").data
    with ctf.app.app_context():
        assert ctf.get_db().execute("SELECT COUNT(*) FROM solves").fetchone()[0] == 0

    # Stored XSS: the payload is reflected unescaped, but the flag itself is
    # never present anywhere in the page. static/app.js (loaded on every
    # authenticated page) exposes a showFlag() helper that does the network
    # request internally, so the beginner-friendly payload is just a call to
    # that function - no fetch/promise/XHR knowledge needed. Notes are now
    # private per user and live on their own page, separate from the
    # IDOR-target dashboard, so a payload never fires in someone else's
    # session via /dashboard/<id> browsing.
    assert b"app.js" in client.get("/dashboard/2").data
    hint_page = client.get("/hint")
    assert hint_page.status_code == 200
    assert b"showFlag()" in hint_page.data
    assert b"showFlag()" not in client.get("/dashboard/2").data
    payload = "<script>showFlag()</script>"
    assert client.post("/notes", data={"content": payload}).status_code == 302
    notes_page = client.get("/notes")
    assert payload.encode() in notes_page.data
    assert ctf.FLAG_XSS.encode() not in notes_page.data
    assert payload.encode() not in client.get("/dashboard/2").data
    api_response = client.get("/api/xss-flag")
    assert api_response.status_code == 200
    assert api_response.data == ctf.FLAG_XSS.encode()

    # Privacy check: a second player must never see the first player's notes.
    client.post("/register", data={"username": "second_player", "password": "password123"})
    second_client = ctf.app.test_client()
    second_client.post("/login", data={"username": "second_player", "password": "password123"})
    second_notes_page = second_client.get("/notes")
    assert payload.encode() not in second_notes_page.data
    assert b"No notes yet." in second_notes_page.data

    with ctf.app.app_context():
        note_id = ctf.get_db().execute("SELECT id FROM notes ORDER BY id DESC LIMIT 1").fetchone()[0]
    assert client.post(f"/notes/{note_id}/delete").status_code == 302
    assert b"No notes yet." in client.get("/notes").data
    with ctf.app.app_context():
        assert ctf.get_db().execute("SELECT COUNT(*) FROM solves").fetchone()[0] == 0
    assert client.post("/submit", data={"flag": ctf.FLAG_IDOR}).status_code == 302
    assert client.post("/submit", data={"flag": ctf.FLAG_DIRLIST}).status_code == 302
    assert client.post("/submit", data={"flag": ctf.FLAG_XSS}).status_code == 302
    assert client.post("/submit", data={"flag": ctf.FLAG_OSINT}).status_code == 302
    board = client.get("/leaderboard")
    assert b"first_player" in board.data and b"400" in board.data
    assert b"First solve (Nepal time)" in board.data
    assert b"Profile Pivot time" in board.data and b"Quiet Directories time" in board.data
    assert b"Shared Scribbles time" in board.data and b"Secretary Search time" in board.data
    assert board.data.count(b"FIRST BLOOD") == 1
    assert b"202" in board.data
    assert client.post("/control", data={"organizer_key": "organizer-test-key"}).status_code == 302
    control = client.get("/control")
    assert control.status_code == 200
    assert b"account_created" in control.data and b"solve" in control.data
    organizer_dashboard = client.get("/dashboard/1")
    assert organizer_dashboard.status_code == 200
    assert ctf.FLAG_IDOR.encode() in organizer_dashboard.data
    with ctf.app.app_context():
        first_blood_count = ctf.get_db().execute("SELECT COUNT(*) FROM first_bloods").fetchone()[0]
    assert first_blood_count == 4

import json

import pytest

import app as app_module


@pytest.fixture()
def client(tmp_path):
    """Test client with an isolated, minimal data directory."""
    app = app_module.app
    app.config.update(
        TESTING=True,
        DATA=str(tmp_path),
        IDEAS_FILE=tmp_path / "ideas.json",
        USERS_FILE=tmp_path / "users.json",
        AVATAR_DIR=tmp_path / "avatars",
    )

    password_hash = app_module.ph.hash("testpassword")

    users = [
        {"username": "bob", "password": password_hash, "full_name": "Bob", "groups": ["Fam1", "Fam2"]},
        {"username": "alice", "password": password_hash, "full_name": "Alice", "groups": ["Fam1"]},
        {"username": "carol", "password": password_hash, "full_name": "Carol", "groups": ["Fam3"]},
        {"username": "dave", "password": password_hash, "full_name": "Dave", "groups": ["Fam2"]},
    ]
    (tmp_path / "users.json").write_text(json.dumps(users))

    ideas = [
        {"gift_idea_id": 1, "user_id": "alice", "gift_name": "From self", "description": "", "added_by": "alice", "bought_by": "bob"},
        {"gift_idea_id": 2, "user_id": "alice", "gift_name": "From shared family", "description": "", "added_by": "alice", "bought_by": "dave"},
        {"gift_idea_id": 3, "user_id": "alice", "gift_name": "From stranger", "description": "", "added_by": "alice", "bought_by": "carol"},
    ]
    (tmp_path / "ideas.json").write_text(json.dumps(ideas))

    with app.test_client() as c:
        yield c


def login(client, username):
    return client.post("/login", data={"username": username, "password": "testpassword"})


def test_index_redirects_to_login(client):
    resp = client.get("/")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_login_page_loads(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert "login" in resp.get_data(as_text=True).lower()


def test_login_success_redirects_to_dashboard(client):
    resp = login(client, "bob")
    assert resp.status_code == 302
    assert "/dashboard" in resp.headers["Location"]


def test_dashboard_loads_after_login(client):
    login(client, "bob")
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "Gift Dashboard" in resp.get_data(as_text=True)


def test_ideas_page_requires_login(client):
    resp = client.get("/user_gift_ideas/alice")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_ideas_page_hides_buyer_without_shared_family(client):
    login(client, "bob")
    resp = client.get("/user_gift_ideas/alice")
    assert resp.status_code == 200

    html = resp.get_data(as_text=True)

    # Idea bought by the connected user is shown as "Me (...)"
    assert "Me (bob)" in html
    # Buyer sharing a family with the connected user is never anonymised
    assert "Dave" in html
    # Buyer sharing no family with the connected user is anonymised
    assert "Anonymous" in html
    assert "Carol" not in html

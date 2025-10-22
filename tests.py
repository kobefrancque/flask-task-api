import requests


def test_signup():
    r = requests.post(
        "http://localhost:5000/signup",
        json={"username": "test", "password": "password"},
    )
    return r.json()


def test_login():
    r = requests.post(
        "http://localhost:5000/login",
        json={"username": "test", "password": "password"},
    )
    return r.json()


def test_get_tasks():
    data = test_login()
    jwt = data.get("access_token")
    r = requests.get(
        "http://localhost:5000/tasks",
        headers={"Authorization": f"Bearer {jwt}"},
    )
    return r.json()


def create_task():
    data = test_login()
    jwt = data.get("access_token")
    r = requests.post(
        "http://localhost:5000/tasks",
        json={"title": "task1", "content": "content1", "done": False},
        headers={"Authorization": f"Bearer {jwt}"},
    )

    return r.json()


print(test_get_tasks())


### OTHER


def get_task_details(id):
    r = requests.get(f"http://localhost:5000/tasks/{id}")
    return r.json()


def delete_task(id):
    r = requests.delete(f"http://localhost:5000/tasks/{id}")
    return r.json()


def complete_task(id):
    r = requests.patch(f"http://localhost:5000/tasks/{id}/complete")
    return r.json()

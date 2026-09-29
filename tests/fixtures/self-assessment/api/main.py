"""Minimal FastAPI app used only as a deterministic fixture for Layer 11
(API Discovery). Plants a small, fixed set of routes so
run-api-discovery.sh's Python/FastAPI route extractor always has something
real to find, regardless of what else is (or isn't) in this repo.
"""
from fastapi import FastAPI

app = FastAPI()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/items/{item_id}")
def get_item(item_id: int):
    return {"item_id": item_id}


@app.post("/items")
def create_item(name: str):
    return {"name": name}

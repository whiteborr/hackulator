# note_loader.py
import os

def load_notes(folder="joplin_export"):
    notes = []
    for root, _, files in os.walk(folder):
        for file in files:
            if file.endswith(".md"):
                path = os.path.join(root, file)
                with open(path, "r", encoding="utf-8") as f:
                    body = f.read()
                notes.append({
                    "title": os.path.splitext(file)[0],
                    "body": body,
                    "path": path
                })
    return notes

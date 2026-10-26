#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, json, hashlib, hmac, time, tempfile
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
CONTENT_PASSWORD = os.environ.get("CONTENT_PASSWORD", "")
TOKEN_SECRET = os.environ.get("TOKEN_SECRET", "")
TOKEN_TTL_SECONDS = int(os.environ.get("TOKEN_TTL_SECONDS", "43200"))
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

if not ADMIN_PASSWORD or not CONTENT_PASSWORD or not TOKEN_SECRET:
    raise RuntimeError("ADMIN_PASSWORD, CONTENT_PASSWORD and TOKEN_SECRET must be configured")

DATA_FILE = "/opt/admin-api/content.json"
HTML_DIR = "/usr/share/nginx/html"
LOGIN_FAILURES = {}
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}
ALLOWED_COURSE_EXTENSIONS = {
    ".pdf", ".ppt", ".pptx", ".doc", ".docx", ".xls", ".xlsx",
    ".txt", ".md", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".zip"
}

@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"ok": False, "error": "request too large"}), 413

def atomic_write_text(path, text):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=directory, delete=False
    )
    tmp_path = handle.name
    try:
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

def atomic_write_json(path, data):
    atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2))

def load_content():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_content(data):
    atomic_write_json(DATA_FILE, data)

def check_token(required_scope="admin"):
    token = request.headers.get("X-Token", "")
    try:
        scope, issued_at, signature = token.split(".", 2)
        issued_at_int = int(issued_at)
    except (ValueError, TypeError):
        return False
    if required_scope == "admin" and scope != "admin":
        return False
    if required_scope == "content" and scope not in ("content", "admin"):
        return False
    age = int(time.time()) - issued_at_int
    if age < 0 or age > TOKEN_TTL_SECONDS:
        return False
    message = scope + "." + issued_at
    expected = hmac.new(TOKEN_SECRET.encode("utf-8"), message.encode("ascii"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)

def issue_token(scope):
    issued_at = str(int(time.time()))
    message = scope + "." + issued_at
    signature = hmac.new(TOKEN_SECRET.encode("utf-8"), message.encode("ascii"), hashlib.sha256).hexdigest()
    return message + "." + signature

def client_ip():
    return request.headers.get("X-Real-IP") or request.remote_addr or "unknown"

@app.route("/admin/")
def admin_page():
    return send_from_directory(HTML_DIR, "admin/index.html")

@app.route("/admin/editor.html")
def editor_main():
    return send_from_directory(HTML_DIR, "admin/editor.html")

@app.route("/admin/editor-intro.html")
def editor_intro():
    return send_from_directory(HTML_DIR, "admin/editor-intro.html")

@app.route("/api/login", methods=["POST"])
def login():
    now = int(time.time())
    ip = client_ip()
    failures = [ts for ts in LOGIN_FAILURES.get(ip, []) if now - ts < 900]
    LOGIN_FAILURES[ip] = failures
    if len(failures) >= 8:
        return jsonify({"ok": False, "error": "too many attempts"}), 429
    data = request.get_json(silent=True) or {}
    supplied = str(data.get("password", ""))
    if hmac.compare_digest(supplied.encode("utf-8"), ADMIN_PASSWORD.encode("utf-8")):
        LOGIN_FAILURES.pop(ip, None)
        return jsonify({"ok": True, "token": issue_token("admin"), "expires_in": TOKEN_TTL_SECONDS})
    failures.append(now)
    LOGIN_FAILURES[ip] = failures
    return jsonify({"ok": False}), 401

@app.route("/api/access-login", methods=["POST"])
def access_login():
    now = int(time.time())
    ip = "content:" + client_ip()
    failures = [ts for ts in LOGIN_FAILURES.get(ip, []) if now - ts < 900]
    LOGIN_FAILURES[ip] = failures
    if len(failures) >= 8:
        return jsonify({"ok": False, "error": "too many attempts"}), 429
    data = request.get_json(silent=True) or {}
    supplied = str(data.get("password", ""))
    if hmac.compare_digest(supplied.encode("utf-8"), CONTENT_PASSWORD.encode("utf-8")):
        LOGIN_FAILURES.pop(ip, None)
        return jsonify({"ok": True, "token": issue_token("content"), "expires_in": TOKEN_TTL_SECONDS})
    failures.append(now)
    LOGIN_FAILURES[ip] = failures
    return jsonify({"ok": False}), 401

@app.route("/api/session", methods=["GET"])
def session_status():
    if not check_token("content"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return jsonify({"ok": True})

@app.route("/api/admin-session", methods=["GET"])
def admin_session_status():
    if not check_token("admin"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return jsonify({"ok": True})

@app.route("/api/content", methods=["GET"])
def get_content():
    return jsonify(load_content())

@app.route("/api/content", methods=["POST"])
def update_content():
    if not check_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    data = request.get_json()
    if not data:
        return jsonify({"ok": False, "error": "no data"}), 400
    save_content(data)
    return jsonify({"ok": True})

@app.route("/api/html/<page>", methods=["GET"])
def get_html(page):
    files = {"main": "index.html", "intro": "intro/index.html", "projects": "projects/index.html", "health": "health/index.html", "schedule": "schedule/index.html", "notes": "notes/index.html"}
    if page not in files:
        return jsonify({"ok": False, "error": "invalid page"}), 400
    path = os.path.join(HTML_DIR, files[page])
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    return jsonify({"ok": True, "html": content})

@app.route("/api/html/<page>", methods=["POST"])
def save_html(page):
    if not check_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    files = {"main": "index.html", "intro": "intro/index.html", "projects": "projects/index.html", "health": "health/index.html", "schedule": "schedule/index.html", "notes": "notes/index.html"}
    if page not in files:
        return jsonify({"ok": False, "error": "invalid page"}), 400
    data = request.get_json()
    if not data or "html" not in data:
        return jsonify({"ok": False, "error": "no html"}), 400
    path = os.path.join(HTML_DIR, files[page])
    with open(path, "w", encoding="utf-8") as f:
        f.write(data["html"])
    return jsonify({"ok": True})


import base64, uuid, time as _time

@app.route("/api/upload", methods=["POST"])
def upload_image():
    if not check_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    if 'file' in request.files:
        f = request.files['file']
        ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else 'png'
        if ext not in ALLOWED_IMAGE_EXTENSIONS:
            return jsonify({"ok": False, "error": "unsupported format"}), 400
        fname = str(uuid.uuid4())[:8] + '_' + str(int(_time.time())) + '.' + ext
        save_dir = os.path.join(HTML_DIR, 'uploads')
        os.makedirs(save_dir, exist_ok=True)
        f.save(os.path.join(save_dir, fname))
        url = '/uploads/' + fname
        return jsonify({"ok": True, "url": url})
    data = request.get_json()
    if data and data.get('base64'):
        b64 = data['base64']
        ext = str(data.get('ext', 'png')).lower()
        if ext not in ALLOWED_IMAGE_EXTENSIONS:
            return jsonify({"ok": False, "error": "unsupported format"}), 400
        fname = str(uuid.uuid4())[:8] + '_' + str(int(_time.time())) + '.' + ext
        save_dir = os.path.join(HTML_DIR, 'uploads')
        os.makedirs(save_dir, exist_ok=True)
        with open(os.path.join(save_dir, fname), 'wb') as f:
            f.write(base64.b64decode(b64))
        url = '/uploads/' + fname
        return jsonify({"ok": True, "url": url})
    return jsonify({"ok": False, "error": "no file"}), 400

@app.route("/api/gallery", methods=["GET"])
def get_gallery():
    content = load_content()
    return jsonify({"ok": True, "gallery": content.get("gallery", [])})

COURSES_FILE = "/opt/admin-api/courses.json"

def load_courses():
    if os.path.exists(COURSES_FILE):
        with open(COURSES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def save_courses(data):
    atomic_write_json(COURSES_FILE, data)

@app.route("/api/courses", methods=["GET"])
def get_courses():
    if not check_token("content"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return jsonify({"ok": True, "courses": load_courses()})

@app.route("/api/courses", methods=["POST"])
def add_course():
    if not check_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    data = request.get_json()
    if not data or not data.get("name"):
        return jsonify({"ok": False, "error": "missing name"}), 400
    courses = load_courses()
    import time
    data["id"] = str(int(time.time() * 1000))
    courses.append(data)
    save_courses(courses)
    return jsonify({"ok": True, "course": data})

@app.route("/api/courses/<cid>", methods=["DELETE"])
def delete_course(cid):
    if not check_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    courses = load_courses()
    courses = [c for c in courses if c.get("id") != cid]
    save_courses(courses)
    return jsonify({"ok": True})

@app.route("/api/courses/<cid>", methods=["PUT"])
def update_course(cid):
    if not check_token():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    data = request.get_json()
    courses = load_courses()
    for i, c in enumerate(courses):
        if c.get("id") == cid:
            data["id"] = cid
            courses[i] = data
            save_courses(courses)
            return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "not found"}), 404

import subprocess, uuid

COURSE_FILES_DIR = "/opt/admin-api/course-files"
os.makedirs(COURSE_FILES_DIR, exist_ok=True)

def get_course_dir(week, day, slot, create=False):
    d = os.path.join(COURSE_FILES_DIR, f"w{week}_d{day}_s{slot}")
    if create:
        os.makedirs(d, exist_ok=True)
    return d

@app.route("/api/course-files/<int:week>/<int:day>/<int:slot>", methods=["GET"])
def list_course_files(week, day, slot):
    if not check_token("content"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    d = get_course_dir(week, day, slot)
    files = []
    meta_file = os.path.join(d, "meta.json")
    if os.path.exists(meta_file):
        with open(meta_file, "r", encoding="utf-8") as f:
            files = json.load(f)
    return jsonify({"ok": True, "files": files})

@app.route("/api/course-files/<int:week>/<int:day>/<int:slot>/upload", methods=["POST"])
def upload_course_file(week, day, slot):
    if not check_token("content"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    d = get_course_dir(week, day, slot, create=True)
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "no file"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"ok": False, "error": "empty filename"}), 400
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in ALLOWED_COURSE_EXTENSIONS:
        return jsonify({"ok": False, "error": "unsupported file type"}), 400
    fname = f"{uuid.uuid4().hex[:12]}{ext}"
    fpath = os.path.join(d, fname)
    f.save(fpath)
    # PPT/PPTX 转 PDF
    pdf_url = None
    if ext in (".ppt", ".pptx"):
        try:
            env = os.environ.copy()
            env["HOME"] = "/tmp"
            result = subprocess.run(
                ["/usr/bin/libreoffice", "--headless", "--convert-to", "pdf", "--outdir", d, fpath],
                timeout=120, capture_output=True, env=env
            )
            pdf_name = fname.rsplit(".", 1)[0] + ".pdf"
            if os.path.exists(os.path.join(d, pdf_name)):
                pdf_url = f"/api/course-files/{week}/{day}/{slot}/file/{pdf_name}"
        except Exception as e:
            import sys; print(f"PDF convert error: {e}", file=sys.stderr)
    # 更新 meta
    meta_file = os.path.join(d, "meta.json")
    files = []
    if os.path.exists(meta_file):
        with open(meta_file, "r", encoding="utf-8") as mf:
            files = json.load(mf)
    import time
    files.append({
        "id": fname.rsplit(".", 1)[0],
        "name": f.filename,
        "file": fname,
        "size": os.path.getsize(fpath),
        "time": int(time.time()),
        "url": f"/api/course-files/{week}/{day}/{slot}/file/{fname}",
        "pdf_url": pdf_url
    })
    atomic_write_json(meta_file, files)
    return jsonify({"ok": True, "file": files[-1]})

@app.route("/api/course-files/<int:week>/<int:day>/<int:slot>/file/<filename>")
def serve_course_file(week, day, slot, filename):
    if not check_token("content"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    d = get_course_dir(week, day, slot)
    orig_name = filename
    meta_file = os.path.join(d, "meta.json")
    if os.path.exists(meta_file):
        with open(meta_file, "r", encoding="utf-8") as mf:
            for item in json.load(mf):
                if item.get("file") == filename:
                    orig_name = item["name"]
                    break
    preview = request.args.get("preview", "0") == "1"
    if preview:
        return send_from_directory(d, filename)
    return send_from_directory(d, filename, as_attachment=True, download_name=orig_name)

@app.route("/api/course-files/<int:week>/<int:day>/<int:slot>/<fid>", methods=["DELETE"])
def delete_course_file(week, day, slot, fid):
    if not check_token("content"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    d = get_course_dir(week, day, slot)
    meta_file = os.path.join(d, "meta.json")
    if not os.path.exists(meta_file):
        return jsonify({"ok": False, "error": "not found"}), 404
    with open(meta_file, "r", encoding="utf-8") as f:
        files = json.load(f)
    target = None
    for fi in files:
        if fi["id"] == fid:
            target = fi
            break
    if not target:
        return jsonify({"ok": False, "error": "not found"}), 404
    # 删除物理文件
    fpath = os.path.join(d, target["file"])
    if os.path.exists(fpath): os.remove(fpath)
    if target.get("pdf_url"):
        pdf_path = os.path.join(d, target["file"].rsplit(".", 1)[0] + ".pdf")
        if os.path.exists(pdf_path): os.remove(pdf_path)
    files = [fi for fi in files if fi["id"] != fid]
    atomic_write_json(meta_file, files)
    return jsonify({"ok": True})

@app.route("/schedule/course.html")
def course_detail_page():
    return send_from_directory(os.path.join(HTML_DIR, "schedule"), "course.html")

@app.route("/api/course-notes/<int:week>/<int:day>/<int:slot>", methods=["GET"])
def get_course_notes(week, day, slot):
    if not check_token("content"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    d = get_course_dir(week, day, slot)
    notes_file = os.path.join(d, "notes.txt")
    text = ""
    if os.path.exists(notes_file):
        with open(notes_file, "r", encoding="utf-8") as f:
            text = f.read()
    return jsonify({"ok": True, "text": text})

@app.route("/api/course-notes/<int:week>/<int:day>/<int:slot>", methods=["POST"])
def save_course_notes(week, day, slot):
    if not check_token("content"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    d = get_course_dir(week, day, slot, create=True)
    data = request.json or {}
    text = data.get("text", "")
    notes_file = os.path.join(d, "notes.txt")
    atomic_write_text(notes_file, text)
    return jsonify({"ok": True})

import subprocess, uuid, time as _time_mod

NOTES_FILE = "/opt/admin-api/notes.json"
os.makedirs("/opt/admin-api", exist_ok=True)

def load_notes():
    if os.path.exists(NOTES_FILE):
        with open(NOTES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def save_notes(notes):
    atomic_write_json(NOTES_FILE, notes)

@app.route("/api/notes", methods=["GET"])
def list_notes():
    if not check_token("content"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return jsonify({"ok": True, "notes": load_notes()})

def safe_json():
    """安全解析JSON，兼容nginx代理"""
    try:
        return request.get_json(force=True, silent=True) or json.loads(request.data.decode('utf-8', errors='ignore'))
    except Exception:
        return None

@app.route("/api/notes", methods=["POST"])
def create_note():
    if not check_token("content"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    data = safe_json()
    if not data or not data.get("title"):
        return jsonify({"ok": False, "error": "missing title"}), 400
    notes = load_notes()
    note = {
        "id": str(int(_time_mod.time() * 1000)),
        "title": data["title"],
        "content": data.get("content", ""),
        "created": int(_time_mod.time()),
        "updated": int(_time_mod.time())
    }
    notes.insert(0, note)
    save_notes(notes)
    return jsonify({"ok": True, "note": note})

@app.route("/api/notes/<nid>", methods=["GET"])
def get_note(nid):
    if not check_token("content"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    notes = load_notes()
    for n in notes:
        if n["id"] == nid:
            return jsonify({"ok": True, "note": n})
    return jsonify({"ok": False, "error": "not found"}), 404

@app.route("/api/notes/<nid>", methods=["PUT"])
def update_note(nid):
    if not check_token("content"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    data = safe_json()
    if not data:
        return jsonify({"ok": False, "error": "no data"}), 400
    notes = load_notes()
    for i, n in enumerate(notes):
        if n["id"] == nid:
            notes[i]["title"] = data.get("title", n["title"])
            notes[i]["content"] = data.get("content", n["content"])
            notes[i]["updated"] = int(_time_mod.time())
            save_notes(notes)
            return jsonify({"ok": True, "note": notes[i]})
    return jsonify({"ok": False, "error": "not found"}), 404

@app.route("/api/notes/<nid>", methods=["DELETE"])
def delete_note(nid):
    if not check_token("content"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    notes = load_notes()
    notes = [n for n in notes if n["id"] != nid]
    save_notes(notes)
    return jsonify({"ok": True})

@app.route("/api/notes/upload", methods=["POST"])
def notes_upload_image():
    """云笔记图片粘贴上传。"""
    if not check_token("content"):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    data = safe_json()
    if not data or not data.get("base64"):
        return jsonify({"ok": False, "error": "no data"}), 400
    import base64 as _b64
    ext = data.get("ext", "png")
    if ext not in ("png", "jpg", "jpeg", "gif", "webp"):
        ext = "png"
    fname = str(uuid.uuid4())[:8] + "_" + str(int(_time_mod.time())) + "." + ext
    save_dir = os.path.join(HTML_DIR, "uploads")
    os.makedirs(save_dir, exist_ok=True)
    try:
        raw = _b64.b64decode(data["base64"])
    except Exception:
        return jsonify({"ok": False, "error": "invalid base64"}), 400
    if len(raw) > 10 * 1024 * 1024:
        return jsonify({"ok": False, "error": "too large"}), 400
    with open(os.path.join(save_dir, fname), "wb") as f:
        f.write(raw)
    return jsonify({"ok": True, "url": "/uploads/" + fname})

BUILTIN_COURSES_FILE = "/opt/admin-api/builtin_courses.json"
SLOT_TIMES = [("08:20","09:55"),("10:15","11:50"),("14:00","15:35"),("15:55","17:30"),("19:00","20:40")]
TERM_START_MONDAY = (2026, 8, 31)

def _to_min(hhmm):
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)

@app.route("/api/now-class", methods=["GET"])
def now_class():
    """当前是否正在上课：返回 {inClass, name, leftMin}"""
    import datetime as _dt
    now = _dt.datetime.now()
    dow = now.isoweekday()  # 1=周一 ... 7=周日
    now_min = now.hour * 60 + now.minute
    # 计算当前周
    term_start = _dt.date(*TERM_START_MONDAY)
    monday = now.date() - _dt.timedelta(days=dow - 1)
    week = (monday - term_start).days // 7 + 1
    week = max(1, min(24, week))
    # 收集今天的课程（内置 + 后台）
    today = []  # [(slot, span, name)]
    if os.path.exists(BUILTIN_COURSES_FILE):
        with open(BUILTIN_COURSES_FILE, "r", encoding="utf-8") as f:
            builtin = json.load(f)
        day_map = builtin.get(str(week), {})
        for key, items in day_map.items():
            try:
                slot_s, wd_s = key.split("_")
                if int(wd_s) != dow:
                    continue
                slot = int(slot_s)
            except (ValueError, AttributeError):
                continue
            for it in items:
                today.append((slot, it.get("span", 1), it.get("name", "")))
    for c in load_courses():
        if dow not in (c.get("weekday"),):
            continue
        weeks = c.get("weeks") or []
        if weeks and week not in weeks:
            continue
        today.append(((c.get("start", 1) - 1), c.get("span", 1), c.get("name", "")))
    # 判断当前是否在某个上课时段内
    for slot, span, name in today:
        if slot < 0 or slot > 4:
            continue
        end_slot = min(slot + span - 1, 4)
        s_min = _to_min(SLOT_TIMES[slot][0])
        e_min = _to_min(SLOT_TIMES[end_slot][1])
        if s_min <= now_min < e_min:
            return jsonify({"ok": True, "inClass": True, "name": name,
                            "leftMin": e_min - now_min, "week": week})
    return jsonify({"ok": True, "inClass": False, "week": week})

@app.route("/api/study-mode", methods=["POST"])
def study_mode():
    """学习模式切换，返回成功即可（前端已自行切换UI）"""
    return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)


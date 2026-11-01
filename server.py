"""SJ YÖNETİM KONSOLLARI VE YÖNETİM - Sunucu (FastAPI)
Render'da çalıştır:  uvicorn server:app --host 0.0.0.0 --port $PORT
Ortam değişkenleri: DATABASE_URL (Render PostgreSQL), ADMIN_KEY (sadece sende olan gizli anahtar)
"""
import os, re, hmac, hashlib, secrets, time, asyncio
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Request, Depends, WebSocket
from pydantic import BaseModel
from sqlalchemy import (create_engine, MetaData, Table, Column, Integer, String, Text,
                        DateTime, select, insert, update, delete, and_, or_, desc)
from sqlalchemy.exc import IntegrityError

DB_URL = os.environ.get("DATABASE_URL", "sqlite:///sj.db")
if DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql+psycopg2://", 1)
elif DB_URL.startswith("postgresql://"):
    DB_URL = DB_URL.replace("postgresql://", "postgresql+psycopg2://", 1)
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")

engine = create_engine(DB_URL, pool_pre_ping=True)
md = MetaData()


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


users = Table("users", md,
    Column("id", Integer, primary_key=True),
    Column("username", String(32), unique=True, nullable=False),
    Column("pw_hash", String(128), nullable=False),
    Column("salt", String(32), nullable=False),
    Column("friend_code", String(16), unique=True, nullable=False),
    Column("role", String(10), nullable=False, default="user"),
    Column("ip", String(64)),            # sadece kullanıcı onay verdiyse dolar
    Column("created", DateTime, default=now))
tokens = Table("tokens", md,
    Column("token", String(64), primary_key=True),
    Column("user_id", Integer, nullable=False),
    Column("created", DateTime, default=now))
friends = Table("friends", md,
    Column("user_id", Integer, primary_key=True),
    Column("friend_id", Integer, primary_key=True))
messages = Table("messages", md,
    Column("id", Integer, primary_key=True),
    Column("sender_id", Integer, nullable=False),
    Column("receiver_id", Integer, nullable=False),
    Column("body", Text, nullable=False),
    Column("ts", DateTime, default=now))
news = Table("news", md,
    Column("id", Integer, primary_key=True),
    Column("title", String(120), nullable=False),
    Column("body", Text, nullable=False),
    Column("author", String(32), nullable=False),
    Column("ts", DateTime, default=now))
logs = Table("logs", md,
    Column("id", Integer, primary_key=True),
    Column("ts", DateTime, default=now),
    Column("actor", String(32)),
    Column("action", String(40)),
    Column("detail", Text))
events = Table("events", md,
    Column("id", Integer, primary_key=True),
    Column("kind", String(12), nullable=False),
    Column("text", Text, nullable=False),
    Column("target_id", Integer),          # None = herkese
    Column("data", String(32)),
    Column("ts", DateTime, default=now))
md.create_all(engine)

app = FastAPI(title="SJ Yönetim Konsolları")


# ---------- yardımcılar ----------
def hash_pw(pw: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()


def log(conn, actor, action, detail=""):
    conn.execute(insert(logs).values(actor=actor, action=action, detail=detail))


def add_event(conn, kind, text_, target_id=None, data=None):
    conn.execute(insert(events).values(kind=kind, text=text_, target_id=target_id, data=data))


def client_ip(req: Request) -> str:
    xff = req.headers.get("x-forwarded-for", "")
    return (xff.split(",")[0].strip() if xff else (req.client.host if req.client else ""))[:64]


_fails = {}  # basit kaba kuvvet koruması: {anahtar: [zamanlar]}


def too_many_fails(key):
    t = time.time()
    _fails[key] = [x for x in _fails.get(key, []) if t - x < 300]
    return len(_fails[key]) >= 5


def current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Giriş yapmalısın.")
    with engine.begin() as c:
        row = c.execute(select(users).join(tokens, tokens.c.user_id == users.c.id)
                        .where(tokens.c.token == authorization[7:])).mappings().first()
    if not row:
        raise HTTPException(401, "Oturum geçersiz, tekrar giriş yap.")
    return dict(row)


def staff(u=Depends(current_user)):
    if u["role"] not in ("admin", "mod"):
        raise HTTPException(403, "Yetkin yok.")
    return u


def admin_only(u=Depends(current_user)):
    if u["role"] != "admin":
        raise HTTPException(403, "Sadece admin.")
    return u


def user_by_name(c, name):
    return c.execute(select(users).where(users.c.username == name)).mappings().first()


# ---------- modeller ----------
class RegisterIn(BaseModel):
    username: str
    password: str
    consent_ip: bool = False
    admin_key: str = ""


class LoginIn(BaseModel):
    username: str
    password: str


class FriendIn(BaseModel):
    code: str


class MsgIn(BaseModel):
    to: str
    text: str


class NewsIn(BaseModel):
    title: str
    body: str


class RoleIn(BaseModel):
    username: str
    role: str  # "mod" veya "user"


# ---------- uçlar ----------
@app.get("/health")
def health():
    return {"ok": True}


@app.post("/register")
def register(d: RegisterIn, req: Request):
    if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", d.username):
        raise HTTPException(400, "Kullanıcı adı 3-20 karakter, sadece harf/rakam/_ olmalı.")
    if len(d.password) < 6:
        raise HTTPException(400, "Şifre en az 6 karakter olmalı.")
    role = "admin" if (ADMIN_KEY and d.admin_key and hmac.compare_digest(d.admin_key, ADMIN_KEY)) else "user"
    salt = secrets.token_hex(16)
    try:
        with engine.begin() as c:
            c.execute(insert(users).values(
                username=d.username, pw_hash=hash_pw(d.password, salt), salt=salt,
                friend_code=secrets.token_hex(3).upper(), role=role,
                ip=client_ip(req) if d.consent_ip else None))
            log(c, d.username, "kayit", f"rol={role}")
    except IntegrityError:
        raise HTTPException(409, "Bu kullanıcı adı alınmış.")
    return {"ok": True, "role": role}


@app.post("/login")
def login(d: LoginIn, req: Request):
    key = f"{d.username}|{client_ip(req)}"
    if too_many_fails(key):
        raise HTTPException(429, "Çok fazla hatalı deneme. 5 dakika bekle.")
    with engine.begin() as c:
        u = user_by_name(c, d.username)
        if not u or not hmac.compare_digest(u["pw_hash"], hash_pw(d.password, u["salt"])):
            _fails.setdefault(key, []).append(time.time())
            raise HTTPException(401, "Kullanıcı adı veya şifre yanlış.")
        tok = secrets.token_hex(32)
        c.execute(insert(tokens).values(token=tok, user_id=u["id"]))
        log(c, u["username"], "giris")
    return {"token": tok, "username": u["username"], "role": u["role"], "friend_code": u["friend_code"]}


@app.get("/me")
def me(u=Depends(current_user)):
    return {"username": u["username"], "role": u["role"], "friend_code": u["friend_code"]}


@app.post("/friends/add")
def add_friend(d: FriendIn, u=Depends(current_user)):
    with engine.begin() as c:
        f = c.execute(select(users).where(users.c.friend_code == d.code.strip().upper())).mappings().first()
        if not f:
            raise HTTPException(404, "Bu koda sahip kullanıcı yok.")
        if f["id"] == u["id"]:
            raise HTTPException(400, "Kendini ekleyemezsin.")
        exists = c.execute(select(friends).where(and_(friends.c.user_id == u["id"], friends.c.friend_id == f["id"]))).first()
        if exists:
            raise HTTPException(409, "Zaten arkadaşsınız.")
        c.execute(insert(friends).values(user_id=u["id"], friend_id=f["id"]))
        c.execute(insert(friends).values(user_id=f["id"], friend_id=u["id"]))
        log(c, u["username"], "arkadas_ekle", f["username"])
        add_event(c, "friend", f"{u['username']} seni arkadaş olarak ekledi", f["id"])
    return {"ok": True, "username": f["username"]}


@app.get("/friends")
def list_friends(u=Depends(current_user)):
    with engine.begin() as c:
        rows = c.execute(select(users.c.username, users.c.role).join(friends, friends.c.friend_id == users.c.id)
                         .where(friends.c.user_id == u["id"]).order_by(users.c.username)).mappings().all()
    return [dict(r) for r in rows]


@app.post("/messages")
def send_message(d: MsgIn, u=Depends(current_user)):
    text_ = d.text.strip()
    if not text_ or len(text_) > 1000:
        raise HTTPException(400, "Mesaj boş olamaz ve 1000 karakteri geçemez.")
    with engine.begin() as c:
        f = user_by_name(c, d.to)
        if not f or not c.execute(select(friends).where(and_(friends.c.user_id == u["id"], friends.c.friend_id == f["id"]))).first():
            raise HTTPException(403, "Sadece arkadaşlarına mesaj atabilirsin.")
        c.execute(insert(messages).values(sender_id=u["id"], receiver_id=f["id"], body=text_))
        add_event(c, "msg", f"{u['username']} sana mesaj attı", f["id"], u["username"])
    return {"ok": True}


@app.get("/messages/{username}")
def get_messages(username: str, after: Optional[int] = None, wait: int = 0, u=Depends(current_user)):
    """after verilmezse son 50 mesaj. after verilirse o id'den yeni mesajlar;
    yeni mesaj yoksa 'wait' saniyeye kadar bekler (anlık mesajlaşma için)."""
    wait = max(0, min(wait, 25))
    deadline = time.time() + wait
    while True:
        with engine.begin() as c:
            f = user_by_name(c, username)
            if not f:
                raise HTTPException(404, "Kullanıcı yok.")
            pair = or_(
                and_(messages.c.sender_id == u["id"], messages.c.receiver_id == f["id"]),
                and_(messages.c.sender_id == f["id"], messages.c.receiver_id == u["id"]))
            if after is None:
                rows = list(reversed(c.execute(select(messages).where(pair)
                            .order_by(desc(messages.c.id)).limit(50)).mappings().all()))
            else:
                rows = c.execute(select(messages).where(and_(pair, messages.c.id > after))
                                 .order_by(messages.c.id).limit(100)).mappings().all()
        if rows or after is None or time.time() >= deadline:
            break
        time.sleep(0.5)
    return [{"id": r["id"],
             "from": u["username"] if r["sender_id"] == u["id"] else f["username"],
             "text": r["body"], "ts": r["ts"].strftime("%d.%m %H:%M")} for r in rows]


@app.get("/news")
def get_news(u=Depends(current_user)):
    with engine.begin() as c:
        rows = c.execute(select(news).order_by(desc(news.c.id)).limit(20)).mappings().all()
    return [{"title": r["title"], "body": r["body"], "author": r["author"], "ts": r["ts"].strftime("%d.%m.%Y %H:%M")} for r in rows]


@app.post("/news")
def post_news(d: NewsIn, u=Depends(staff)):
    if not d.title.strip() or not d.body.strip():
        raise HTTPException(400, "Başlık ve içerik boş olamaz.")
    with engine.begin() as c:
        c.execute(insert(news).values(title=d.title[:120], body=d.body[:4000], author=u["username"]))
        log(c, u["username"], "haber_yayin", d.title[:60])
        add_event(c, "news", f"HABER ({u['username']}): {d.title[:60]} - {d.body[:120]}")
    return {"ok": True}


@app.get("/logs")
def get_logs(u=Depends(staff)):
    with engine.begin() as c:
        rows = c.execute(select(logs).order_by(desc(logs.c.id)).limit(100)).mappings().all()
    return [{"ts": r["ts"].strftime("%d.%m %H:%M:%S"), "actor": r["actor"], "action": r["action"], "detail": r["detail"]} for r in rows]


@app.get("/admin/users")
def admin_users(u=Depends(admin_only)):
    with engine.begin() as c:
        rows = c.execute(select(users).order_by(users.c.id)).mappings().all()
    return [{"username": r["username"], "role": r["role"], "ip": r["ip"] or "-"} for r in rows]


@app.post("/admin/role")
def set_role(d: RoleIn, u=Depends(admin_only)):
    if d.role not in ("mod", "user"):
        raise HTTPException(400, "Rol 'mod' veya 'user' olmalı.")
    with engine.begin() as c:
        t = user_by_name(c, d.username)
        if not t:
            raise HTTPException(404, "Kullanıcı yok.")
        if t["role"] == "admin":
            raise HTTPException(403, "Adminin rolü değiştirilemez.")
        c.execute(update(users).where(users.c.id == t["id"]).values(role=d.role))
        log(c, u["username"], "rol_degis", f"{d.username} -> {d.role}")
        add_event(c, "role", f"Rolün değişti: {d.role}", t["id"], d.role)
    return {"ok": True}


@app.get("/events")
def get_events(after: Optional[int] = None, wait: int = 0, u=Depends(current_user)):
    """Anlık bildirimler. after verilmezse sadece son id döner (eski olaylar gösterilmez).
    after verilirse yeni olay gelene kadar 'wait' saniyeye kadar bekler."""
    wait = max(0, min(wait, 25))
    deadline = time.time() + wait
    while True:
        with engine.begin() as c:
            if after is None:
                last = c.execute(select(events.c.id).order_by(desc(events.c.id)).limit(1)).scalar() or 0
                return {"last": last, "events": []}
            rows = c.execute(select(events).where(and_(
                events.c.id > after,
                or_(events.c.target_id.is_(None), events.c.target_id == u["id"])))
                .order_by(events.c.id).limit(50)).mappings().all()
        if rows or time.time() >= deadline:
            break
        time.sleep(0.5)
    return {"last": rows[-1]["id"] if rows else after,
            "events": [{"id": r["id"], "kind": r["kind"], "text": r["text"], "data": r["data"]} for r in rows]}


# ---------- canlı sesli konuşma ----------
class CallIn(BaseModel):
    to: str


@app.post("/call/invite")
def call_invite(d: CallIn, u=Depends(current_user)):
    with engine.begin() as c:
        f = user_by_name(c, d.to)
        if not f or not c.execute(select(friends).where(and_(friends.c.user_id == u["id"], friends.c.friend_id == f["id"]))).first():
            raise HTTPException(403, "Sadece arkadaşlarını arayabilirsin.")
        add_event(c, "call", f"{u['username']} seni sesli arıyor! Ana menüde 5'e bas (sohbetteysen /kabul yaz).", f["id"], u["username"])
        log(c, u["username"], "sesli_arama", f["username"])
    return {"ok": True}


rooms = {}  # {"ali|veli": {"ali": ws, "veli": ws}}  - ses sadece aktarılır, kaydedilmez


def ws_auth(token, other):
    with engine.begin() as c:
        me = c.execute(select(users).join(tokens, tokens.c.user_id == users.c.id)
                       .where(tokens.c.token == token)).mappings().first()
        if not me:
            return None
        f = user_by_name(c, other)
        if not f or not c.execute(select(friends).where(and_(friends.c.user_id == me["id"], friends.c.friend_id == f["id"]))).first():
            return None
        return me["username"]


@app.websocket("/ws/call/{other}")
async def call_ws(ws: WebSocket, other: str):
    await ws.accept()
    try:
        token = await asyncio.wait_for(ws.receive_text(), timeout=10)
    except Exception:
        await ws.close()
        return
    me = ws_auth(token, other)
    if not me:
        await ws.close(code=4401)
        return
    key = "|".join(sorted([me, other]))
    room = rooms.setdefault(key, {})
    old = room.get(me)
    if old:
        try:
            await old.close()
        except Exception:
            pass
    room[me] = ws
    await ws.send_text("ok")
    peer = room.get(other)
    if peer:
        for w in (ws, peer):
            try:
                await w.send_text("peer")
            except Exception:
                pass
    try:
        while True:
            data = await ws.receive_bytes()
            p = room.get(other)
            if p:
                try:
                    await p.send_bytes(data)
                except Exception:
                    pass
    except Exception:
        pass
    finally:
        if room.get(me) is ws:
            room.pop(me, None)
        p = room.get(other)
        if p:
            try:
                await p.close()
            except Exception:
                pass
        if not room:
            rooms.pop(key, None)

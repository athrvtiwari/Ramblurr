import re
import os
import random
import string
import json
import asyncpg
from aiohttp import web

# ==================================================
# Postgres Setup
# ==================================================

async def init_db(app):
    app["db"] = await asyncpg.create_pool(
        dsn=os.environ["DATABASE_URL"],
        min_size = 1,
        max_size = 100,
        ssl="require"
    )

    async with app["db"].acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS rooms(
                name TEXT PRIMARY KEY,
                private BOOLEAN
            );
        """)

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users(
                device TEXT PRIMARY KEY,
                name TEXT UNIQUE,
                banned BOOLEAN DEFAULT FALSE
            );
        """)

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS messages(
                id SERIAL PRIMARY KEY,
                room TEXT,
                username TEXT,
                message TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)

    await db_create_room(app, "global", False)

async def close_db(app):
    await app["db"].close()

# ==================================================
# DB helpers
# ==================================================

async def db_create_room(app, name, private):
    async with app["db"].acquire() as conn:
        stmt = await conn.prepare(
            """
            INSERT INTO rooms(name, private)
            VALUES ($1, $2)
            ON CONFLICT (name) DO NOTHING
            """
        )
        await stmt.fetch(name, private)

async def db_add_message(app, room, username, message):
    async with app["db"].acquire() as conn:
        stmt = await conn.prepare(
            """
            INSERT INTO messages (room, username, message)
            VALUES ($1, $2, $3)
            """
        )
        await stmt.fetch(room, username, message)

async def db_get_messages(app, room, limit=10000):
    async with app["db"].acquire() as conn:
        stmt = rows = await conn.prepare(
            """
            SELECT username, message
            FROM messages
            WHERE room=$1
            ORDER BY id ASC
            LIMIT $2
            """
        )
        await stmt.fetch(room, limit)

    return [f"{r['username']}: {r['message']}" for r in rows]

async def db_get_user(app, device):
    async with app["db"].acquire() as conn:
        stmt = row = await conn.prepare(
            "SELECT name FROM users WHERE device=$1",
        )
        await stmt.fetchrow(device)

    return row["name"] if row else None

async def db_set_username(app, device, name):
    async with app["db"].acquire() as conn:
        stmt_check = await conn.prepare("SELECT 1 FROM users WHERE name=$1")
        exists = await stmt_check.fetchrow(name)
        if exists:
            raise ValueError("Username already taken")

        stmt = await conn.prepare(
            """
            INSERT INTO users (device, name)
            VALUES ($1, $2)
            ON CONFLICT (device)
            DO UPDATE SET name = EXCLUDED.name
            """
        )
        await stmt.fetch(device, name)        

async def set_username(request):
    try:
        data = await request.json()
    except:
        return web.json_response({"error": "Invalid JSON"}, status = 400)
    
    device = data.get("device")
    name = data.get("name")

    # Basic validation
    if not device or not name:
        return web.json_response({"error": "Missing fields"}, status=400)
    
    if not re.match(r"^[A-Za-z0-9_]{3,20}$", name):
        return web.json_response(
            {"error": "Username must be 3 - 20 characters"},
            status=400
        )
    
    await db_set_username(request.app, device, name)
    return web.json_response({"success": "True"})

async def db_username_exists(app, name):
    async with app["db"].acquire() as conn:
        stmt = await conn.prepare("SELECT 1 FROM users WHERE name=$1")
        row = await stmt.fetchrow(name)
        return row is not None

async def send_message(request):
    data = await request.json()

    device = data["device"]
    room = data["room"]
    message = data["message"]

    username = await db_get_user(request.app, device)

    if not username:
        username = "Anonymous"

    await db_add_message(request.app, room, username, message)

    return web.json_response({"ok": True})

async def db_get_all_users(app):
    async with app["db"].acquire() as conn:
        rows = await conn.fetch("SELECT name FROM users")

    return [r["name"] for r in rows]

async def db_ban_user(app, username):
    async with app["db"].acquire() as conn:
        result = await conn.prepare(
            "UPDATE users SET banned = TRUE WHERE name = $1",
            username
        )
        return result

async def db_is_banned(app, device):
    async with app["db"].acquire() as conn:
        row = await conn.fetchrow("SELECT banned FROM users WHERE device=$1", device)
        return row["banned"] if row else False

# ==================================================
# runtime state
# ==================================================

rooms = {
    "global": {
        "clients": set(),
        "private": False
    }
}

usernames = {}
user_room = {}
online_users = set()

user_counter = 1

bad_words = {
    'fuck', 'fucking', 'shit', 'bitch', 'bastard', 'dick', 'cock', 'pussy', 'asshole', 'crap', 'douche', 'douchebag', 
    'slut', 'whore', 'cunt', 'nigga', 'nigger', 'nazi', 'retard',
    'sex', 'porn', 'xxx', 'cum', 'dildo', 'penis', 'vagina', 'boobs', 'tits', 'anal', 'blowjob', 'handjob', 'milf', 'orgy', 'fetish',
    'idiot', 'stupid', 'moron', 'loser', 'jerk', 'dumb', 'twat', 'fag', 'gay', 'lame', 'fatass', 'shithead', 'tool', 'retarded',
    'wtf', 'fml', 'lmao', 'lmfao', 'piss', 'hell', 'shitface', 'asswipe',
    'kill', 'rape', 'terrorist', 'bomb', 'suicide', 'shoot', 'killself'
}

MAX_SIZE = 25 * 1024 * 1024


# ==================================================
# helpers
# ==================================================

def make_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))


def filter_text(msg):
    for bad in bad_words:
        msg = re.sub(rf"\b{bad}\w*\b", "*" * len(bad), msg, flags=re.I)
    return msg


async def broadcast(app, room, username, message):
    await db_add_message(app, room, username, message)

    formatted = f"{username}: {message}"

    for ws in rooms[room]["clients"]:
        await ws.send_str(formatted)


async def send_user_list(app):
    all_users = await db_get_all_users(app)

    payload = json.dumps({
        "type": "users",
        "online": list(online_users),
        "all": all_users
    })

    for room in rooms.values():
        for ws in room["clients"]:
            await ws.send_str(payload)


# ==================================================
# websocket handler
# ==================================================

async def ws_handler(request):
    global user_counter

    ws = web.WebSocketResponse()
    await ws.prepare(request)

    # =====================
    # AUTH
    # =====================

    auth_msg = await ws.receive()
    name = None

    if auth_msg.type == web.WSMsgType.TEXT:
        try:
            data = json.loads(auth_msg.data)

            if data.get("type") == "auth":
                device = data["deviceId"]
                name = data.get("username")

                if name:
                    await db_set_username(request.app, device, name)
                else:
                    name = await db_get_user(request.app, device)
                    if not name:
                        name = f"Anonymous{user_counter:03d}"
                        await db_set_username(request.app, device, name)
                        user_counter += 1                    
        except:
            pass

    if not name:
        name = f"Anonymous{user_counter:03d}"
        user_counter += 1

    usernames[ws] = name
    online_users.add(name)

    # =====================
    # JOIN GLOBAL
    # =====================

    current_room = "global"

    rooms["global"]["clients"].add(ws)
    user_room[ws] = "global"

    for old in await db_get_messages(request.app, "global"):
        await ws.send_str(old)

    await broadcast(request.app, "global", "[Server]", f"[{name} joined]")
    await send_user_list(request.app)

    # =====================
    # MAIN LOOP
    # =====================

    async for msg in ws:

        # IMAGE
        if msg.type == web.WSMsgType.BINARY:
            room = user_room[ws]

            if not rooms[room]["private"]:
                await ws.send_str("[Server]: Images only allowed in private rooms")
                continue

            if len(msg.data) > MAX_SIZE:
                await ws.send_str("[Server]: Image too large (max 25MB)")
                continue

            if not msg.data.startswith(b'\x89PNG') and not msg.data.startswith(b'\xff\xd8'):
                await ws.send_str("[Server]: Only PNG/JPG allowed")
                continue

            for client in rooms[room]["clients"]:
                if client != ws:
                    await client.send_bytes(msg.data)

            continue

        if msg.type != web.WSMsgType.TEXT:
            continue

        text = msg.data.strip()

        # ===========================
        # CHECK IF USER IS BANNED
        # ===========================

        if await db_is_banned(request.app, device):
            await ws.send_str("[Server]: You are banned and cannot send messages.")
            continue

        # =====================
        # CREATE ROOM
        # =====================

        if text == "/create":
            code = make_code()

            if code not in rooms:
                rooms[code] = {
                    "clients": set(),
                    "private": True
                }

                await db_create_room(request.app, code, True)

            rooms[current_room]["clients"].discard(ws)

            current_room = code
            user_room[ws] = code
            rooms[code]["clients"].add(ws)

            await ws.send_str(f"[Room created] Code: {code}")
            await send_user_list(request.app)
            continue

        # =====================
        # JOIN ROOM
        # =====================

        if text.startswith("/join "):
            code = text.split(" ", 1)[1]

            if code not in rooms:
                await ws.send_str("[Room not found]")
                continue

            rooms[current_room]["clients"].discard(ws)

            current_room = code
            user_room[ws] = code
            rooms[code]["clients"].add(ws)

            for old in await db_get_messages(request.app, code):
                await ws.send_str(old)

            await broadcast(request.app, code, "[Server]", f"[{name} joined]")
            await send_user_list(request.app)
            continue

        # =====================
        # NORMAL MESSAGE
        # =====================

        clean = filter_text(text) if current_room == "global" else text
        await broadcast(request.app, current_room, name, clean)

        # ===================
        # BAN SYSTEM
        # ===================
        # =======================
        admin_devices = ["351843eb-f2bc-4769-8430-6235a7feb22a"]
        
        if text.startswith(".") and device in admin_devices:
            parts = text.split()
            cmd = parts[0].lower()

            if cmd == ".ban" and len(parts) > 1:
                target_name = parts[1]
                await db_ban_user(request.app, target_name)

                await broadcast(request.app, current_room, "[Server]", f"User '{target_name} has been banned.")
                continue

    # =====================
    # DISCONNECT
    # =====================

    rooms[current_room]["clients"].discard(ws)
    user_room.pop(ws, None)

    await broadcast(request.app, current_room, name, "[left]")

    usernames.pop(ws, None)
    online_users.discard(name)

    await send_user_list(request.app)

    return ws


# ==================================================
# app setup
# ==================================================

app = web.Application()

app.router.add_get("/ws", ws_handler)
app.router.add_static("/static/", "./static", show_index=False)

async def home(request):
    return web.FileResponse("client.html")

app.on_startup.append(init_db)
app.on_cleanup.append(close_db)

app.router.add_get("/", home)

web.run_app(app, port=int(os.environ.get("PORT", 8000)))

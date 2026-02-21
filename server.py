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
        min_size=1,
        max_size=100,
        ssl="require"
    )

    try:
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
    except Exception as e:
        print(f"Database setup failed: {e}")


async def close_db(app):
    await app["db"].close()


# ==================================================
# DB helpers
# ==================================================

async def db_create_room(app, name, private):
    async with app["db"].acquire() as conn:
        await conn.execute(
            """
            INSERT INTO rooms(name, private)
            VALUES ($1, $2)
            ON CONFLICT (name) DO NOTHING
            """,
            name, private
        )


async def db_add_message(app, room, username, message):
    async with app["db"].acquire() as conn:
        await conn.execute(
            "INSERT INTO messages (room, username, message) VALUES ($1, $2, $3)",
            room, username, message
        )


async def db_get_messages(app, room, limit=10000):
    async with app["db"].acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT username, message
            FROM messages
            WHERE room = $1 AND username != '[Server]'
            ORDER BY id ASC
            LIMIT $2
            """,
            room, limit
        )
    return [f"{r['username']}: {r['message']}" for r in rows]


async def db_username_exists(app, name):
    async with app["db"].acquire() as conn:
        row = await conn.fetchrow("SELECT 1 FROM users WHERE name = $1", name)
        return row is not None


async def db_get_user(app, device):
    async with app["db"].acquire() as conn:
        row = await conn.fetchrow("SELECT name FROM users WHERE device = $1", device)
        return row["name"] if row else None


async def db_set_username(app, device, name):
    if not re.match(r'^[A-Za-z0-9_]{3,20}$', name):
        return False

    try:
        async with app["db"].acquire() as conn:
            result = await conn.execute(
                """
                INSERT INTO users(device, name) VALUES($1, $2)
                ON CONFLICT (device) DO UPDATE SET name = EXCLUDED.name
                WHERE NOT EXISTS (
                    SELECT 1 FROM users WHERE name = $2 AND device != $1
                )
                """,
                device, name
            )
        return result.split()[-1] != "0"
    except Exception as e:
        print(f"db_set_username error: {e}")
        return False


async def db_get_all_users(app):
    async with app["db"].acquire() as conn:
        rows = await conn.fetch("SELECT name FROM users")
    return [r["name"] for r in rows]


async def db_ban_user(app, username):
    async with app["db"].acquire() as conn:
        await conn.execute(
            "UPDATE users SET banned = TRUE WHERE name = $1",
            username
        )


async def db_is_banned(app, device):
    async with app["db"].acquire() as conn:
        row = await conn.fetchrow(
            "SELECT banned FROM users WHERE device = $1", device
        )
        return row["banned"] if row else False


# ==================================================
# HTTP send_message route
# ==================================================

async def send_message(request):
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"ok": False, "error": "Invalid JSON"}, status=400)

    device = data.get("device")
    room = data.get("room")
    message = data.get("message")

    if not device or not room or not message:
        return web.json_response({"ok": False, "error": "Missing fields"}, status=400)

    if not isinstance(device, str) or not isinstance(room, str) or not isinstance(message, str):
        return web.json_response({"ok": False, "error": "Invalid field types"}, status=400)

    username = await db_get_user(request.app, device)
    if not username:
        username = "Anonymous"

    await db_add_message(request.app, room, username, message)

    if room in rooms:
        formatted = f"{username}: {message}"
        for ws in list(rooms[room]["clients"]):
            try:
                await ws.send_str(formatted)
            except Exception:
                pass

    return web.json_response({"ok": True})


# ==================================================
# Runtime state
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

ADMIN_DEVICES = {"351843eb-f2bc-4769-8430-6235a7feb22a"}

DEVICE_ID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)


# ==================================================
# Helpers
# ==================================================

def make_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))


def filter_text(msg):
    for bad in bad_words:
        msg = re.sub(rf"\b{bad}\w*\b", "*" * len(bad), msg, flags=re.I)
    return msg


def sanitize_message(msg):
    msg = msg.replace('\x00', '')
    return msg[:2000]


async def broadcast(app, room, username, message):
    if room not in rooms:
        return
    await db_add_message(app, room, username, message)
    formatted = f"{username}: {message}"
    for ws in list(rooms[room]["clients"]):
        try:
            await ws.send_str(formatted)
        except Exception:
            pass


async def send_event(room, text):
    """Send a join/leave/ban notification to all clients in a room."""
    if room not in rooms:
        return
    payload = json.dumps({"type": "event", "text": text})
    for ws_client in list(rooms[room]["clients"]):
        try:
            await ws_client.send_str(payload)
        except Exception:
            pass


async def send_user_list(app):
    all_users = await db_get_all_users(app)
    payload = json.dumps({
        "type": "users",
        "online": list(online_users),
        "all": all_users
    })
    for room in rooms.values():
        for ws in list(room["clients"]):
            try:
                await ws.send_str(payload)
            except Exception:
                pass


# ==================================================
# WebSocket handler
# ==================================================

async def ws_handler(request):
    global user_counter

    ws = web.WebSocketResponse(max_msg_size=MAX_SIZE + 1024)
    await ws.prepare(request)

    device = None
    name = None

    # =====================
    # AUTH
    # =====================

    try:
        auth_msg = await ws.receive()

        if auth_msg.type == web.WSMsgType.TEXT:
            data = json.loads(auth_msg.data)

            if data.get("type") == "auth":
                raw_device = data.get("deviceId", "")

                if not DEVICE_ID_PATTERN.match(raw_device):
                    await ws.send_str("[Server]: Invalid device ID.")
                    await ws.close()
                    return ws

                device = raw_device
                requested_name = data.get("username")

                if requested_name:
                    success = await db_set_username(request.app, device, requested_name)
                    if success:
                        name = requested_name
                    else:
                        name = await db_get_user(request.app, device)
                else:
                    name = await db_get_user(request.app, device)

    except Exception as e:
        print(f"Auth error: {e}")

    if not device:
        try:
            await ws.send_str("[Server]: Authentication failed.")
            await ws.close()
        except Exception:
            pass
        return ws

    if not name:
        while True:
            candidate = f"Anonymous{user_counter:03d}"
            user_counter += 1
            success = await db_set_username(request.app, device, candidate)
            if success:
                name = candidate
                break
            if user_counter > 99999:
                await ws.send_str("[Server]: Could not assign a username.")
                await ws.close()
                return ws

    usernames[ws] = name
    online_users.add(name)
    ws.device = device

    await ws.send_str(json.dumps({"type": "auth_ok", "username": name}))

    # =====================
    # JOIN GLOBAL
    # =====================

    current_room = "global"
    rooms["global"]["clients"].add(ws)
    user_room[ws] = "global"

    for old in await db_get_messages(request.app, "global"):
        try:
            await ws.send_str(old)
        except Exception:
            pass

    await send_event("global", f"{name} joined")
    await send_user_list(request.app)

    # =====================
    # MAIN LOOP
    # =====================

    try:
        async for msg in ws:

            if msg.type == web.WSMsgType.BINARY:
                room = user_room[ws]

                if not rooms[room]["private"]:
                    await ws.send_str("[Server]: Images only allowed in private rooms.")
                    continue

                if len(msg.data) > MAX_SIZE:
                    await ws.send_str("[Server]: Image too large (max 25MB).")
                    continue

                if not msg.data.startswith(b'\x89PNG') and not msg.data.startswith(b'\xff\xd8'):
                    await ws.send_str("[Server]: Only PNG/JPG allowed.")
                    continue

                for client in list(rooms[room]["clients"]):
                    if client != ws:
                        try:
                            await client.send_bytes(msg.data)
                        except Exception:
                            pass

                continue

            if msg.type != web.WSMsgType.TEXT:
                continue

            text = sanitize_message(msg.data.strip())

            if not text:
                continue

            # =====================
            # BAN CHECK
            # =====================

            if await db_is_banned(request.app, device):
                await ws.send_str("[Server]: You are banned and cannot send messages.")
                continue

            # =====================
            # ADMIN COMMANDS
            # =====================

            if text.startswith(".") and device in ADMIN_DEVICES:
                parts = text.split()
                cmd = parts[0].lower()

                if cmd == ".ban" and len(parts) > 1:
                    target_name = parts[1]
                    await db_ban_user(request.app, target_name)
                    await send_event(current_room, f"{target_name} has been banned.")

                continue 
            # =====================
            # CREATE ROOM
            # =====================

            if text == "/create":
                code = make_code()
                while code in rooms:
                    code = make_code()

                rooms[code] = {"clients": set(), "private": True}
                await db_create_room(request.app, code, True)

                rooms[current_room]["clients"].discard(ws)
                current_room = code
                user_room[ws] = code
                rooms[code]["clients"].add(ws)

                await ws.send_str(json.dumps({"type": "event", "text": f"Room created — code: {code}"}))
                await send_user_list(request.app)
                continue

            # =====================
            # JOIN ROOM
            # =====================

            if text.startswith("/join "):
                code = text.split(" ", 1)[1].strip()

                if not re.match(r'^[A-Z0-9]{6}$', code) and code != "global":
                    await ws.send_str(json.dumps({"type": "event", "text": "Invalid room code."}))
                    continue

                if code not in rooms:
                    await ws.send_str(json.dumps({"type": "event", "text": "Room not found."}))
                    continue

                await send_event(current_room, f"{name} left")
                rooms[current_room]["clients"].discard(ws)
                current_room = code
                user_room[ws] = code
                rooms[code]["clients"].add(ws)

                for old in await db_get_messages(request.app, code):
                    try:
                        await ws.send_str(old)
                    except Exception:
                        pass

                await send_event(current_room, f"{name} joined")
                await send_user_list(request.app)
                continue

            # =====================
            # NORMAL MESSAGE
            # =====================

            clean = filter_text(text) if current_room == "global" else text
            await broadcast(request.app, current_room, name, clean)

    except Exception as e:
        print(f"WS loop error for {name}: {e}")

    finally:
        # =====================
        # DISCONNECT
        # =====================
        rooms[current_room]["clients"].discard(ws)
        user_room.pop(ws, None)
        usernames.pop(ws, None)
        online_users.discard(name)

        await send_event(current_room, f"{name} disconnected")
        await send_user_list(request.app)

    return ws


# ==================================================
# App setup
# ==================================================

app = web.Application()

app.router.add_get("/ws", ws_handler)
app.router.add_post("/send", send_message)
app.router.add_static("/static/", "./static", show_index=False)


async def home(request):
    return web.FileResponse("client.html")


app.on_startup.append(init_db)
app.on_cleanup.append(close_db)

app.router.add_get("/", home)

web.run_app(app, port=int(os.environ.get("PORT", 8000)))
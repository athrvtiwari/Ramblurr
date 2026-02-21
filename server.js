const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    throw new Error("JWT_SECRET not set");
}

const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const { Pool } = require("pg");
const crypto = require("crypto");

// ==================================================
// Postgres Setup
// ==================================================

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

async function initDb() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS rooms(
            name TEXT PRIMARY KEY,
            private BOOLEAN
        );
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users(
            device TEXT PRIMARY KEY,
            name TEXT UNIQUE,
            banned BOOLEAN DEFAULT FALSE
        );
    `);
    await pool.query(`
        CREATE TABLE IF NOT EXISTS messages(
            id SERIAL PRIMARY KEY,
            room TEXT,
            username TEXT,
            message TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
    `);
    await dbCreateRoom("global", false);
    console.log("Database ready.");
}

// ==================================================
// DB helpers
// ==================================================

async function dbCreateRoom(name, private_room) {
    await pool.query(
        `INSERT INTO rooms(name, private) VALUES($1, $2) ON CONFLICT (name) DO NOTHING`,
        [name, private_room]
    );
}

async function dbAddMessage(room, username, message) {
    await pool.query(
        `INSERT INTO messages(room, username, message) VALUES($1, $2, $3)`,
        [room, username, message]
    );
}

async function dbGetMessages(room, limit = 10000) {
    const res = await pool.query(
        `SELECT username, message FROM messages
         WHERE room = $1 AND username != '[Server]'
         ORDER BY id ASC LIMIT $2`,
        [room, limit]
    );
    return res.rows.map(r => `${r.username}: ${r.message}`);
}

async function dbGetUser(device) {
    const res = await pool.query(
        `SELECT name FROM users WHERE device = $1`,
        [device]
    );
    return res.rows[0]?.name || null;
}

async function dbSetUsername(device, name) {
    if (!/^[A-Za-z0-9_]{3,20}$/.test(name)) return false;

    try {
        const res = await pool.query(
            `INSERT INTO users(device, name) VALUES($1, $2)
             ON CONFLICT (device) DO UPDATE SET name = EXCLUDED.name
             WHERE NOT EXISTS (
                 SELECT 1 FROM users WHERE name = $2 AND device != $1
             )`,
            [device, name]
        );
        return res.rowCount > 0;
    } catch (e) {
        console.error("dbSetUsername error:", e.message);
        return false;
    }
}

async function dbGetAllUsers() {
    const res = await pool.query(`SELECT name FROM users`);
    return res.rows.map(r => r.name);
}

async function dbBanUser(username) {
    await pool.query(`UPDATE users SET banned = TRUE WHERE name = $1`, [username]);
}

async function dbIsBanned(device) {
    const res = await pool.query(
        `SELECT banned FROM users WHERE device = $1`,
        [device]
    );
    return res.rows[0]?.banned || false;
}

// ==================================================
// Runtime state
// ==================================================

const rooms = {
    global: { clients: new Set(), private: false }
};

const onlineUsers = new Set();
let userCounter = 1;

const MAX_SIZE = 25 * 1024 * 1024;

const BAD_WORDS = new Set([
    'fuck', 'fucking', 'shit', 'bitch', 'bastard', 'dick', 'cock', 'pussy', 'asshole', 'crap', 'douche', 'douchebag',
    'slut', 'whore', 'cunt', 'nigga', 'nigger', 'nazi', 'retard',
    'sex', 'porn', 'xxx', 'cum', 'dildo', 'penis', 'vagina', 'boobs', 'tits', 'anal', 'blowjob', 'handjob', 'milf', 'orgy', 'fetish',
    'idiot', 'stupid', 'moron', 'loser', 'jerk', 'dumb', 'twat', 'fag', 'gay', 'lame', 'fatass', 'shithead', 'tool', 'retarded',
    'wtf', 'fml', 'lmao', 'lmfao', 'piss', 'hell', 'shitface', 'asswipe',
    'kill', 'rape', 'terrorist', 'bomb', 'suicide', 'shoot', 'killself'
]);

// ==================================================
// Helpers
// ==================================================

function makeCode() {
    return crypto.randomBytes(3).toString("hex").toUpperCase();
}

function filterText(msg) {
    for (const bad of BAD_WORDS) {
        msg = msg.replace(new RegExp(`\\b${bad}\\w*\\b`, "gi"), "*".repeat(bad.length));
    }
    return msg;
}

function sanitizeMessage(msg) {
    return msg.replace(/\x00/g, "").slice(0, 2000);
}

async function broadcast(room, username, message) {
    if (!rooms[room]) return;
    await dbAddMessage(room, username, message);
    const formatted = `${username}: ${message}`;
    for (const client of [...rooms[room].clients]) {
        if (client.readyState === WebSocket.OPEN) {
            try { client.send(formatted); } catch {}
        }
    }
}

async function sendEvent(room, text) {
    if (!rooms[room]) return;
    const payload = JSON.stringify({ type: "event", text });
    for (const client of [...rooms[room].clients]) {
        if (client.readyState === WebSocket.OPEN) {
            try { client.send(payload); } catch {}
        }
    }
}

async function sendUserList() {
    const allUsers = await dbGetAllUsers();
    const payload = JSON.stringify({
        type: "users",
        online: [...onlineUsers],
        all: allUsers
    });
    for (const room of Object.values(rooms)) {
        for (const client of [...room.clients]) {
            if (client.readyState === WebSocket.OPEN) {
                try { client.send(payload); } catch {}
            }
        }
    }
}

// ==================================================
// Express + HTTP server
// ==================================================

const app = express();
app.use(express.json());
app.use("/static", express.static("./static"));
app.get("/", (req, res) => res.sendFile(__dirname + "/client.html"));

app.post("/send", async (req, res) => {
    const { token, room, message } = req.body;

    if (!token || !room || !message) {
        return res.json({ ok: false });
    }

    let decoded;
    try {
        decoded = jwt.verify(token, JWT_SECRET);
    } catch {
        return res.json({ ok: false });
    }

    const device = decoded.device;
    const username = (await dbGetUser(device)) || "Anonymous";

    await dbAddMessage(room, username, message);

    if (rooms[room]) {
        const formatted = `${username}: ${message}`;
        for (const client of [...rooms[room].clients]) {
            if (client.readyState === WebSocket.OPEN) {
                try { client.send(formatted); } catch {}
            }
        }
    }

    res.json({ ok: true });
});

const server = http.createServer(app);

// ==================================================
// WebSocket handler
// ==================================================

const wss = new WebSocket.Server({ server, path: "/ws", maxPayload: MAX_SIZE + 1024 });

wss.on("connection", async (ws) => {
    let device = null;
    let name = null;
    let currentRoom = "global";
    let role = "user";

    // =====================
    // AUTH
    // =====================
    const authResult = await new Promise((resolve) => {
        const timeout = setTimeout(() => resolve(null), 10000);

        ws.onerror("message", async (data) => {
            clearTimeout(timeout);

            try {
                const msg = JSON.parse(data.toString());

                // REGISTER
                if (msg.type === "register") {
                    const newDevice = crypto.randomUUID();

                    const token = jwt.sign(
                        { device: newDevice, role: "user" },
                        JWT_SECRET,
                        { expiresIn: "30d" }
                    );

                    await pool.query(
                        `INSERT INTO users(device) VALUES($1)
                         ON CONFLICT (device) DO NOTHING`,
                        [newDevice]
                    );

                    ws.send(JSON.stringify({
                        type: "registered",
                        token
                    }));

                    return resolve({ device: newDevice, role: "user" });
                };

                // RETURNING USER
                if (msg.type === "auth" && msg.token) {
                    try {
                        const decoded = jwt.verify(msg.token, JWT_SECRET);

                        return resolve({
                            device: decoded.device,
                            role: decoded.role || "user"
                        });
                    } catch {
                        return resolve(null);
                    }
                }

                resolve(null);
            } catch {
                resolve(null);
            }
        });
    });

    if (!authResult) {
        ws.send("[Server]: Authentication failed.");
        ws.close();
        return;
    }

    device = authResult.device;
    role = authResult.role;
    
    // Assign anonymous name if needed
    if (!name) {
        while (true) {
            const candidate = `Anonymous${String(userCounter).padStart(3, "0")}`;
            userCounter++;
            const ok = await dbSetUsername(device, candidate);
            if (ok) { name = candidate; break; }
            if (userCounter > 99999) {
                try { ws.send("[Server]: Could not assign username."); ws.close(); } catch {}
                return;
            }
        }
    }

    ws.device = device;
    ws.name = name;

    onlineUsers.add(name);

    ws.send(JSON.stringify({ type: "auth_ok", username: name }));

    // =====================
    // JOIN GLOBAL
    // =====================

    rooms["global"].clients.add(ws);
    currentRoom = "global";

    const history = await dbGetMessages("global");
    for (const old of history) {
        try { ws.send(old); } catch {}
    }

    await sendEvent("global", `${name} joined`);
    await sendUserList();

    // =====================
    // MAIN MESSAGE HANDLER
    // =====================

    ws.on("message", async (data, isBinary) => {
        try {
            // IMAGE
            if (isBinary) {
                if (!rooms[currentRoom]?.private) {
                    ws.send("[Server]: Images only allowed in private rooms.");
                    return;
                }
                if (data.length > MAX_SIZE) {
                    ws.send("[Server]: Image too large (max 25MB).");
                    return;
                }
                const header = data.slice(0, 4);
                const isPNG = header[0] === 0x89 && header[1] === 0x50;
                const isJPG = header[0] === 0xFF && header[1] === 0xD8;
                if (!isPNG && !isJPG) {
                    ws.send("[Server]: Only PNG/JPG allowed.");
                    return;
                }
                for (const client of [...rooms[currentRoom].clients]) {
                    if (client !== ws && client.readyState === WebSocket.OPEN) {
                        try { client.send(data, { binary: true }); } catch {}
                    }
                }
                return;
            }

            const text = sanitizeMessage(data.toString().trim());
            if (!text) return;

            // BAN CHECK
            if (await dbIsBanned(device)) {
                ws.send("[Server]: You are banned and cannot send messages.");
                return;
            }

            // ADMIN COMMANDS
            if (text.startsWith(".") && role === "admin") {
                const parts = text.split(/\s+/);
                const cmd = parts[0].toLowerCase();
                if (cmd === ".ban" && parts[1]) {
                    await dbBanUser(parts[1]);
                    await sendEvent(currentRoom, `${parts[1]} has been banned.`);
                }
                return; 
            }

            // CREATE ROOM
            if (text === "/create") {
                let code = makeCode();
                while (rooms[code]) code = makeCode();

                rooms[code] = { clients: new Set(), private: true };
                await dbCreateRoom(code, true);

                rooms[currentRoom].clients.delete(ws);
                currentRoom = code;
                rooms[code].clients.add(ws);

                ws.send(JSON.stringify({ type: "event", text: `Room created — code: ${code}` }));
                await sendUserList();
                return;
            }

            // JOIN ROOM
            if (text.startsWith("/join ")) {
                const code = text.split(" ")[1]?.trim();
                if (!code || (!/^[A-Z0-9]{6}$/.test(code) && code !== "global")) {
                    ws.send(JSON.stringify({ type: "event", text: "Invalid room code." }));
                    return;
                }
                if (!rooms[code]) {
                    ws.send(JSON.stringify({ type: "event", text: "Room not found." }));
                    return;
                }

                await sendEvent(currentRoom, `${name} left`);
                rooms[currentRoom].clients.delete(ws);
                currentRoom = code;
                rooms[code].clients.add(ws);

                const roomHistory = await dbGetMessages(code);
                for (const old of roomHistory) {
                    try { ws.send(old); } catch {}
                }

                await sendEvent(currentRoom, `${name} joined`);
                await sendUserList();
                return;
            }

            // NORMAL MESSAGE
            const clean = currentRoom === "global" ? filterText(text) : text;
            await broadcast(currentRoom, name, clean);

        } catch (e) {
            console.error(`Message handler error for ${name}:`, e.message);
        }
    });

    // =====================
    // DISCONNECT
    // =====================

    ws.on("close", async () => {
        try {
            rooms[currentRoom]?.clients.delete(ws);
            onlineUsers.delete(name);
            await sendEvent(currentRoom, `${name} disconnected`);
            await sendUserList();
        } catch (e) {
            console.error(`Disconnect error for ${name}:`, e.message);
        }
    });

    ws.on("error", (e) => {
        console.error(`WS error for ${name}:`, e.message);
    });
});

// ==================================================
// Start
// ==================================================

const PORT = process.env.PORT || 8000;

initDb().then(() => {
    server.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}).catch(e => {
    console.error("Failed to init DB:", e.message);
    process.exit(1);
});

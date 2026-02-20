// =======================
// DYNAMIC TITLE
// =======================
const titles = ["W", "We", "Wel", "Welc", "Welco", "Welcom", "Welcome ", "Welcome t", "Welcome to ", "Welcome to R", "Welcome to Ra", "Welcome to Ram", "Welcome to Ramb", "Welcome to Rambl", "Welcome to Ramblu", "Welcome to Ramblur", "Welcome to Ramblurr", "Welcome to Ramblurr!", "~ Enjoy your stay! ~"];
        let index = 0;

        function changeTitle() {
            document.title = titles[index];
            index = (index + 1) % titles.length;
        }

        setInterval(changeTitle, 500);

// =======================
// DEVICE ID (persistent)
// =======================

let deviceId = localStorage.getItem("deviceId");

if (!deviceId) {
    deviceId = crypto.randomUUID();
    localStorage.setItem("deviceId", deviceId);
}

let username = localStorage.getItem("username");

if (!username) {
    username = prompt("Enter a username (3-20 characters, letters/numbers/_):");

    if (username) {
        fetch("/set_username", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                device: deviceId,
                name: username
            })
        }).then(res => res.json()).then(data => {
            if (data.success) {
                localStorage.setItem("username", username);
            } else {
                alert(data.error);
            }
        });
    }
}

// =======================
// ELEMENTS
// =======================

const chat = document.getElementById("c");
const input = document.getElementById("m");
const codeInput = document.getElementById("codeInput");
const emojiBtn = document.getElementById("emojiBtn");
const emojiPicker = document.getElementById("emojiPicker");
const userList = document.getElementById("userList");
const sendBtn = document.getElementById("sendBtn");

let myName = null;


// =======================
// COLOR HELPER (NEW)
// =======================

function nameToColor(name) {
    let hash = 0;

    for (let i = 0; i < name.length; i++) {
        hash = name.charCodeAt(i) + ((hash << 5) - hash);
    }

    const hue = Math.abs(hash) % 360;
    return `hsl(${hue}, 70%, 60%)`;
}


// =======================
// WEBSOCKET
// =======================

const protocol = location.protocol === "https:" ? "wss://" : "ws://";
const ws = new WebSocket(protocol + location.host + "/ws");


// =======================
// CHAT RENDER HELPERS
// =======================

function scrollChat() {
    chat.scrollTop = chat.scrollHeight;
}

function addSystem(text) {
    const div = document.createElement("div");
    div.className = "system";
    div.textContent = text;
    chat.appendChild(div);
    scrollChat();
}

function addMessage(sender, text, side) {
    const wrapper = document.createElement("div");
    wrapper.className = `msg-wrapper ${side}`;

    const name = document.createElement("div");
    name.className = "sender";
    name.textContent = sender;

    // ✅ colored usernames
    name.style.color = nameToColor(sender);

    const bubble = document.createElement("div");
    bubble.className = "msg bubble";
    bubble.textContent = text;

    wrapper.appendChild(name);
    wrapper.appendChild(bubble);
    chat.appendChild(wrapper);

    scrollChat();
}

function addImage(blob, side) {
    const wrapper = document.createElement("div");
    wrapper.className = `msg-wrapper ${side}`;

    const img = document.createElement("img");
    img.src = URL.createObjectURL(blob);
    img.className = "msg image";

    wrapper.appendChild(img);
    chat.appendChild(wrapper);

    scrollChat();
}


// =======================
// USER LIST (NEW)
// =======================

function renderUsers(online, all) {
    if (!userList) return;

    userList.innerHTML = "";

    for (const name of all) {
        const div = document.createElement("div");
        div.className = "user " + (online.includes(name) ? "online" : "offline");
        div.textContent = name;

        // colored in sidebar too
        div.style.color = nameToColor(name);

        userList.appendChild(div);
    }
}


// =======================
// SEND HELPERS
// =======================

function sendText(text) {
    if (!text || ws.readyState !== WebSocket.OPEN) return;
    ws.send(text);
}

function sendImage(file) {
    if (!file || ws.readyState !== WebSocket.OPEN) return;
    addImage(file, "self"); // show immediately
    file.arrayBuffer().then(buf => ws.send(buf));
}

// =======================
// SOCKET EVENTS
// =======================

ws.onopen = () => {
    ws.send(JSON.stringify({ type: "auth", deviceId, username}));
    addSystem("[Connected]");
};

ws.onerror = () => addSystem("[Connection error]");

ws.onmessage = (e) => {

    // ===== IMAGE =====
    if (e.data instanceof Blob) {
        addImage(e.data, "other");
        return;
    }

    const text = e.data;

    // ===== JSON (user list update) =====
    try {
        const data = JSON.parse(text);

        if (data.type === "users") {
            renderUsers(data.online, data.all);
            return;
        }
    } catch {}

    // detect own username
    const joinMatch = text.match(/^\[(.+?) joined\]$/);
    if (joinMatch && !myName) {
        myName = joinMatch[1];
    }

    // normal chat: "Name: message"
    const msgMatch = text.match(/^([^:]+):\s(.+)$/);

    if (msgMatch) {
        const sender = msgMatch[1];
        const content = msgMatch[2];
        const side = sender === myName ? "self" : "other";
        addMessage(sender, content, side);
    } else {
        addSystem(text);
    }
};


// =======================
// TEXT INPUT
// =======================

sendBtn.addEventListener("click", () => {
    sendText(input.value.trim());
    input.value = "";
});

input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
        e.preventDefault();
        sendText(input.value.trim());
        input.value = "";
    }
});

// =======================
// ROOMS
// =======================

function createRoom() {
    sendText("/create");
}

function joinRoom() {
    const code = codeInput.value.trim();
    if (code) sendText("/join " + code);
}

function joinGlobal() {
    sendText("/join global");
}


// =======================
// PASTE IMAGE SUPPORT
// =======================

document.addEventListener("paste", (e) => {
    const items = e.clipboardData?.items || [];

    for (const item of items) {
        if (item.type.startsWith("image/")) {
            sendImage(item.getAsFile());
            e.preventDefault();
        }
    }
});


// =======================
// DRAG & DROP SUPPORT
// =======================

document.addEventListener("dragover", (e) => {
    e.preventDefault();
    chat.classList.add("dragging");
});

document.addEventListener("dragleave", () => {
    chat.classList.remove("dragging");
});

document.addEventListener("drop", (e) => {
    e.preventDefault();
    chat.classList.remove("dragging");

    for (const file of e.dataTransfer.files) {
        if (file.type.startsWith("image/")) {
            sendImage(file);
        }
    }
});


// =======================
// EMOJI PICKER
// =======================

const emojis = [
    "😀","😁","😂","🤣","😅","😊","😍","🥰","😎","🤓",
    "😐","😴","😭","😡","🤯","😱","🥶","🥵","👍","👎",
    "👏","🙏","🔥","💀","❤️","💔","⭐","✨","🎉","💯",
    "🍕","🍔","🍟","🥤","🎮","⚽","🏆","🚀","🌙","☀️"
];

emojis.forEach(e => {
    const span = document.createElement("span");
    span.textContent = e;

    span.onclick = () => {
        input.value += e;
        input.focus();
    };

    emojiPicker.appendChild(span);
});

emojiBtn.onclick = () => {
    emojiPicker.classList.toggle("hidden");
};

document.addEventListener("click", (e) => {
    if (!emojiPicker.contains(e.target) && e.target !== emojiBtn) {
        emojiPicker.classList.add("hidden");
    }
});

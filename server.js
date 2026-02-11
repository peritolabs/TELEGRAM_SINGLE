// ===============================================
// TELEGRAM SERVER (Admin + Agent Role-Based)
// ===============================================
require("dotenv").config();

const express = require("express");
const https = require("https");
const cors = require("cors");
const { Server } = require("socket.io");
const mongoose = require("mongoose");

const { TelegramClient, Api } = require("telegram");
const { StringSession } = require("telegram/sessions");
const { NewMessage } = require("telegram/events");
const { CustomFile } = require("telegram/client/uploads");
const fs = require("fs");
const path = require("path");

const TelegramSession = require("./models/TelegramSession");
const ChatIndex = require("./models/ChatIndex");
const Message = require("./models/Message");
const NumberNameCache = require("./models/NumberNameCache");
const TenantAgent = require("./models/TenantAgent")

const { decryptMessage, encryptMessage } = require("./aes")

// -----------------------------------------------
// MongoDB
// -----------------------------------------------
mongoose
    .connect(process.env.MONGO_URL, { dbName: "TG_AICONNECT_SINGLE" })
    .then(() => console.log("📦 MongoDB Bağlandı"))
    .catch((err) => console.log("MongoDB Hatası:", err));

// Express and Servers
const app = express();

// Middleware
app.use(express.json());
app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
}));

// SSL sertifikası dosyaları
const sslOptions = {
    key: fs.readFileSync('/etc/letsencrypt/live/tgs.aiconnect.com.tr/privkey.pem'),
    cert: fs.readFileSync('/etc/letsencrypt/live/tgs.aiconnect.com.tr/cert.pem'),
    ca: fs.readFileSync('/etc/letsencrypt/live/tgs.aiconnect.com.tr/chain.pem'),
};

const server = https.createServer(sslOptions, app); // HTTPS sunucusu oluşturuldu
const io = new Server(server, {
    cors: {
        origin: [
            'http://localhost:3000',
            'https://waclient.aiconnect.com.tr',
            'https://waserver.aiconnect.com.tr',
            'https://demo.aiconnect.com.tr',
        ], // Bağlantı kurulacak originler eklendi
        methods: ['GET', 'POST'],
        credentials: true,
        allowedHeaders: ['origin', 'X-Requested-With', 'Content-Type', 'Accept'],
    },
    pingInterval: 25000, // Ping aralığı
    pingTimeout: 20000,  // Ping zaman aşımı
    maxPayload: 100000000, // Maksimum yük boyutu
});


const apiId = Number(process.env.API_ID);
const apiHash = process.env.API_HASH;

// Tüm Telegram clientları
const tgClients = new Map(); // key = tenantId:agentId

// ====================================================
// HELPER
// ====================================================
function buildKey(tenantId, agentId) {
    return `${tenantId}:${agentId}`;
}

function waitForEvent(socket, event) {
    return new Promise((resolve) => socket.once(event, resolve));
}

function buildChatKey(tenantId, telegramname) {
    return `${tenantId}-${telegramname}`;
}

async function saveMessageToDB(data) {
    const m = new Message(data);
    await m.save();
    return m;
}

async function getCustomerNameFromCacheOrPacket(client, tenantId, userId, packetUser) {
    const userKey = String(userId);

    // 1️⃣ CACHE'E BAK
    const cached = await NumberNameCache.findOne({
        tenantId,
        telegramname: userKey,
    });

    // 📌 İsimleri hesapla (gerekirse)
    const resolvedTelegramName =
        packetUser?.username || userKey;

    const resolvedName =
        [packetUser?.firstName, packetUser?.lastName]
            .filter(Boolean)
            .join(" ")
        || packetUser?.username
        || `TG_${userKey}`;

    // 2️⃣ CACHE VARSA
    if (cached) {
        console.log(cached)
        // 🔥 chatKey YOKSA → İLK KEZ SABİTLE
        if (!cached.chatKey) {
            const chatKey = `${tenantId}-${resolvedTelegramName}`;

            cached.chatKey = chatKey;
            cached.name = resolvedName; // güncel isim
            cached.updatedAt = new Date();

            await cached.save();

            return {
                telegramname: userKey,
                name: resolvedName,
                chatKey,
                fromCache: true,
            };
        }

        // ✅ chatKey VAR → ASLA DEĞİŞTİRME
        // sadece isim güncellenebilir
        if (cached.name !== resolvedName) {
            cached.name = resolvedName;
            cached.updatedAt = new Date();
            await cached.save();
        }

        return {
            telegramname: userKey,
            name: cached.name,
            chatKey: cached.chatKey,
            fromCache: true,
        };
    }

    // 3️⃣ CACHE YOK → İLK MESAJ
    const chatKey = `${tenantId}-${resolvedTelegramName}`;

    await NumberNameCache.create({
        tenantId,
        telegramname: userKey,
        name: resolvedName,
        chatKey,
        source: "telegram",
        updatedAt: new Date(),
    });

    return {
        telegramname: userKey,
        name: resolvedName,
        chatKey,
        fromCache: false,
    };
}

async function ensureChatIndex({
    tenantId,
    chatKey,
    telegramname,
    name,
    ownerAgentId,
    assignedAgentId,
    assignedAgentExtension,
}) {
    const now = new Date();

    await ChatIndex.findOneAndUpdate(
        { tenantId, chatKey },
        {
            $setOnInsert: {
                tenantId,
                chatKey,
                telegramname,
                name,
                ownerAgentId,
            },
            $set: {
                assignedAgentId,
                assignedAgentExtension,
                lastMessageAt: now,
                isActive: true,

            },
        },
        { upsert: true }
    );
}

async function buildAdminActiveChatsList(tenantId) {
    const rows = await ChatIndex.find({ tenantId, isActive: true }).sort({ lastMessageAt: -1 }).lean();

    return rows.map(r => ({
        chatKey: r.chatKey,
        telegramname: r.telegramname,
        name: r.name,
        ownerAgentId: r.ownerAgentId,
        assignedAgentId: r.assignedAgentId,
        assignedAgentExtension: r.assignedAgentExtension,
        lastMessageAt: r.lastMessageAt ? r.lastMessageAt.toISOString() : null,
    }));
}

async function buildAgentActiveChatsList(tenantId, agentId) {
    const rows = await ChatIndex.find({
        tenantId: String(tenantId),
        isActive: true,
        $or: [
            { ownerAgentId: String(agentId) },
            { assignedAgentId: String(agentId) },
        ],

    })
        .sort({ lastMessageAt: -1 })
        .lean();

    return rows.map(r => ({
        chatKey: r.chatKey,
        telegramname: r.telegramname,
        name: r.name,
        ownerAgentId: r.ownerAgentId,
        assignedAgentId: r.assignedAgentId,
        lastMessageAt: r.lastMessageAt ? r.lastMessageAt.toISOString() : null,
    }));
}

function emitActiveChatsToAdmins(tenantId, list) {
    io.sockets.sockets.forEach((socket) => {
        const q = socket.handshake.query;
        if (q.role === "admin" && q.tenantId === String(tenantId)) {
            const json = JSON.stringify(list);
            const encrypted = encryptMessage(json)
            socket.emit("active-chats", { data: encrypted });
        }
    });
}

async function emitActiveChats(tenantId, agentId = null) {
    if (agentId) {
        const list = await buildAgentActiveChatsList(tenantId, agentId);
        const json = JSON.stringify(list);
        const encrypted = encryptMessage(json)
        io.to(`agent:${tenantId}:${agentId}`).emit("active-chats", { data: encrypted });
        return;
    }

    const list = await buildAdminActiveChatsList(tenantId);
    emitActiveChatsToAdmins(tenantId, list);
}

async function buildTenantAgentsList(tenantId) {
    const rows = await TenantAgent.find({ tenantId }).lean();

    return rows.map(a => ({
        userId: a.agentId,
        role: a.role,
        extension: a.extension,
        lastSeenAt: a.updatedAt,
        userName: a.userTitle
    }));
}

async function emitTenantAgents(tenantId) {
    const list = await buildTenantAgentsList(tenantId);

    io.to(`admin:tenant:${tenantId}`).emit("tenant-agents", list);
}

async function getTelegramAccountInfo(client) {
    try {
        const me = await client.getMe();

        return {
            telegramId: me.id?.value ? String(me.id.value) : String(me.id),
            username: me.username || null,
            phone: me.phone || null,
        };
    } catch (err) {
        console.error("getTelegramAccountInfo error:", err);
        return null;
    }
}

async function checkTelegramSessionStatus(tenantId, agentId) {
    const key = buildKey(tenantId, agentId);

    console.log("tgclients -->", tgClients)

    // 1️⃣ RAM'de aktif client varsa (EN GÜVENİLİR)
    const client = tgClients.get(key);
    if (client) {
        const account = await getTelegramAccountInfo(client);

        return {
            loggedIn: true,
            source: "memory",
            account,
        };
    }

    // 2️⃣ DB'de session var mı? (henüz connect edilmemiş olabilir)
    const saved = await TelegramSession.findOne({ tenantId, agentId }).lean();
    if (saved?.session) {
        return {
            loggedIn: true,
            source: "db",
            account: null, // henüz client ayağa kalkmadı
        };
    }

    return {
        loggedIn: false,
    };
}

async function sendTelegramPhotoNative(client, chatId, media) {
    // base64 → buffer
    const buffer = Buffer.from(media.data, "base64");

    // geçici dosya (Telegram uploadFile BUNU SEVİYOR)
    const tmpPath = path.join(
        "/tmp",
        `tg_${Date.now()}_${media.fileName || "photo.jpg"}`
    );

    fs.writeFileSync(tmpPath, buffer);

    try {
        const uploaded = await client.uploadFile({
            file: new CustomFile(
                path.basename(tmpPath),
                fs.statSync(tmpPath).size,
                tmpPath
            ),
            workers: 1,
        });

        return await client.invoke(
            new Api.messages.SendMedia({
                peer: chatId,
                media: new Api.InputMediaUploadedPhoto({
                    file: uploaded,
                }),
                message: media.caption || "",
                randomId: BigInt(Date.now()),
            })
        );
    } finally {
        fs.unlinkSync(tmpPath); // temizlik
    }
}


async function sendTelegramDocumentNative(client, chatId, media) {
    const buffer = Buffer.from(media.data, "base64");
    const tmpPath = path.join("/tmp", media.fileName || "file.bin");

    fs.writeFileSync(tmpPath, buffer);

    try {
        const uploaded = await client.uploadFile({
            file: new CustomFile(
                path.basename(tmpPath),
                fs.statSync(tmpPath).size,
                tmpPath
            ),
            workers: 1,
        });

        return await client.invoke(
            new Api.messages.SendMedia({
                peer: chatId,
                media: new Api.InputMediaUploadedDocument({
                    file: uploaded,
                    mimeType: media.mimetype,
                    attributes: [
                        new Api.DocumentAttributeFilename({
                            fileName: media.fileName || "file",
                        }),
                    ],
                }),
                message: media.caption || "",
                randomId: BigInt(Date.now()),
            })
        );
    } finally {
        fs.unlinkSync(tmpPath);
    }
}

function resolveTelegramClient(tenantId, chat) {
    const ownerId = chat?.ownerAgentId ? String(chat.ownerAgentId) : null;
    const assignedId = chat?.assignedAgentId ? String(chat.assignedAgentId) : null;

    // 1) Sticky owner
    if (ownerId) {
        const ownerClient = tgClients.get(buildKey(tenantId, ownerId));
        if (ownerClient) {
            return { client: ownerClient, usedAgentId: ownerId, source: "owner" };
        }
    }

    // 2) Fallback assigned
    if (assignedId) {
        const assignedClient = tgClients.get(buildKey(tenantId, assignedId));
        if (assignedClient) {
            return { client: assignedClient, usedAgentId: assignedId, source: "assigned" };
        }
    }

    return null;
}



// ====================================================
// SOCKET.IO ANA BAĞLANTI
// ====================================================
io.on("connection", (socket) => {
    const { role, tenantId, agentId, extension, token, userTitle } = socket.handshake.query;

    console.log("⚡ Yeni Telegram Socket:", {
        role,
        tenantId,
        agentId,
        extension,
    });

    if (!role || !tenantId || !agentId) {
        socket.emit("tg-error", "Eksik bağlantı parametreleri");
        return;
    }

    if (role === "admin") setupAdminSocket(socket, tenantId, agentId, extension, token);
    else if (role === "agent") setupAgentSocket(socket, tenantId, agentId, extension, token, userTitle, role);
    else socket.emit("tg-error", "Geçersiz rol");
});

// ====================================================
// ADMIN SOCKET EVENTLERİ
// ====================================================
async function setupAdminSocket(socket, tenantId, agentId, extension, token) {
    console.log(`👑 ADMIN bağlandı → ${tenantId}:${agentId}`);

    socket.join(`admin:${tenantId}:${agentId}`);
    socket.join(`admin:tenant:${tenantId}`);

    const status = await checkTelegramSessionStatus(tenantId, agentId);
    socket.emit("tg-session-status", status);

    socket.on("tg-start", async ({ phone }) => {
        const saved = await TelegramSession.findOne({ tenantId, agentId });

        if (saved?.session) return connectWithSession(tenantId, agentId, saved.session, socket);

        return connectWithoutSession(tenantId, agentId, socket, extension, phone);
    });

    const list = await buildAdminActiveChatsList(tenantId)
    const json = JSON.stringify(list);
    const encrypted = encryptMessage(json)

    socket.emit("active-chats", { data: encrypted });

    socket.emit(
        "tenant-agents",
        await buildTenantAgentsList(tenantId)
    );

    socket.on("get-chat", async (payload) => {
        const decrypted = decryptMessage(payload.data);
        const parsed = JSON.parse(decrypted);
        const { chatKey, count } = parsed
        try {
            const total = await Message.countDocuments({ chatKey, isActive: true });

            const skip = Math.max(total - count, 0);

            const msgs = await Message.find({ chatKey, isActive: true })
                .sort({ timestamp: 1 })  // her zaman zaman sırasına göre
                .skip(skip)
                .limit(count);

            const payload = {
                chatKey,
                messages: msgs
            }

            const json = JSON.stringify(payload);
            const encrypted = encryptMessage(json)

            socket.emit("chat-history", { data: encrypted });
        } catch (err) {
            console.error(err);
        }
    });

    // Admin mesaj gönderebilir
    socket.on("send-message", (payload) =>
        handleSendMessage(socket, tenantId, agentId, payload, role = "admin", extension)
    );

    socket.on("delete-chat", async (payload) => {
        const decrypted = decryptMessage(payload.data);
        const parsed = JSON.parse(decrypted);
        const { chatKey } = parsed;
        if (!chatKey) return;

        // 🔍 Sohbeti bul (agent bilgisi için)
        const chat = await ChatIndex.findOne({ tenantId, chatKey }).lean();
        if (!chat) return;

        // 🔒 Soft delete
        await ChatIndex.updateOne(
            { tenantId, chatKey },
            { $set: { isActive: false } }
        );

        await Message.updateMany(
            { tenantId, chatKey },
            { $set: { isActive: false } }
        );

        // 🔄 1) TÜM ADMINLER
        await emitActiveChats(tenantId);

        // 🔄 2) OWNER AGENT
        if (chat.ownerAgentId) {
            await emitActiveChats(tenantId, chat.ownerAgentId);
        }

        // 🔄 3) ASSIGNED AGENT (aynı değilse)
        if (
            chat.assignedAgentId &&
            chat.assignedAgentId !== chat.ownerAgentId
        ) {
            await emitActiveChats(tenantId, chat.assignedAgentId);
        }

        // (opsiyonel) UI için anlık event
        io.to(`admin:tenant:${tenantId}`).emit("chat-deleted");
    });

    socket.on("assign-chat", async (payload) => {
        const decrypted = decryptMessage(payload.data);
        const parsed = JSON.parse(decrypted);
        const { chatKey, agentId } = parsed
        if (!chatKey || !agentId) return;

        // 🔍 Chat'i bul
        const chat = await ChatIndex.findOne({ tenantId, chatKey }).lean();
        if (!chat) return;

        const oldAgentId = chat.assignedAgentId || chat.ownerAgentId;

        // 🔍 Yeni agent bilgisi
        const agent = await TenantAgent.findOne({
            tenantId,
            agentId,
        }).lean();

        if (!agent) {
            socket.emit("tg-error", "Agent bulunamadı");
            return;
        }

        // 🔄 ChatIndex update
        await ChatIndex.updateOne(
            { tenantId, chatKey },
            {
                $set: {
                    assignedAgentId: String(agentId),
                    assignedAgentExtension: agent.extension,
                    isActive: true,
                },
            }
        );

        // 🔄 ADMIN → herkes güncellensin
        await emitActiveChats(tenantId);

        // 🔄 ESKİ AGENT → sohbet düşsün
        if (oldAgentId && oldAgentId !== String(agentId)) {
            await emitActiveChats(tenantId, oldAgentId);
        }

        // 🔄 YENİ AGENT → sohbet gelsin
        await emitActiveChats(tenantId, agentId);

        const payload1 = {
            chatKey,
            agentId,
            extension: agent.extension
        }

        const json1 = JSON.stringify(payload1);
        const encrypted1 = encryptMessage(json1)

        // (opsiyonel) UI için bilgi
        io.to(`admin:tenant:${tenantId}`).emit("chat-assigned", {
            data: encrypted1
        });
    });

}

// ====================================================
// AGENT SOCKET EVENTLERİ
// ====================================================
async function setupAgentSocket(socket, tenantId, agentId, extension, token, userTitle, role) {
    console.log(`🟩 AGENT bağlandı → ${tenantId}:${agentId}`);

    socket.join(`agent:${tenantId}:${agentId}`);

    await TenantAgent.findOneAndUpdate(
        { tenantId, agentId },
        {
            tenantId,
            agentId,
            role,
            extension,
            userTitle,
            updatedAt: new Date(),
        },
        { upsert: true, new: true }
    );

    await emitTenantAgents(tenantId);

    const status = await checkTelegramSessionStatus(tenantId, agentId);
    socket.emit("tg-session-status", status);

    socket.on("tg-start", async ({ phone }) => {
        const saved = await TelegramSession.findOne({ tenantId, agentId });

        if (saved?.session) return connectWithSession(tenantId, agentId, saved.session, socket);

        return connectWithoutSession(tenantId, agentId, socket, extension, phone);
    });

    const list = await buildAgentActiveChatsList(tenantId, agentId);

    const json = JSON.stringify(list);
    const encrypted = encryptMessage(json)

    socket.emit("active-chats", { data: encrypted });


    // Agent mesaj gönderebilir
    socket.on("send-message", (payload) =>
        handleSendMessage(socket, tenantId, agentId, payload, role = "agent", extension)
    );

    socket.on("get-chat", async (payload) => {
        const decrypted = decryptMessage(payload.data);
        const parsed = JSON.parse(decrypted);
        const { chatKey, count } = parsed
        try {
            // 🔐 1) Yetki kontrolü
            const chat = await ChatIndex.findOne({
                tenantId,
                chatKey,
                isActive: true,
                $or: [
                    { ownerAgentId: String(agentId) },
                    { assignedAgentId: String(agentId) },
                ],
            }).lean();

            if (!chat) {
                socket.emit("tg-error", "Bu sohbet size atanmadığı için geçmişi görüntüleyemezsiniz.",);
                return;
            }

            // 📜 2) Mesaj geçmişi
            const total = await Message.countDocuments({
                tenantId,
                chatKey,
                isActive: true,
            });

            const skip = Math.max(total - count, 0);

            const msgs = await Message.find({
                tenantId,
                chatKey,
                isActive: true,
            })
                .sort({ timestamp: 1 })
                .skip(skip)
                .limit(count);

            const payload = {
                chatKey,
                messages: msgs
            }

            const json = JSON.stringify(payload);
            const encrypted = encryptMessage(json)

            socket.emit("chat-history", { data: encrypted });
        } catch (err) {
            console.error("get-chat error:", err);
            socket.emit("tg-error", "Sohbet geçmişi alınırken hata oluştu.",);
        }
    });


    socket.on("disconnect", async () => {
        const { tenantId, agentId } = socket.handshake.query;
        if (!tenantId || !agentId) return;

        await TenantAgent.deleteOne({ tenantId, agentId });

        await emitTenantAgents(tenantId);
    });
}

// ====================================================
// SESSION VARSA → DOĞRUDAN BAĞLAN
// ====================================================
async function connectWithSession(tenantId, agentId, sessionString, socket) {
    const key = buildKey(tenantId, agentId);

    console.log(`🔁 Session ile bağlanıyor → ${key}`);

    const client = new TelegramClient(new StringSession(sessionString), apiId, apiHash, {
        connectionRetries: 5,
    });

    tgClients.set(key, client);

    await client.connect();

    socket.emit("tg-login-success", { session: true });

    console.log(`✔ Telegram session ile bağlandı: ${key}`);

    startMessageListener(tenantId, agentId);
}

// ====================================================
// SESSION YOKSA → TELEFON / KOD AL
// ====================================================
async function connectWithoutSession(tenantId, agentId, socket, extension, phone) {
    const key = buildKey(tenantId, agentId);

    console.log(`📱 İlk kez giriş yapılıyor → ${key}`);

    const client = new TelegramClient(new StringSession(""), apiId, apiHash, {
        connectionRetries: 5,
    });

    tgClients.set(key, client);

    await client.start({
        phoneNumber: async () => {
            if (phone) {
                return phone;
            }
            socket.emit("tg-need-phone");
            return await waitForEvent(socket, "tg-phone");
        },
        phoneCode: async () => {
            socket.emit("tg-need-code");
            return await waitForEvent(socket, "tg-code");
        },
        password: async () => {
            socket.emit("tg-need-password");
            return await waitForEvent(socket, "tg-password");
        },
        onError: (err) => console.error("Login Error:", err),
    });

    const sessionString = client.session.save();

    await TelegramSession.findOneAndUpdate(
        { tenantId, agentId },
        { session: sessionString, agentExtension: extension },
        { upsert: true }
    );

    console.log(`💾 Telegram session MongoDB’ye kaydedildi → ${key}`);

    const status = await checkTelegramSessionStatus(tenantId, agentId);
    socket.emit("tg-session-status", status);

    socket.emit("tg-login-success", { session: false });

    startMessageListener(tenantId, agentId);
}

// ====================================================
// TELEGRAM MESAJ DİNLEME
// ====================================================
function startMessageListener(tenantId, agentId, agentEx) {
    const key = buildKey(tenantId, agentId);
    const client = tgClients.get(key);
    if (!client) return;

    client.addEventHandler(async (event) => {
        try {
            const message = event.message;
            if (!message || !event.isPrivate) return;

            console.log(message)

            let body = message.text || "";
            let media = null;

            if (message.media) {
                const buffer = await client.downloadMedia(message.media);
                const base64 = buffer.toString("base64");

                // 📸 FOTOĞRAF
                if (message.media.photo) {
                    media = {
                        data: base64,
                        mimetype: "image/jpeg",   // Telegram foto default
                        fileName: null,
                        type: "image",
                    };
                }

                // 🎥 / 📄 DOCUMENT (video, pdf, dosya)
                else if (message.media.document) {
                    const doc = message.media.document;

                    const filenameAttr = doc.attributes?.find(
                        a => a.className === "DocumentAttributeFilename"
                    );

                    media = {
                        data: base64,
                        mimetype: doc.mimeType || "application/octet-stream",
                        fileName: filenameAttr?.fileName || null,
                        type:
                            doc.mimeType?.startsWith("video/")
                                ? "video"
                                : doc.mimeType === "application/pdf"
                                    ? "pdf"
                                    : "file",
                    };
                }
            }


            const sender = await message.getSender(); // ✅ DOĞRU YER
            const telegramUserId = sender.id?.value
                ? String(sender.id.value)
                : String(sender.id);

            const { telegramname, name, chatKey } =
                await getCustomerNameFromCacheOrPacket(
                    client,
                    tenantId,
                    telegramUserId,
                    sender
                );

            // 💾 DB
            const savedMessage = await saveMessageToDB({
                tenantId,
                accountId: 123,
                chatKey,

                fromType: "customer",
                from: sender.username || telegramUserId,
                to: String(agentId),

                body,
                media,

                agentId,
                adminId: null,
                timestamp: Date.now(),
            });

            await ensureChatIndex({
                tenantId,
                chatKey,
                telegramname: sender.username,
                name,
                ownerAgentId: String(agentId),
                assignedAgentId: String(agentId),
                assignedAgentExtension: agentEx,
            });

            const payload = savedMessage.toObject();

            const encryptPayload = {
                chatKey,
                message: payload
            }

            const json = JSON.stringify(encryptPayload);
            const encrypted = encryptMessage(json)

            // 👤 Agent
            io.to(`agent:${tenantId}:${agentId}`).emit("message", {
                data: encrypted
            });

            // 👑 Tüm Adminler
            io.to(`admin:tenant:${tenantId}`).emit("new-message", {
                data: encrypted
            });

            await emitActiveChats(tenantId);
            await emitActiveChats(tenantId, agentId);

        } catch (err) {
            console.error("TG message handler error:", err);
        }
    }, new NewMessage({}));
}

// ====================================================
// MESAJ GÖNDERME (Admin + Agent ortak)
// ====================================================
async function handleSendMessage(
    socket,
    tenantId,
    agentId, // UI'dan yazan kişi (admin / agent)
    payload,
    role,
    extension
) {
    const decrypted = decryptMessage(payload.data);
    const parsed = JSON.parse(decrypted);
    const { chatId, message, chatKey, name } = parsed;

    // =====================================================
    // 1️⃣ ChatIndex bul
    // =====================================================
    let chat = await ChatIndex.findOne({ tenantId, chatKey }).lean();

    // =====================================================
    // 2️⃣ Agent yetki kontrolü
    // =====================================================
    if (role === "agent" && chat) {
        if (String(chat.assignedAgentId) !== String(agentId)) {
            socket.emit(
                "tg-error",
                "Bu sohbet size atanmadığı için mesaj gönderemezsiniz."
            );
            return;
        }
    }

    // =====================================================
    // 3️⃣ Chat yoksa → ilk mesaj → owner = agent
    // =====================================================
    if (!chat) {
        const [, telegramname] = chatKey.split("-");

        await ensureChatIndex({
            tenantId,
            chatKey,
            telegramname,
            name,
            ownerAgentId: String(agentId),
            assignedAgentId: String(agentId),
            assignedAgentExtension: extension,
        });

        chat = {
            chatKey,
            ownerAgentId: String(agentId),
            assignedAgentId: String(agentId),
        };
    }

    const ownerAgentId = String(chat.ownerAgentId);
    const assignedAgentId = String(chat.assignedAgentId);

    // =====================================================
    // 4️⃣ Telegram client çöz (owner → assigned fallback)
    // =====================================================
    const resolved = resolveTelegramClient(tenantId, chat);

    if (!resolved) {
        socket.emit(
            "tg-error",
            "Bu sohbete ait aktif bir Telegram oturumu bulunamadı."
        );
        return;
    }

    const { client, usedAgentId, source } = resolved;
    console.log(`📨 Telegram send via ${source} → agent ${usedAgentId}`);

    // =====================================================
    // 5️⃣ Telegram’a gönder
    // =====================================================
    try {
        if (typeof message === "string") {
            await client.sendMessage(chatId, { message });

        } else if (typeof message === "object" && message.data) {
            const approxSizeMB =
                (message.data.length * 3) / 4 / (1024 * 1024);

            if (approxSizeMB > 64) {
                socket.emit("tg-error", "Medya 64 MB’tan büyük olamaz");
                return;
            }

            if (message.mimetype?.startsWith("image/")) {
                await sendTelegramPhotoNative(client, chatId, message);
            } else {
                await sendTelegramDocumentNative(client, chatId, message);
            }

        } else {
            socket.emit("tg-error", "Geçersiz mesaj formatı");
            return;
        }

        // =====================================================
        // 6️⃣ DB’ye kaydet (GERÇEK Telegram hesabı ile)
        // =====================================================
        const isMedia = typeof message === "object";

        const savedMessage = await saveMessageToDB({
            tenantId,
            accountId: 123,
            chatKey,

            fromType: role,
            from: String(agentId),
            to: String(chatId),

            body: isMedia ? "" : message,
            media: isMedia
                ? {
                    mimetype: message.mimetype,
                    data: message.data,
                    fileName: message.fileName || null,
                    type: message.type || "file",
                }
                : null,

            agentId: usedAgentId,          // 🔥 hangi TG hesabı kullandı
            adminId: role === "admin" ? String(agentId) : null,
            timestamp: Date.now(),
            agentExtension: extension,
        });

        // =====================================================
        // 7️⃣ ChatIndex güncelle (OWNER ASLA DEĞİŞMEZ)
        // =====================================================
        const [, telegramname] = chatKey.split("-");

        await ensureChatIndex({
            tenantId,
            chatKey,
            telegramname,
            name,
            ownerAgentId,
            assignedAgentId,
            assignedAgentExtension: extension,
        });

        // =====================================================
        // 8️⃣ FRONTEND EMIT
        // =====================================================
        const payload = savedMessage.toObject();

        const encryptPayload = {
            chatKey,
            message: payload
        }

        const json = JSON.stringify(encryptPayload);
        const encrypted = encryptMessage(json)

        // Owner
        io.to(`agent:${tenantId}:${ownerAgentId}`).emit("message", {
            data: encrypted
        });

        // Assigned (farklıysa)
        if (assignedAgentId && assignedAgentId !== ownerAgentId) {
            io.to(`agent:${tenantId}:${assignedAgentId}`).emit("message", {
                data: encrypted
            });
        }

        // Adminler
        io.to(`admin:tenant:${tenantId}`).emit("new-message", {
            data: encrypted
        });

        // Active chats
        await emitActiveChats(tenantId);
        await emitActiveChats(tenantId, ownerAgentId);

        if (assignedAgentId !== ownerAgentId) {
            await emitActiveChats(tenantId, assignedAgentId);
        }

    } catch (err) {
        console.error("Mesaj gönderim hatası:", err);
        socket.emit("tg-error", "Mesaj gönderilemedi");
    }
}



// ====================================================
// SUNUCU BAŞLANGICINDA TÜM SESSIONLARI OTOMATİK YÜKLE
// ====================================================
async function initializeAllTelegramSessions() {
    console.log("🔍 DB'deki Telegram sessionlar yükleniyor...");

    const sessions = await TelegramSession.find({});

    for (const s of sessions) {
        const key = `${s.tenantId}:${s.agentId}`;

        try {
            console.log(`♻ Session restore → ${key}`);

            const client = new TelegramClient(
                new StringSession(s.session),
                apiId,
                apiHash,
                { connectionRetries: 5 }
            );

            await client.connect();

            tgClients.set(key, client);

            // Telegram mesaj listener aç
            startMessageListener(s.tenantId, s.agentId, s.agentExtension);

            console.log(`✔ Başarıyla bağlandı → ${key}`);

        } catch (err) {
            console.log(`❌ Session yüklenemedi → ${key}`, err);
        }
    }

    console.log("✅ Tüm daha önce giriş yapılmış TG hesapları aktif!");
}

// ====================================================
// POST → TELEGRAM SESSION KAPAT
// ====================================================
app.post("/api/telegram/logout", async (req, res) => {
    const { tenantId, agentId } = req.body;

    if (!tenantId || !agentId) {
        return res.status(400).json({
            success: false,
            message: "tenantId ve agentId zorunludur",
        });
    }

    const key = buildKey(tenantId, agentId);

    try {
        // 1️⃣ Aktif Telegram client varsa kapat
        const client = tgClients.get(key);
        if (client) {
            try {
                await client.disconnect();
            } catch (e) {
                console.warn("Telegram client disconnect error:", e.message);
            }
            tgClients.delete(key);
        }

        console.log("tgclients -->", tgClients)


        // 2️⃣ DB'den session sil
        await TelegramSession.deleteOne({ tenantId, agentId });

        // 3️⃣ (Opsiyonel) Agent socketine bildir
        io.to(`agent:${tenantId}:${agentId}`).emit("tg-logged-out", {
            tenantId,
            agentId,
        });

        return res.json({
            success: true,
            message: "Telegram oturumu başarıyla kapatıldı",
        });

    } catch (err) {
        console.error("Telegram logout error:", err);
        return res.status(500).json({
            success: false,
            message: "Telegram oturumu kapatılamadı",
        });
    }
});


// ====================================================
server.listen(2055, async () => {
    console.log("🚀 Telegram Server Başladı → 2055");
    await initializeAllTelegramSessions();
});

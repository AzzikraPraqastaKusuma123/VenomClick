// File: test_telegram_node.js
// Tujuan: Hanya untuk mengetes pengiriman pesan HTML dari Node.js

require('dotenv').config();
const axios = require('axios');

const botToken = process.env.TELEGRAM_BOT_TOKEN;
const chatId = process.env.TELEGRAM_CHAT_ID;

async function sendTestMessage() {
    if (!botToken || !chatId) {
        console.error("❌ Gagal: Pastikan TELEGRAM_BOT_TOKEN dan TELEGRAM_CHAT_ID ada di file .env Anda.");
        return;
    }

    console.log(`🚀 Mencoba mengirim pesan tes ke Chat ID: ${chatId}...`);

    const messageText = `<b>Tes dari Node.js Berhasil! 🚀</b>\n\n<a href="https://github.com">Ini adalah link tes dari skrip Node.js.</a>`;

    try {
        await axios.post(
            `https://api.telegram.org/bot${botToken}/sendMessage`,
            {
                chat_id: chatId,
                text: messageText,
                parse_mode: 'HTML'
            }
        );
        console.log("✅ SUKSES! Pesan tes terkirim. Silakan periksa Telegram Anda.");

    } catch (error) {
        console.error("❌ GAGAL MENGIRIM PESAN:", error.response ? error.response.data : error.message);
    }
}

// Langsung jalankan fungsi tes
sendTestMessage();
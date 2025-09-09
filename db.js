const mysql = require("mysql2");

// MENGGUNAKAN createPool untuk koneksi yang lebih stabil dan efisien
const pool = mysql.createPool({
  host: "localhost",
  user: "root",       // sesuaikan
  password: "",       // sesuaikan
  database: "tracking_app", // pastikan ini tracking_app
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

pool.getConnection((err, conn) => {
  if (err) {
    console.error("❌ Gagal koneksi ke Pool DB:", err);
  } else {
    console.log("✅ Terhubung ke database MySQL tracking_app via Pool.");
    conn.release(); // Lepaskan koneksi setelah cek berhasil
  }
});

// Ekspor pool promise-based untuk digunakan di seluruh aplikasi
module.exports = pool.promise();
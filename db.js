const mysql = require("mysql2");

const db = mysql.createConnection({
  host: "localhost",
  user: "root",        // sesuaikan
  password: "",        // sesuaikan
  database: "tracking_app"  // pastikan ini tracking_app
});

db.connect((err) => {
  if (err) {
    console.error("❌ Gagal koneksi DB:", err);
  } else {
    console.log("✅ Terhubung ke database MySQL tracking_app.");
  }
});

module.exports = db;

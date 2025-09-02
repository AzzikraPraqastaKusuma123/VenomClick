const readline = require('readline');
const bcrypt = require('bcrypt');
const db = require('./db');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const saltRounds = 10;

console.log('--- Pembuatan Akun Admin ---');

rl.question('Masukkan username untuk admin: ', (username) => {
  rl.question('Masukkan password untuk admin: ', async (password) => {
    if (!username || !password) {
      console.error('❌ Username dan password tidak boleh kosong.');
      rl.close();
      return;
    }

    try {
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      
      const query = `
        INSERT INTO users (username, password, is_admin, created_at) 
        VALUES (?, ?, TRUE, NOW())
        ON DUPLICATE KEY UPDATE password = ?, is_admin = TRUE;
      `;
      
      db.query(query, [username, hashedPassword, hashedPassword], (err, result) => {
        if (err) {
          console.error('❌ Gagal membuat admin di database:', err);
        } else {
          console.log(`✅ Akun admin '${username}' berhasil dibuat/diperbarui.`);
          console.log('Sekarang Anda bisa menjalankan server utama dengan "node server.js" dan login.');
        }
        db.end(); // Tutup koneksi database
      });

    } catch (error) {
      console.error('❌ Terjadi kesalahan saat hashing password:', error);
      db.end();
    }
    
    rl.close();
  });
});
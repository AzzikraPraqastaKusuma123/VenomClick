const db = require('../db');

// Ambil semua lokasi + user
exports.getLocations = (req, res) => {
  const query = `
    SELECT u.id AS user_id, u.username, u.email, 
           l.id AS location_id, l.latitude, l.longitude, l.created_at
    FROM users u
    JOIN locations l ON u.id = l.user_id
    ORDER BY l.created_at DESC
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching data:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(results);
  });
};

// Tambah lokasi baru
exports.addLocation = (req, res) => {
  const { user_id, latitude, longitude } = req.body;

  if (!user_id || !latitude || !longitude) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const query = `INSERT INTO locations (user_id, latitude, longitude) VALUES (?, ?, ?)`;

  db.query(query, [user_id, latitude, longitude], (err, result) => {
    if (err) {
      console.error('Error inserting data:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json({ message: 'Location added successfully', id: result.insertId });
  });
};

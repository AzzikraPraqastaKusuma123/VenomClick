const express = require('express');
const router = express.Router();
const locationController = require('../controllers/locationController');

// GET semua lokasi
router.get('/locations', locationController.getLocations);

// POST tambah lokasi
router.post('/locations', locationController.addLocation);

module.exports = router;

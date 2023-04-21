const router = require("express").Router();

const partyController = require("../controllers/partyController");

// Post
router.route("/parties").post((req, res) => partyController.create(req, res));

// GetAll
router.route("/parties").get((req, res) => partyController.getAll(req,res));

// GetById
router.route("/parties/:id").get((req, res) => partyController.get(req, res));

// Delete
router.route("/parties/:id").delete((req, res) => partyController.delete(req, res));

// Update
router.route("/parties/:id").put((req, res) => partyController.update(req, res));

module.exports = router;
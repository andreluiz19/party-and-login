const router = require("express").Router();

// Parties Route
const partyRouter = require("./parties");

router.use("/", partyRouter);

module.exports = router;